//! Windows filesystem helpers for `tirith setup` — the same public API as
//! `fs_helpers.rs` using held Windows handles and explicit DACL handling.

#[path = "fs_retention_windows.rs"]
mod retention;
pub(crate) use retention::{open_existing_in_place, InPlaceLease};

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::{cell::RefCell, rc::Rc};

use sha2::{Digest, Sha256};

use super::fs_transaction::PublicationOutcome;
pub(crate) use super::fs_transaction::{
    transactional_update, transactional_update_checked, FileUpdate,
};

#[path = "fs_helpers_windows_path.rs"]
mod path_rules;

use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    ERROR_UNABLE_TO_MOVE_REPLACEMENT, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2, HANDLE, HLOCAL,
    WAIT_ABANDONED, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorLength,
    GetSecurityDescriptorOwner, GetTokenInformation, SetKernelObjectSecurity,
    SetSecurityDescriptorControl, TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SE_DACL_AUTO_INHERITED, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileAttributeTagInfo, FileDispositionInfo, FlushFileBuffers,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    MoveFileExW, ReplaceFileW, SetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, CREATE_NEW,
    DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, MOVEFILE_WRITE_THROUGH,
    OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
};

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_file(self) -> fs::File {
        let raw = self.0 .0 as RawHandle;
        std::mem::forget(self);
        unsafe { fs::File::from_raw_handle(raw) }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

struct ValidatedParent {
    path: PathBuf,
    handles: Vec<OwnedHandle>,
    root_final: String,
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
thread_local! {
    static REPLACE_FILE_TEST_HOOK: std::cell::RefCell<
        Option<Box<dyn FnMut(&Path, &Path, &Path) -> Result<(), u32>>>,
    > = std::cell::RefCell::new(None);
    static OLD_BACKUP_CLEANUP_TEST_HOOK: std::cell::RefCell<
        Option<Box<dyn FnMut(&Path)>>,
    > = std::cell::RefCell::new(None);
    static CREATED_ARTIFACT_CAPTURE_TEST_HOOK: std::cell::RefCell<
        Option<Box<dyn FnMut(&Path)>>,
    > = std::cell::RefCell::new(None);
    static DELETE_FAILURE_TEST_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn replace_file_call(
    destination: &Path,
    replacement: &Path,
    displaced: &Path,
) -> Result<(), windows::core::Error> {
    #[cfg(test)]
    if let Some(result) = REPLACE_FILE_TEST_HOOK.with(|slot| {
        slot.borrow_mut()
            .as_mut()
            .map(|hook| hook(destination, replacement, displaced))
    }) {
        return result
            .map_err(|code| windows::core::Error::from_hresult(HRESULT::from_win32(code)));
    }

    let destination_wide = wide(destination);
    let replacement_wide = wide(replacement);
    let displaced_wide = wide(displaced);
    unsafe {
        ReplaceFileW(
            PCWSTR(destination_wide.as_ptr()),
            PCWSTR(replacement_wide.as_ptr()),
            PCWSTR(displaced_wide.as_ptr()),
            Default::default(),
            None,
            None,
        )
    }
}

const BACKUP_MARKER: &str = ".tirith-backup-v2-";
const DISPLACED_MARKER: &str = ".tirith-displaced-v2-";
const ARTIFACT_RETENTION_LIMIT: usize = 5;

fn hex_bytes(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn destination_tag(destination: &Path) -> String {
    let mut hasher = Sha256::new();
    for unit in destination
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase()
        .encode_utf16()
    {
        hasher.update(unit.to_le_bytes());
    }
    let digest = hasher.finalize();
    hex_bytes(&digest[..16])
}

fn content_binding(destination: &Path, size: u64, digest: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tirith-setup-backup-v2\0");
    hasher.update(destination_tag(destination).as_bytes());
    hasher.update(size.to_le_bytes());
    hasher.update(digest);
    hex_bytes(&hasher.finalize())
}

fn recovery_binding(destination: &Path, generation: &FileGeneration) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"tirith-setup-displaced-v2\0");
    hasher.update(destination_tag(destination).as_bytes());
    hasher.update(generation.volume_serial.to_le_bytes());
    hasher.update(generation.file_index.to_le_bytes());
    hasher.update(generation.size.to_le_bytes());
    hasher.update(generation.attributes.to_le_bytes());
    hasher.update(generation.reparse_tag.unwrap_or_default().to_le_bytes());
    hasher.update(generation.digest);
    hasher.update(&generation.security_descriptor);
    hex_bytes(&hasher.finalize())
}

fn timestamp_is_valid(timestamp: &str) -> bool {
    timestamp.len() == 25
        && timestamp.as_bytes()[8] == b'-'
        && timestamp.as_bytes()[15] == b'-'
        && timestamp
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 8 || index == 15 || byte.is_ascii_digit())
}

fn with_current_user_sid<T>(use_sid: impl FnOnce(PSID) -> T) -> Result<T, String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|error| format!("open current process token: {error}"))?;
    let token = OwnedHandle(token);

    let mut required = 0u32;
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
    if required < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err("query current-user SID size returned an invalid length".into());
    }
    let word = std::mem::size_of::<usize>();
    let mut storage = vec![0usize; (required as usize + word - 1) / word];
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(storage.as_mut_ptr().cast()),
            required,
            &mut required,
        )
    }
    .map_err(|error| format!("read current-user SID: {error}"))?;
    let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if token_user.User.Sid.0.is_null() {
        return Err("current process token returned a null user SID".into());
    }
    Ok(use_sid(token_user.User.Sid))
}

fn current_user_sid_string() -> Result<String, String> {
    with_current_user_sid(|sid| {
        let mut encoded = PWSTR::null();
        unsafe { ConvertSidToStringSidW(sid, &mut encoded) }
            .map_err(|error| format!("format current-user SID: {error}"))?;
        let decoded = unsafe { encoded.to_string() }
            .map_err(|error| format!("decode current-user SID: {error}"));
        unsafe {
            let _ = LocalFree(Some(HLOCAL(encoded.0.cast())));
        }
        decoded
    })?
}

/// Re-apply a preserved owner + group + DACL to the file `ReplaceFileW` just
/// published, and return the refreshed generation observed through the same
/// held handle after the write.
///
/// `ReplaceFileW` MERGES ACLs rather than preserving them: the replaced file's
/// ACEs are copied onto the replacement as EXPLICIT entries, auto-inheritance
/// re-applies the parent's inheritable ACEs on top, and the owner is not
/// restored at all. Asserting byte-identity after the call therefore asserts
/// something the API never promised — it holds only where the parent has no
/// inheritable ACEs AND the owner happens to match. The same trap applies to
/// `SetSecurityInfo`: it feeds the provided DACL through the auto-inheritance
/// machinery, which strips `INHERITED_ACE` flags into explicit entries and
/// appends freshly recomputed inherited ACEs — the result is never the
/// preserved bytes. `SetKernelObjectSecurity` writes the descriptor literally
/// (no inheritance recomputation), so the preserved DACL — including its
/// `INHERITED_ACE`-flagged entries and `SE_DACL_PROTECTED` state — lands
/// byte-for-byte. `SE_DACL_AUTO_INHERITED` is the one control bit a literal
/// write clears unless explicitly re-requested, so it is carried across via
/// `SE_DACL_AUTO_INHERIT_REQ`. The caller's byte-for-byte comparison then
/// verifies that all of this actually landed.
///
/// The handle is opened no-reparse, share-read only, and its generation must
/// equal the replacement that was just installed, so the restore cannot be
/// redirected onto a different file between the replace and this call.
/// `WRITE_OWNER` is requested only when the owner or group actually needs to
/// change, so an unprivileged publication over a file the caller owns never
/// demands rights it does not have.
fn restore_preserved_security(
    path: &Path,
    installed: &FileGeneration,
    preserved: &[u8],
) -> Result<FileGeneration, String> {
    let mut owned = preserved.to_vec();
    let descriptor = PSECURITY_DESCRIPTOR(owned.as_mut_ptr().cast());

    let mut control = 0u16;
    let mut revision = 0u32;
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }
        .map_err(|error| format!("read preserved descriptor control: {error}"))?;

    let mut preserved_owner = PSID::default();
    let mut defaulted = BOOL(0);
    unsafe { GetSecurityDescriptorOwner(descriptor, &mut preserved_owner, &mut defaulted) }
        .map_err(|error| format!("read preserved owner: {error}"))?;
    let mut preserved_group = PSID::default();
    unsafe { GetSecurityDescriptorGroup(descriptor, &mut preserved_group, &mut defaulted) }
        .map_err(|error| format!("read preserved group: {error}"))?;

    // Decide whether the principal components actually changed, using the
    // installed descriptor the caller just captured. Owner/group writes need
    // `WRITE_OWNER`; a DACL write only needs `WRITE_DAC`, which the file's
    // owner always holds. Restoring only what drifted keeps the common
    // unprivileged path (same owner, merged DACL) working.
    let mut installed_bytes = installed.security_descriptor.clone();
    let installed_descriptor = PSECURITY_DESCRIPTOR(installed_bytes.as_mut_ptr().cast());
    let mut installed_owner = PSID::default();
    unsafe {
        GetSecurityDescriptorOwner(installed_descriptor, &mut installed_owner, &mut defaulted)
    }
    .map_err(|error| format!("read installed owner: {error}"))?;
    let mut installed_group = PSID::default();
    unsafe {
        GetSecurityDescriptorGroup(installed_descriptor, &mut installed_group, &mut defaulted)
    }
    .map_err(|error| format!("read installed group: {error}"))?;
    let sids_equal = |a: PSID, b: PSID| -> bool {
        if a.is_invalid() || b.is_invalid() {
            return a.is_invalid() && b.is_invalid();
        }
        unsafe { EqualSid(a, b) }.is_ok()
    };
    let owner_changes = !sids_equal(preserved_owner, installed_owner);
    let group_changes = !sids_equal(preserved_group, installed_group);
    let needs_write_owner = owner_changes || group_changes;

    let path_wide = wide(path);
    let open_with = |rights: u32| unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            rights,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    };
    let base_rights = FILE_GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES | WRITE_DAC;
    let handle = if needs_write_owner {
        open_with((base_rights | WRITE_OWNER).0).map_err(|error| {
            format!(
                "reopen {} with WRITE_OWNER to restore its preserved owner: {error}",
                path.display()
            )
        })?
    } else {
        open_with(base_rights.0).map_err(|error| {
            format!(
                "reopen {} to restore its preserved security descriptor: {error}",
                path.display()
            )
        })?
    };
    let held = OwnedHandle(handle).into_file();
    let (held, _, generation) = capture_stable_file(held, path)?;
    if !generation.same_identity(installed) {
        return Err(format!(
            "{} is no longer the identity just published; refusing to write its security descriptor",
            path.display()
        ));
    }

    // A literal descriptor write stores `SE_DACL_AUTO_INHERITED` only when the
    // request bit accompanies it; without this, restoring a descriptor from an
    // auto-inherited tree would drop the flag and fail the byte comparison.
    if control & SE_DACL_AUTO_INHERITED.0 != 0 {
        unsafe {
            SetSecurityDescriptorControl(
                descriptor,
                SE_DACL_AUTO_INHERIT_REQ,
                SE_DACL_AUTO_INHERIT_REQ,
            )
        }
        .map_err(|error| format!("request preserved auto-inherit state: {error}"))?;
    }

    let mut information = DACL_SECURITY_INFORMATION;
    if owner_changes {
        information |= OWNER_SECURITY_INFORMATION;
    }
    if group_changes {
        information |= GROUP_SECURITY_INFORMATION;
    }
    unsafe { SetKernelObjectSecurity(HANDLE(held.as_raw_handle()), information, descriptor) }
        .map_err(|error| {
            format!(
                "restore preserved security descriptor on {}: {error}",
                path.display()
            )
        })?;

    // Re-observe through the SAME handle so the caller compares the exact
    // post-restore state with no path re-resolution in between.
    let (_held, _, refreshed) = capture_stable_file(held, path)?;
    if !refreshed.same_identity(installed) {
        return Err(format!(
            "{} changed identity while its security descriptor was being restored",
            path.display()
        ));
    }
    Ok(refreshed)
}

/// Render a self-relative security descriptor as SDDL for diagnostics.
///
/// A byte length names nothing an operator can act on. SDDL names the owner,
/// the group, and every ACE, so a publication mismatch reports WHICH access
/// changed. This is diagnostic only: on failure it falls back to the length so
/// the renderer can never be the reason a mismatch goes unreported.
fn describe_security_descriptor(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }
    let mut owned = bytes.to_vec();
    let descriptor = PSECURITY_DESCRIPTOR(owned.as_mut_ptr().cast());
    let mut encoded = PWSTR::null();
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut encoded,
            None,
        )
    }
    .is_err()
    {
        return format!("{} bytes, unrenderable", bytes.len());
    }
    let rendered = unsafe { encoded.to_string() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(encoded.0.cast())));
    }
    rendered.unwrap_or_else(|_| format!("{} bytes, undecodable", bytes.len()))
}

fn owner_is_current_user(owner: PSID) -> bool {
    with_current_user_sid(|current| unsafe { EqualSid(owner, current) }.is_ok()).unwrap_or(false)
}

fn owner_only_security_descriptor(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let mut descriptor_bytes = bytes.to_vec();
    let descriptor = PSECURITY_DESCRIPTOR(descriptor_bytes.as_mut_ptr().cast());
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.is_err()
        || control & SE_DACL_PROTECTED.0 == 0
    {
        return false;
    }
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        .is_err()
        || !present.as_bool()
        || dacl.is_null()
    {
        return false;
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .is_err()
        || size.AceCount != 1
    {
        return false;
    }
    let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
    if unsafe { GetAce(dacl, 0, &mut ace) }.is_err() || ace.is_null() {
        return false;
    }
    let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
    if unsafe { (*ace).Header.AceType != 0 || (*ace).Mask != FILE_ALL_ACCESS.0 } {
        return false;
    }
    let mut owner = PSID::default();
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) }.is_err()
        || owner.0.is_null()
    {
        return false;
    }
    let ace_sid = unsafe { PSID((&mut (*ace).SidStart as *mut u32).cast()) };
    owner_is_current_user(owner) && unsafe { EqualSid(owner, ace_sid) }.is_ok()
}

fn control_trustee_is_trusted(sid: PSID) -> bool {
    if sid.0.is_null() {
        return false;
    }
    if owner_is_current_user(sid) {
        return true;
    }
    let mut encoded = PWSTR::null();
    if unsafe { ConvertSidToStringSidW(sid, &mut encoded) }.is_err() {
        return false;
    }
    let text = unsafe { encoded.to_string() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(encoded.0.cast())));
    }
    matches!(text.as_deref(), Ok("S-1-5-18" | "S-1-5-32-544"))
}

/// Ancestors may grant read/traverse rights to other users. Effective rights
/// that can create, replace, delete or change security must have trusted owners.
/// Unrecognized effective ACE forms fail closed; native qualification is still
/// required for the supported Windows volume/profile ACL combinations.
fn control_ancestor_security_descriptor(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let mut storage = bytes.to_vec();
    let descriptor = PSECURITY_DESCRIPTOR(storage.as_mut_ptr().cast());
    let mut owner = PSID::default();
    let mut defaulted = BOOL(0);
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) }.is_err()
        || !control_trustee_is_trusted(owner)
    {
        return false;
    }
    let mut present = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        .is_err()
        || !present.as_bool()
        || dacl.is_null()
    {
        return false;
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .is_err()
    {
        return false;
    }
    // FILE_ADD_FILE/SUBDIRECTORY, WRITE_EA, DELETE_CHILD, WRITE_ATTRIBUTES;
    // DELETE, WRITE_DAC, WRITE_OWNER; MAXIMUM_ALLOWED, GENERIC_ALL/WRITE.
    const MUTATION_RIGHTS: u32 = 0x0000_0156 | 0x000d_0000 | 0x5200_0000;
    for index in 0..size.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) }.is_err() || ace.is_null() {
            return false;
        }
        let header = unsafe { &*ace.cast::<windows::Win32::Security::ACE_HEADER>() };
        // INHERIT_ONLY has no effect on this held ancestor; children are checked
        // through their own descriptors. A deny ACE cannot add authority.
        if header.AceFlags & 0x08 != 0 || header.AceType == 1 {
            continue;
        }
        if header.AceType != 0
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return false;
        }
        let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
        let mask = unsafe { (*allowed).Mask };
        let sid = unsafe { PSID((&mut (*allowed).SidStart as *mut u32).cast()) };
        if mask & MUTATION_RIGHTS != 0 && !control_trustee_is_trusted(sid) {
            return false;
        }
    }
    true
}

fn control_directory_descriptor(file: &fs::File) -> Result<Vec<u8>, String> {
    let handle = HANDLE(file.as_raw_handle());
    let label = Path::new("<held control directory>");
    let info = handle_information(handle, label)?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, true) {
        return Err("held control path is not a regular non-reparse directory".into());
    }
    security_descriptor(handle, label)
}

pub(crate) fn validate_control_directory_handle(file: &fs::File) -> Result<(), String> {
    if !owner_only_security_descriptor(&control_directory_descriptor(file)?) {
        return Err("control directory must retain a protected current-user-only DACL".into());
    }
    Ok(())
}

pub(crate) fn validate_control_ancestor_handle(file: &fs::File) -> Result<(), String> {
    let descriptor = control_directory_descriptor(file)?;
    if !control_ancestor_security_descriptor(&descriptor) {
        #[cfg(test)]
        eprintln!(
            "Unsupported native test ancestor ACL: {}",
            describe_security_descriptor(&descriptor)
        );
        return Err("control directory ancestor has an untrusted owner or write authority".into());
    }
    Ok(())
}

fn backup_name(destination: &Path, bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    format!(
        "{BACKUP_MARKER}{}-{}_{}_{}",
        destination_tag(destination),
        chrono::Local::now().format("%Y%m%d-%H%M%S-%9f"),
        content_binding(destination, bytes.len() as u64, &digest),
        uuid::Uuid::new_v4().simple()
    )
}

fn backup_name_matches(path: &Path, destination: &Path, generation: &FileGeneration) -> bool {
    let candidate = path.file_name().unwrap_or_default().to_string_lossy();
    let prefix = format!("{BACKUP_MARKER}{}-", destination_tag(destination));
    let Some(rest) = candidate.strip_prefix(&prefix) else {
        return false;
    };
    let mut fields = rest.split('_');
    let timestamp = fields.next();
    let binding = fields.next();
    let nonce = fields.next();
    fields.next().is_none()
        && timestamp.is_some_and(timestamp_is_valid)
        && binding
            == Some(content_binding(destination, generation.size, &generation.digest).as_str())
        && nonce.is_some_and(|value| {
            value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        && generation.reparse_tag.is_none()
        && path_rules::attributes_are_safe(generation.attributes, false)
        && owner_only_security_descriptor(&generation.security_descriptor)
}

fn displaced_name_matches(path: &Path, destination: &Path, generation: &FileGeneration) -> bool {
    let candidate = path.file_name().unwrap_or_default().to_string_lossy();
    let prefix = format!("{DISPLACED_MARKER}{}-", destination_tag(destination));
    let Some(rest) = candidate.strip_prefix(&prefix) else {
        return false;
    };
    let mut fields = rest.split('_');
    let timestamp = fields.next();
    let binding = fields.next();
    let nonce = fields.next();
    fields.next().is_none()
        && timestamp.is_some_and(timestamp_is_valid)
        && binding == Some(recovery_binding(destination, generation).as_str())
        && nonce.is_some_and(|value| {
            value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn new_displaced_path(destination: &Path, expected: &FileGeneration) -> Result<PathBuf, String> {
    let parent = destination
        .parent()
        .ok_or_else(|| format!("no parent for {}", destination.display()))?;
    // The UUID is passed directly to ReplaceFileW. A preflight existence
    // check would merely create a check/use race and is deliberately absent.
    Ok(parent.join(format!(
        "{DISPLACED_MARKER}{}-{}_{}_{}",
        destination_tag(destination),
        chrono::Local::now().format("%Y%m%d-%H%M%S-%9f"),
        recovery_binding(destination, expected),
        uuid::Uuid::new_v4().simple()
    )))
}

fn is_win32(error: &windows::core::Error, code: u32) -> bool {
    error.code() == HRESULT::from_win32(code)
}

fn final_path(handle: HANDLE) -> Result<String, String> {
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, Default::default()) };
        if length == 0 {
            return Err(format!(
                "GetFinalPathNameByHandleW: {}",
                std::io::Error::last_os_error()
            ));
        }
        if (length as usize) < buffer.len() {
            return Ok(String::from_utf16_lossy(&buffer[..length as usize]));
        }
        buffer.resize(length as usize + 1, 0);
    }
}

fn reparse_tag(handle: HANDLE) -> Result<u32, String> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|error| format!("inspect reparse tag: {error}"))?;
    Ok(info.ReparseTag)
}

fn open_directory(path: &Path) -> Result<Option<OwnedHandle>, String> {
    let path_wide = wide(path);
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            (FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error)
            if is_win32(&error, ERROR_FILE_NOT_FOUND.0)
                || is_win32(&error, ERROR_PATH_NOT_FOUND.0) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(format!("open directory handle {}: {error}", path.display())),
    };
    let owned = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .map_err(|e| format!("inspect directory handle {}: {e}", path.display()))?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, true) {
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            let tag = reparse_tag(handle)?;
            let redirects = path_rules::reparse_tag_redirects_name(tag);
            return Err(format!(
                "{} is a reparse point (tag 0x{tag:08x}, name_redirect={redirects}) — refusing for safety",
                path.display(),
            ));
        }
        return Err(format!("{} is not a directory", path.display()));
    }
    Ok(Some(owned))
}

fn open_or_create_directory(
    current: &mut PathBuf,
    component: &OsStr,
    handles: &mut Vec<OwnedHandle>,
    create: bool,
) -> Result<bool, String> {
    current.push(component);
    let component_handle = match open_directory(current)? {
        Some(handle) => handle,
        None if !create => return Ok(false),
        None => {
            let current_wide = wide(current);
            // Set owner and privacy atomically. A default token owner may be the
            // Administrators group on an elevated native Windows runner; a
            // later DACL-only update cannot turn that into a user-owned object.
            let descriptor = owner_only_descriptor()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0 .0,
                bInheritHandle: BOOL(0),
            };
            if let Err(error) =
                unsafe { CreateDirectoryW(PCWSTR(current_wide.as_ptr()), Some(&attributes)) }
            {
                if !is_win32(&error, ERROR_ALREADY_EXISTS.0) {
                    return Err(format!("create directory {}: {error}", current.display()));
                }
            }
            open_directory(current)?.ok_or_else(|| {
                format!("{} disappeared after directory creation", current.display())
            })?
        }
    };
    handles.push(component_handle);
    Ok(true)
}

fn validated_parent(
    path: &Path,
    scope_root: &Path,
    create: bool,
) -> Result<Option<ValidatedParent>, String> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("current_dir: {e}"))?
            .join(path)
    };
    let root = if scope_root.is_absolute() {
        scope_root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("current_dir: {e}"))?
            .join(scope_root)
    };
    let relative = path.strip_prefix(&root).map_err(|_| {
        format!(
            "{} is outside trusted setup root {}",
            path.display(),
            root.display()
        )
    })?;
    let mut relative_parts: Vec<_> = relative.components().collect();
    if relative_parts.pop().is_none() {
        return Err(format!(
            "{} names the trusted root, not a file",
            path.display()
        ));
    }
    if relative_parts
        .iter()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "{} contains a non-normal path component",
            path.display()
        ));
    }

    let mut anchor = root.clone();
    let mut missing = Vec::new();
    while !anchor.exists() {
        missing.push(
            anchor
                .file_name()
                .ok_or_else(|| format!("cannot resolve {}", root.display()))?
                .to_os_string(),
        );
        if !anchor.pop() {
            return Err(format!("cannot resolve {}", root.display()));
        }
    }
    if !missing.is_empty() && !create {
        return Ok(None);
    }
    let mut current = anchor
        .canonicalize()
        .map_err(|e| format!("canonicalize trusted root {}: {e}", anchor.display()))?;
    let mut handles = vec![open_directory(&current)?
        .ok_or_else(|| format!("trusted root {} disappeared", current.display()))?];

    for component in missing.iter().rev() {
        if !open_or_create_directory(&mut current, component, &mut handles, create)? {
            return Ok(None);
        }
    }
    // Capture the final path of the requested scope root itself, rather than
    // its nearest pre-existing ancestor when the scope had to be created.
    let root_final = final_path(handles.last().expect("root handle exists").0)?;

    for component in relative_parts.iter().filter_map(|part| match part {
        std::path::Component::Normal(name) => Some(*name),
        _ => None,
    }) {
        if !open_or_create_directory(&mut current, component, &mut handles, create)? {
            return Ok(None);
        }
    }

    let parent_final = final_path(handles.last().expect("anchor handle exists").0)?;
    if !path_rules::final_path_within(&root_final, &parent_final) {
        return Err(format!(
            "{} resolves outside trusted setup root",
            current.display()
        ));
    }
    Ok(Some(ValidatedParent {
        path: current,
        handles,
        root_final,
    }))
}

fn open_existing(path: &Path) -> Result<Option<OwnedHandle>, String> {
    let path_wide = wide(path);
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            (FILE_GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error)
            if is_win32(&error, ERROR_FILE_NOT_FOUND.0)
                || is_win32(&error, ERROR_PATH_NOT_FOUND.0) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(format!("open destination {}: {error}", path.display())),
    };
    let owned = OwnedHandle(handle);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .map_err(|e| format!("inspect destination {}: {e}", path.display()))?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, false) {
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            let tag = reparse_tag(handle)?;
            let redirects = path_rules::reparse_tag_redirects_name(tag);
            return Err(format!(
                "{} is a reparse point (tag 0x{tag:08x}, name_redirect={redirects}) — refusing for safety",
                path.display(),
            ));
        }
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(Some(owned))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileGeneration {
    volume_serial: u32,
    file_index: u64,
    size: u64,
    links: u32,
    last_write: u64,
    attributes: u32,
    reparse_tag: Option<u32>,
    digest: [u8; 32],
    security_descriptor: Vec<u8>,
}

impl FileGeneration {
    fn from_observation(
        info: &BY_HANDLE_FILE_INFORMATION,
        reparse_tag: Option<u32>,
        digest: [u8; 32],
        security_descriptor: Vec<u8>,
    ) -> Self {
        Self {
            volume_serial: info.dwVolumeSerialNumber,
            file_index: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
            size: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
            links: info.nNumberOfLinks,
            last_write: ((info.ftLastWriteTime.dwHighDateTime as u64) << 32)
                | info.ftLastWriteTime.dwLowDateTime as u64,
            attributes: info.dwFileAttributes,
            reparse_tag,
            digest,
            security_descriptor,
        }
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.volume_serial == other.volume_serial && self.file_index == other.file_index
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SnapshotGeneration {
    Absent,
    Present(FileGeneration),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlatformSnapshot {
    pub(crate) bytes: Option<Vec<u8>>,
    pub(crate) mode: Option<u32>,
    generation: SnapshotGeneration,
}

impl PlatformSnapshot {
    pub(crate) fn require_private(&self) -> Result<(), String> {
        if let SnapshotGeneration::Present(generation) = &self.generation {
            if generation.links != 1
                || generation.reparse_tag.is_some()
                || !path_rules::attributes_are_safe(generation.attributes, false)
                || !owner_only_security_descriptor(&generation.security_descriptor)
            {
                return Err("private file must be single-link, non-reparse and retain a protected current-user-only DACL".into());
            }
        }
        Ok(())
    }

    fn absent() -> Self {
        Self {
            bytes: None,
            mode: None,
            generation: SnapshotGeneration::Absent,
        }
    }
}

fn handle_information(handle: HANDLE, path: &Path) -> Result<BY_HANDLE_FILE_INFORMATION, String> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &mut info) }
        .map_err(|error| format!("inspect {} through open handle: {error}", path.display()))?;
    Ok(info)
}

fn security_descriptor(handle: HANDLE, path: &Path) -> Result<Vec<u8>, String> {
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if status.0 != 0 {
        return Err(format!(
            "read {} DACL security metadata: error {}",
            path.display(),
            status.0
        ));
    }
    let descriptor = LocalSecurityDescriptor(descriptor);
    let length = unsafe { GetSecurityDescriptorLength(descriptor.0) } as usize;
    if length == 0 {
        return Err(format!("read {} empty security descriptor", path.display()));
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(descriptor.0 .0.cast::<u8>(), length).to_vec() };
    Ok(bytes)
}

fn optional_reparse_tag(
    handle: HANDLE,
    info: &BY_HANDLE_FILE_INFORMATION,
) -> Result<Option<u32>, String> {
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 {
        Ok(None)
    } else {
        reparse_tag(handle).map(Some)
    }
}

/// Whether a live observation proves the exact competing file object landed
/// back, for the post-rollback verification specifically. The rollback is
/// itself a `ReplaceFileW`, which rewrites the security descriptor of
/// whichever file it installs (the same merge behavior the publication
/// restore exists to undo), so byte-identical generations — descriptor and
/// timestamps included — are not something a rollback can promise. Identity,
/// size, content digest, and reparse state are what prove the competitor is
/// back; the descriptor it then carries is its own business.
fn rollback_landed(live: Option<&FileGeneration>, expected: Option<&FileGeneration>) -> bool {
    match (live, expected) {
        (Some(live), Some(expected)) => {
            live.same_identity(expected)
                && live.size == expected.size
                && live.digest == expected.digest
                && live.reparse_tag == expected.reparse_tag
        }
        _ => false,
    }
}

fn capture_stable_file(
    file: fs::File,
    path: &Path,
) -> Result<(fs::File, Vec<u8>, FileGeneration), String> {
    capture_stable_file_capped(file, path, super::fs_transaction::MAX_SETUP_FILE_BYTES)
}

fn capture_once(
    file: &mut fs::File,
    path: &Path,
    limit: usize,
) -> Result<(Vec<u8>, FileGeneration), String> {
    let handle = HANDLE(file.as_raw_handle());
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek {} through open handle: {error}", path.display()))?;
    let before = handle_information(handle, path)?;
    let before_security = security_descriptor(handle, path)?;
    let before_reparse = optional_reparse_tag(handle, &before)?;
    let before_size = ((before.nFileSizeHigh as u64) << 32) | before.nFileSizeLow as u64;
    if before_size > limit as u64 {
        return Err(format!(
            "{} exceeds setup file limit of {} bytes",
            path.display(),
            limit
        ));
    }

    let mut bytes = Vec::with_capacity(before_size as usize);
    (&mut *file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {} through open handle: {error}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!(
            "{} exceeds setup file limit of {} bytes",
            path.display(),
            limit
        ));
    }

    let after = handle_information(handle, path)?;
    let after_security = security_descriptor(handle, path)?;
    let after_reparse = optional_reparse_tag(handle, &after)?;
    let stable_metadata = before.dwVolumeSerialNumber == after.dwVolumeSerialNumber
        && before.nFileIndexHigh == after.nFileIndexHigh
        && before.nFileIndexLow == after.nFileIndexLow
        && before.nFileSizeHigh == after.nFileSizeHigh
        && before.nFileSizeLow == after.nFileSizeLow
        && before.ftLastWriteTime == after.ftLastWriteTime
        && before.dwFileAttributes == after.dwFileAttributes
        && before_security == after_security
        && before_reparse == after_reparse;
    let after_size = ((after.nFileSizeHigh as u64) << 32) | after.nFileSizeLow as u64;
    if !stable_metadata || bytes.len() as u64 != after_size {
        return Err(format!("{} changed while being read", path.display()));
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    Ok((
        bytes,
        FileGeneration::from_observation(&after, after_reparse, digest, after_security),
    ))
}

fn capture_stable_file_capped(
    mut file: fs::File,
    path: &Path,
    limit: usize,
) -> Result<(fs::File, Vec<u8>, FileGeneration), String> {
    let mut previous = capture_once(&mut file, path, limit)?;
    for _ in 0..3 {
        let current = capture_once(&mut file, path, limit)?;
        if current == previous {
            return Ok((file, current.0, current.1));
        }
        previous = current;
    }
    Err(format!(
        "{} changed repeatedly while being read; retry setup",
        path.display()
    ))
}

fn generation_at(path: &Path) -> Result<Option<FileGeneration>, String> {
    let Some(handle) = open_existing(path)? else {
        return Ok(None);
    };
    let (_, _, generation) = capture_stable_file(handle.into_file(), path)?;
    Ok(Some(generation))
}

fn open_cleanup_handle(path: &Path) -> Result<Option<OwnedHandle>, String> {
    let path_wide = wide(path);
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            (FILE_GENERIC_READ | READ_CONTROL | FILE_READ_ATTRIBUTES | DELETE).0,
            // Cleanup and recovery artifacts must never grant write sharing.
            // The held DELETE-capable handle therefore blocks both pathname
            // replacement and non-cooperating writers until commit/release.
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(error)
            if is_win32(&error, ERROR_FILE_NOT_FOUND.0)
                || is_win32(&error, ERROR_PATH_NOT_FOUND.0) =>
        {
            return Ok(None)
        }
        Err(error) => {
            return Err(format!(
                "open {} for identity-bound cleanup: {error}",
                path.display()
            ))
        }
    };
    let owned = OwnedHandle(handle);
    let info = handle_information(handle, path)?;
    if !path_rules::attributes_are_safe(info.dwFileAttributes, false) {
        return Err(format!(
            "{} is not a safe regular file for cleanup",
            path.display()
        ));
    }
    Ok(Some(owned))
}

fn mark_held_file_for_deletion(file: &fs::File) -> Result<(), String> {
    #[cfg(test)]
    if DELETE_FAILURE_TEST_HOOK.with(std::cell::Cell::get) {
        return Err("injected exact-handle deletion failure".into());
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|error| format!("delete exact held transaction identity: {error}"))
}

struct CleanupCapability {
    file: fs::File,
    generation: FileGeneration,
}

impl CleanupCapability {
    fn from_created(file: fs::File, path: &Path, intended: &[u8]) -> Result<Self, String> {
        #[cfg(test)]
        CREATED_ARTIFACT_CAPTURE_TEST_HOOK.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook(path);
            }
        });

        // Capture through a duplicate while retaining the original creation
        // handle. There is no close/reopen interval in which the pathname can
        // be swapped and subsequently trusted as Tirith's artifact.
        let duplicate = match file.try_clone() {
            Ok(duplicate) => duplicate,
            Err(error) => {
                let cleanup = mark_held_file_for_deletion(&file)
                    .err()
                    .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                    .unwrap_or_default();
                return Err(format!(
                    "clone newly-created artifact handle: {error}{cleanup}"
                ));
            }
        };
        let captured = capture_stable_file(duplicate, path);
        let (_, bytes, generation) = match captured {
            Ok(captured) => captured,
            Err(error) => {
                let cleanup = mark_held_file_for_deletion(&file)
                    .err()
                    .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                    .unwrap_or_default();
                return Err(format!(
                    "validate newly-created transaction artifact: {error}{cleanup}"
                ));
            }
        };
        if bytes != intended {
            let cleanup = mark_held_file_for_deletion(&file)
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!(
                "newly-created transaction artifact did not contain the intended bytes{cleanup}"
            ));
        }
        if generation.reparse_tag.is_some()
            || !path_rules::attributes_are_safe(generation.attributes, false)
            || !owner_only_security_descriptor(&generation.security_descriptor)
        {
            let cleanup = mark_held_file_for_deletion(&file)
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!(
                "newly-created transaction artifact did not retain its intended owner-only non-reparse security state{cleanup}"
            ));
        }
        Ok(Self { file, generation })
    }

    fn open(path: &Path) -> Result<Self, String> {
        let handle = open_cleanup_handle(path)?
            .ok_or_else(|| format!("transaction artifact disappeared at {}", path.display()))?;
        let (file, _, generation) = capture_stable_file(handle.into_file(), path)?;
        Ok(Self { file, generation })
    }

    fn open_exact(path: &Path, expected: &FileGeneration) -> Result<Option<Self>, String> {
        let Some(handle) = open_cleanup_handle(path)? else {
            return Ok(None);
        };
        let (file, _, generation) = capture_stable_file(handle.into_file(), path)?;
        let capability = Self { file, generation };
        if &capability.generation != expected {
            return Ok(None);
        }
        Ok(Some(capability))
    }

    fn validate(&mut self, path: &Path) -> Result<(), String> {
        let (_, _, generation) = capture_stable_file(
            self.file
                .try_clone()
                .map_err(|error| format!("clone held cleanup handle: {error}"))?,
            path,
        )?;
        if generation != self.generation {
            return Err(format!(
                "{} changed through its held cleanup handle",
                path.display()
            ));
        }
        Ok(())
    }

    fn delete(self) -> Result<(), String> {
        mark_held_file_for_deletion(&self.file)
    }
}

struct HeldIdentity {
    path: PathBuf,
    file: fs::File,
    generation: FileGeneration,
}

impl HeldIdentity {
    fn open_exact(path: PathBuf, expected: &FileGeneration) -> Result<Self, String> {
        let handle = open_existing(&path)?
            .ok_or_else(|| format!("exact recovery identity disappeared at {}", path.display()))?;
        let (file, _, generation) = capture_stable_file(handle.into_file(), &path)?;
        if &generation != expected {
            return Err(format!(
                "recovery identity at {} did not match the displaced original",
                path.display()
            ));
        }
        Ok(Self {
            path,
            file,
            generation,
        })
    }

    fn validate(&self) -> Result<(), String> {
        let (_, _, generation) = capture_stable_file(
            self.file
                .try_clone()
                .map_err(|error| format!("clone held recovery handle: {error}"))?,
            &self.path,
        )?;
        if generation != self.generation {
            return Err(format!(
                "held recovery identity at {} changed",
                self.path.display()
            ));
        }
        Ok(())
    }
}

fn snapshot_destination(
    destination: &Path,
    display_path: &Path,
) -> Result<PlatformSnapshot, String> {
    snapshot_destination_capped(
        destination,
        display_path,
        super::fs_transaction::MAX_SETUP_FILE_BYTES,
    )
}

fn snapshot_destination_capped(
    destination: &Path,
    display_path: &Path,
    limit: usize,
) -> Result<PlatformSnapshot, String> {
    let Some(handle) = open_existing(destination)? else {
        return Ok(PlatformSnapshot::absent());
    };
    let (_, bytes, generation) =
        capture_stable_file_capped(handle.into_file(), display_path, limit)?;
    Ok(PlatformSnapshot {
        bytes: Some(bytes),
        mode: None,
        generation: SnapshotGeneration::Present(generation),
    })
}

pub(crate) fn read_snapshot_scoped(
    path: &Path,
    scope_root: &Path,
) -> Result<PlatformSnapshot, String> {
    let Some(parent) = validated_parent(path, scope_root, false)? else {
        return Ok(PlatformSnapshot::absent());
    };
    let destination = parent.path.join(
        path.file_name()
            .ok_or_else(|| format!("no file name for {}", path.display()))?,
    );
    let snapshot = snapshot_destination(&destination, path)?;
    drop(parent);
    Ok(snapshot)
}

/// Read at a smaller cap while retaining the same parent, ACL, and file-generation checks.
pub(crate) fn read_snapshot_scoped_capped(
    path: &Path,
    scope_root: &Path,
    limit: usize,
) -> Result<PlatformSnapshot, String> {
    let Some(parent) = validated_parent(path, scope_root, false)? else {
        return Ok(PlatformSnapshot::absent());
    };
    let destination = parent
        .path
        .join(path.file_name().ok_or("file name unavailable")?);
    let Some(handle) = open_existing(&destination)? else {
        return Ok(PlatformSnapshot::absent());
    };
    let (_, bytes, generation) = capture_stable_file_capped(
        handle.into_file(),
        path,
        limit.min(super::fs_transaction::MAX_SETUP_FILE_BYTES),
    )?;
    let snapshot = PlatformSnapshot {
        bytes: Some(bytes),
        mode: None,
        generation: SnapshotGeneration::Present(generation),
    };
    drop(parent);
    Ok(snapshot)
}

/// Read through validated, retained no-reparse parent handles with a strict
/// cap. Missing files or parents return `None` without creating directories.
pub fn read_to_string_scoped(path: &Path, scope_root: &Path) -> Result<Option<String>, String> {
    read_snapshot_scoped(path, scope_root)?
        .bytes
        .map(|bytes| {
            String::from_utf8(bytes)
                .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))
        })
        .transpose()
}

pub(crate) fn directory_identity(path: &Path) -> Result<(u64, u64), String> {
    let handle = open_directory(path)?.ok_or("mutation scope directory disappeared")?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle.0, &mut information) }
        .map_err(|e| format!("identify mutation scope directory: {e}"))?;
    Ok((
        information.dwVolumeSerialNumber as u64,
        ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
    ))
}

pub(crate) fn private_directory_names(
    directory: &Path,
    scope: &Path,
    limit: usize,
) -> Result<(Vec<OsString>, bool), String> {
    let Some(_parents) = validated_parent(&directory.join(".inventory"), scope, false)? else {
        return Ok((Vec::new(), false));
    };
    // Parent handles deny delete-sharing, retaining the enumerated pathname.
    let encoded = wide(directory);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(encoded.as_ptr()),
            (FILE_GENERIC_READ | READ_CONTROL).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|_| "cannot retain private journal directory")?;
    let held = OwnedHandle(handle).into_file();
    validate_control_directory_handle(&held)?;
    let mut names = Vec::new();
    let mut limited = false;
    for entry in fs::read_dir(directory).map_err(|_| "cannot enumerate private journals")? {
        let entry = entry.map_err(|_| "private journal enumeration failed")?;
        if names.len() == limit {
            limited = true;
            break;
        }
        names.push(entry.file_name());
    }
    validate_control_directory_handle(&held)?;
    Ok((names, limited))
}

/// Keep operation payloads and compensation preimages private on Windows too.
/// Retained parent handles prevent rename/reparse substitution while applying
/// and verifying the owner-only DACL on the directory handle.
pub(crate) fn ensure_private_directory(path: &Path, scope_root: &Path) -> Result<(), String> {
    let _parents = validated_parent(&path.join(".journal-entry"), scope_root, true)?
        .ok_or("cannot create private journal directory")?;
    let encoded = wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(encoded.as_ptr()),
            (FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| format!("open private journal directory: {e}"))?;
    let held = OwnedHandle(handle);
    // This helper is only for the caller's explicitly selected managed state
    // directory. Never take ownership of an existing shared/foreign directory.
    let mut before = security_descriptor(held.0, path)?;
    let mut owner = PSID::default();
    let mut defaulted = BOOL(0);
    unsafe {
        GetSecurityDescriptorOwner(
            PSECURITY_DESCRIPTOR(before.as_mut_ptr().cast()),
            &mut owner,
            &mut defaulted,
        )
    }
    .map_err(|e| format!("read private journal directory owner: {e}"))?;
    if owner.0.is_null() || !owner_is_current_user(owner) {
        return Err("private journal directory is not owned by the current user".into());
    }
    let descriptor = owner_only_descriptor()?;
    let mut dacl = std::ptr::null_mut();
    let mut present = BOOL(0);
    unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        .map_err(|e| format!("read private journal directory DACL: {e}"))?;
    if !present.as_bool() || dacl.is_null() {
        return Err("private journal directory descriptor has no DACL".into());
    }
    // SetSecurityInfo is the filesystem-specific API. Protection must be an
    // explicit security-information flag, not merely a bit in the source SDDL.
    unsafe {
        SetSecurityInfo(
            held.0,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    }
    .ok()
    .map_err(|e| format!("make journal directory private: {e}"))?;
    if !owner_only_security_descriptor(&security_descriptor(held.0, path)?) {
        return Err("private journal directory ACL could not be verified".into());
    }
    Ok(())
}

fn owner_only_descriptor() -> Result<LocalSecurityDescriptor, String> {
    let sid = current_user_sid_string()?;
    let sddl = format!("O:{sid}D:P(A;;FA;;;{sid})");
    let sddl_wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .map_err(|e| format!("build owner-only security descriptor: {e}"))?;
    Ok(LocalSecurityDescriptor(descriptor))
}

fn transaction_mutex_name(path: &Path, scope_root: &Path) -> Result<Vec<u16>, String> {
    let current = std::env::current_dir().map_err(|error| format!("current_dir: {error}"))?;
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current.join(path)
    };
    let absolute_root = if scope_root.is_absolute() {
        scope_root.to_path_buf()
    } else {
        current.join(scope_root)
    };
    let mut hasher = Sha256::new();
    for unit in absolute_root
        .to_string_lossy()
        .to_lowercase()
        .encode_utf16()
    {
        hasher.update(unit.to_le_bytes());
    }
    hasher.update([0]);
    for unit in absolute_path
        .to_string_lossy()
        .to_lowercase()
        .encode_utf16()
    {
        hasher.update(unit.to_le_bytes());
    }
    let mut lock_name = String::from("Local\\TirithSetup-");
    for byte in hasher.finalize() {
        let _ = write!(&mut lock_name, "{byte:02x}");
    }
    Ok(lock_name.encode_utf16().chain(Some(0)).collect())
}

fn open_transaction_mutex(path: &Path, scope_root: &Path) -> Result<OwnedHandle, String> {
    let name = transaction_mutex_name(path, scope_root)?;
    let owner_only = owner_only_descriptor()?;
    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: owner_only.0 .0,
        bInheritHandle: BOOL(0),
    };
    let handle = unsafe { CreateMutexW(Some(&security_attributes), false, PCWSTR(name.as_ptr())) }
        .map_err(|error| format!("open owner-only setup transaction mutex: {error}"))?;
    Ok(OwnedHandle(handle))
}

pub(crate) struct PlatformLock {
    mutex: OwnedHandle,
    owned: bool,
}

pub(crate) fn try_lock_operation(
    path: &Path,
    scope: &Path,
) -> Result<Option<PlatformLock>, String> {
    let mutex = open_transaction_mutex(path, scope)?;
    let wait = unsafe { WaitForSingleObject(mutex.0, 0) };
    if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
        Ok(Some(PlatformLock { mutex, owned: true }))
    } else if wait == windows::Win32::Foundation::WAIT_TIMEOUT {
        Ok(None)
    } else {
        Err(format!("wait for operation mutex returned {}", wait.0))
    }
}

impl Drop for PlatformLock {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                let _ = ReleaseMutex(self.mutex.0);
            }
        }
    }
}

pub(crate) struct PlatformTransaction {
    parent: ValidatedParent,
    destination: PathBuf,
    display_path: PathBuf,
    _lock: PlatformLock,
    published_generation: std::cell::RefCell<Option<FileGeneration>>,
    published_recovery: RefCell<Option<PathBuf>>,
    cleanup_failures: Rc<RefCell<Vec<String>>>,
}

impl PlatformTransaction {
    pub(crate) fn lock(path: &Path, scope_root: &Path) -> Result<PlatformLock, String> {
        Self::lock_for(path, scope_root, super::fs_transaction::SETUP_LOCK_TIMEOUT)
    }

    pub(crate) fn lock_for(
        path: &Path,
        scope_root: &Path,
        timeout: std::time::Duration,
    ) -> Result<PlatformLock, String> {
        let mutex = open_transaction_mutex(path, scope_root)?;
        super::fs_transaction::wait_for_lock(timeout, || {
            let wait = unsafe { WaitForSingleObject(mutex.0, 0) };
            if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
                Ok(true)
            } else if wait == windows::Win32::Foundation::WAIT_TIMEOUT {
                Ok(false)
            } else {
                Err(format!(
                    "wait for setup transaction mutex returned {}",
                    wait.0
                ))
            }
        })?;
        Ok(PlatformLock { mutex, owned: true })
    }

    pub(crate) fn begin(
        path: &Path,
        scope_root: &Path,
        lock: PlatformLock,
    ) -> Result<Self, String> {
        let parent = validated_parent(path, scope_root, true)?
            .ok_or_else(|| format!("cannot create parent for {}", path.display()))?;
        let destination = parent.path.join(
            path.file_name()
                .ok_or_else(|| format!("no file name for {}", path.display()))?,
        );
        Ok(Self {
            parent,
            destination,
            display_path: path.to_path_buf(),
            _lock: lock,
            published_generation: std::cell::RefCell::new(None),
            published_recovery: RefCell::new(None),
            cleanup_failures: Rc::new(RefCell::new(Vec::new())),
        })
    }

    #[cfg(test)]
    fn lock_is_contended(path: &Path, scope_root: &Path) -> Result<bool, String> {
        let mutex = open_transaction_mutex(path, scope_root)?;
        let wait = unsafe { WaitForSingleObject(mutex.0, 0) };
        if wait == windows::Win32::Foundation::WAIT_TIMEOUT {
            Ok(true)
        } else if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            unsafe { ReleaseMutex(mutex.0) }
                .map_err(|error| format!("release probed setup mutex: {error}"))?;
            Ok(false)
        } else {
            Err(format!("probe setup transaction mutex returned {}", wait.0))
        }
    }

    pub(crate) fn read_snapshot(&self) -> Result<PlatformSnapshot, String> {
        snapshot_destination(&self.destination, &self.display_path)
    }

    pub(crate) fn take_cleanup_failures(&self) -> Vec<String> {
        std::mem::take(&mut *self.cleanup_failures.borrow_mut())
    }

    pub(crate) fn validate_snapshot(&self, expected: &PlatformSnapshot) -> Result<(), String> {
        let parent_final = final_path(
            self.parent
                .handles
                .last()
                .expect("validated parent has a handle")
                .0,
        )?;
        if !path_rules::final_path_within(&self.parent.root_final, &parent_final) {
            return Err("destination parent moved outside trusted setup root".into());
        }
        let limit = expected.bytes.as_ref().map_or(0, Vec::len);
        let live = snapshot_destination_capped(&self.destination, &self.display_path, limit)?;
        if &live != expected {
            return Err(format!(
                "{} changed while setup was preparing the update; no changes were published",
                self.display_path.display()
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_temp<'a>(
        &'a self,
        bytes: &[u8],
        _mode: u32,
        _preserve_existing_mode: bool,
        _snapshot: &PlatformSnapshot,
        _keep_backup: Option<&BackupGuard>,
    ) -> Result<TempGuard<'a>, String> {
        let path = self.parent.path.join(format!(
            ".tirith-setup-{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        let path_wide = wide(&path);
        let owner_only = owner_only_descriptor()?;
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: owner_only.0 .0,
            bInheritHandle: BOOL(0),
        };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                (FILE_GENERIC_READ
                    | FILE_GENERIC_WRITE
                    | READ_CONTROL
                    | FILE_READ_ATTRIBUTES
                    | DELETE)
                    .0,
                FILE_SHARE_READ,
                Some(&security_attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| format!("create exclusive owner-only temporary file: {error}"))?;
        let mut file = OwnedHandle(handle).into_file();
        if let Err(error) = file.write_all(bytes) {
            let cleanup = mark_held_file_for_deletion(&file)
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!("write temporary file: {error}{cleanup}"));
        }
        if let Err(error) = unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) } {
            let cleanup = mark_held_file_for_deletion(&file)
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!(
                "flush temporary file before publication: {error}{cleanup}"
            ));
        }
        let cleanup = CleanupCapability::from_created(file, &path, bytes)?;
        let generation = cleanup.generation.clone();
        Ok(TempGuard {
            _transaction: self,
            path,
            cleanup: Some(cleanup),
            generation,
            armed: true,
            cleanup_failures: Rc::clone(&self.cleanup_failures),
        })
    }

    pub(crate) fn publish(
        &self,
        mut temp: TempGuard<'_>,
        expected: &PlatformSnapshot,
        #[cfg(test)] test_hook: &mut impl FnMut(super::fs_transaction::TestStage) -> Result<(), String>,
    ) -> Result<PublicationGuard, String> {
        let expected_exists = expected.bytes.is_some();
        // ReplaceFileW documents two failure modes in which it may already
        // have moved one or both names. Keep a private, flushed copy of the
        // locked snapshot until the API has returned so those failures cannot
        // erase both the original and the transaction artifacts.
        let mut recovery = if expected_exists {
            Some(self.create_backup_impl(expected, false)?)
        } else {
            None
        };

        // Creating the recovery copy can take time, so repeat the complete
        // no-follow generation/content/DACL check before publication while the
        // prepared identity remains protected by its no-share-delete handle.
        temp.validate_name()?;
        self.validate_snapshot(expected)?;
        temp.release_for_publication()?;
        #[cfg(test)]
        test_hook(super::fs_transaction::TestStage::PublicationReady)?;

        let temp_wide = wide(&temp.path);
        let destination_wide = wide(&self.destination);
        match path_rules::publication_kind(expected_exists) {
            path_rules::PublicationKind::ReplacePreservingMetadata => {
                let SnapshotGeneration::Present(expected_generation) = &expected.generation else {
                    unreachable!("existing snapshot has a generation")
                };
                let displaced_path = new_displaced_path(&self.destination, expected_generation)?;
                if let Err(error) =
                    replace_file_call(&self.destination, &temp.path, &displaced_path)
                {
                    let names_may_have_changed =
                        is_win32(&error, ERROR_UNABLE_TO_MOVE_REPLACEMENT.0)
                            || is_win32(&error, ERROR_UNABLE_TO_MOVE_REPLACEMENT_2.0);
                    if names_may_have_changed {
                        let destination_generation = generation_at(&self.destination);
                        let replacement_generation = generation_at(&temp.path);
                        let displaced_generation = generation_at(&displaced_path);

                        // With an API backup name, ERROR_UNABLE_TO_MOVE_REPLACEMENT
                        // documents that both original names remain. Prove that
                        // exact identity state before treating it as a clean
                        // failure; otherwise retain every artifact.
                        if is_win32(&error, ERROR_UNABLE_TO_MOVE_REPLACEMENT.0)
                            && destination_generation.as_ref().is_ok_and(|generation| {
                                generation.as_ref() == Some(expected_generation)
                            })
                            && replacement_generation.as_ref().is_ok_and(|generation| {
                                generation.as_ref() == Some(&temp.generation)
                            })
                            && displaced_generation.as_ref().is_ok_and(Option::is_none)
                        {
                            return Err(format!(
                                "replace {} failed before moving either identity: {error}",
                                self.destination.display()
                            ));
                        }

                        let recovery_path = recovery
                            .as_mut()
                            .expect("existing replacement has a recovery snapshot")
                            .retain_for_recovery()
                            .map_err(|validation| {
                                format!(
                                    "replace {} entered a partial Windows failure state ({error}); recovery snapshot validation failed: {validation}",
                                    self.destination.display()
                                )
                            })?;
                        temp.armed = false;
                        return Err(format!(
                            "replace {} entered a partial Windows failure state ({error}); retained the locked original snapshot at {}, destination identity {:?}, replacement identity {:?} at {}, and displaced identity {:?} at {}",
                            self.destination.display(),
                            recovery_path.display(),
                            destination_generation,
                            replacement_generation,
                            temp.path.display(),
                            displaced_generation,
                            displaced_path.display()
                        ));
                    }
                    return Err(format!(
                        "replace {} while preserving its DACL: {error}",
                        self.destination.display()
                    ));
                }

                let mut installed = match generation_at(&self.destination) {
                    Ok(generation) => generation,
                    Err(observation_error) => {
                        let recovery_path = recovery
                            .as_mut()
                            .expect("existing replacement has a recovery snapshot")
                            .retain_for_recovery()
                            .map_err(|validation| {
                                format!("published identity inspection failed and recovery snapshot validation failed: {validation}")
                            })?;
                        temp.armed = false;
                        return Err(format!(
                            "published {} but could not inspect the installed identity ({observation_error}); retained recovery snapshot {}, replacement {}, and displaced path {}",
                            self.destination.display(),
                            recovery_path.display(),
                            temp.path.display(),
                            displaced_path.display()
                        ));
                    }
                };
                // `ReplaceFileW` rewrote the installed file's security metadata
                // (merged DACL, creator owner). Put the preserved descriptor
                // back — but only on the exact identity that was just
                // installed, so a swapped-in competitor never gets its
                // descriptor rewritten. The byte-for-byte comparison below then
                // verifies against the refreshed post-restore observation.
                let mut restore_failure: Option<String> = None;
                if let Some(generation) = installed.as_ref() {
                    if generation.same_identity(&temp.generation)
                        && generation.security_descriptor != expected_generation.security_descriptor
                    {
                        match restore_preserved_security(
                            &self.destination,
                            generation,
                            &expected_generation.security_descriptor,
                        ) {
                            Ok(refreshed) => installed = Some(refreshed),
                            Err(error) => restore_failure = Some(error),
                        }
                    }
                }
                let displaced = match generation_at(&displaced_path) {
                    Ok(generation) => generation,
                    Err(observation_error) => {
                        let recovery_path = recovery
                            .as_mut()
                            .expect("existing replacement has a recovery snapshot")
                            .retain_for_recovery()
                            .map_err(|validation| {
                                format!("displaced identity inspection failed and recovery snapshot validation failed: {validation}")
                            })?;
                        temp.armed = false;
                        return Err(format!(
                            "published {} but could not inspect its displaced identity ({observation_error}); retained recovery snapshot {}, replacement {}, and displaced path {}",
                            self.destination.display(),
                            recovery_path.display(),
                            temp.path.display(),
                            displaced_path.display()
                        ));
                    }
                };
                // Name each component that disagreed. The publication contract
                // spans identity, bytes, attributes, and the preserved security
                // descriptor, and an opaque "changed at publication" gives a
                // caller nothing to act on.
                let mut mismatches = Vec::new();
                match installed.as_ref() {
                    None => mismatches.push("destination absent after replace".to_string()),
                    Some(generation) => {
                        if !generation.same_identity(&temp.generation) {
                            mismatches
                                .push("installed identity is not the replacement".to_string());
                        }
                        if generation.size != temp.generation.size {
                            mismatches.push(format!(
                                "installed size {} != replacement size {}",
                                generation.size, temp.generation.size
                            ));
                        }
                        if generation.digest != temp.generation.digest {
                            mismatches.push("installed digest is not the replacement".to_string());
                        }
                        if generation.reparse_tag != temp.generation.reparse_tag {
                            mismatches.push("installed reparse tag changed".to_string());
                        }
                        if !path_rules::attributes_are_safe(generation.attributes, false) {
                            mismatches.push(format!(
                                "installed attributes {:#x} are unsafe",
                                generation.attributes
                            ));
                        }
                        if generation.security_descriptor != expected_generation.security_descriptor
                        {
                            mismatches.push(format!(
                                "installed security descriptor {} is not the preserved one {}",
                                describe_security_descriptor(&generation.security_descriptor),
                                describe_security_descriptor(
                                    &expected_generation.security_descriptor
                                )
                            ));
                        }
                    }
                }
                match displaced.as_ref() {
                    None => mismatches.push("no displaced backup was produced".to_string()),
                    Some(generation) if generation != expected_generation => {
                        mismatches.push(format!(
                            "displaced identity differs (same_identity={}, sd {} vs {})",
                            generation.same_identity(expected_generation),
                            describe_security_descriptor(&generation.security_descriptor),
                            describe_security_descriptor(&expected_generation.security_descriptor)
                        ));
                    }
                    Some(_) => {}
                }
                if let Some(error) = restore_failure {
                    mismatches.push(format!(
                        "preserved security descriptor could not be restored ({error})"
                    ));
                }
                if !mismatches.is_empty() {
                    // ReplaceFileW's backup captured the exact competing file.
                    // Atomically restore it and keep our attempted replacement
                    // at the original private temp name.
                    let stable = generation_at(&self.destination)
                        .is_ok_and(|live| live == installed)
                        && generation_at(&displaced_path).is_ok_and(|live| live == displaced)
                        && generation_at(&temp.path).is_ok_and(|live| live.is_none());
                    if stable
                        && replace_file_call(&self.destination, &displaced_path, &temp.path).is_ok()
                        && generation_at(&self.destination)
                            .is_ok_and(|live| rollback_landed(live.as_ref(), displaced.as_ref()))
                        && generation_at(&temp.path).is_ok_and(|live| live == installed)
                    {
                        // The rollback replace rewrote the restored competitor's
                        // descriptor exactly the way publication rewrote ours.
                        // Its identity and bytes are proven back above; put the
                        // descriptor that was observed on it back too, so the
                        // competitor is restored in full. Best-effort by
                        // design — the identity proof is what the error claims.
                        if let (Ok(Some(live)), Some(displaced_generation)) =
                            (generation_at(&self.destination), displaced.as_ref())
                        {
                            if live.security_descriptor != displaced_generation.security_descriptor
                            {
                                let _ = restore_preserved_security(
                                    &self.destination,
                                    &live,
                                    &displaced_generation.security_descriptor,
                                );
                            }
                        }
                        // When the file back at the private temp name is OUR
                        // OWN prepared replacement, byte for byte, its metadata
                        // (the restored descriptor) no longer matches the
                        // generation the cleanup guard captured at preparation,
                        // so the scheduled scrub could not reacquire it and the
                        // artifact would strand. Point the guard at the exact
                        // identity verified above. Anything else at that name,
                        // a swapped-in foreign file OR our identity carrying
                        // tampered bytes, keeps the original expectation and is
                        // deliberately retained as evidence.
                        if let Some(generation) = installed.as_ref() {
                            if generation.same_identity(&temp.generation)
                                && generation.digest == temp.generation.digest
                                && generation.size == temp.generation.size
                            {
                                temp.generation = generation.clone();
                            }
                        }
                        return Err(format!(
                            "{} or its prepared replacement changed at publication ({}); restored the competing destination and published nothing",
                            self.destination.display(),
                            mismatches.join("; ")
                        ));
                    }

                    let recovery_path = recovery
                        .as_mut()
                        .expect("existing replacement has a recovery snapshot")
                        .retain_for_recovery()
                        .map_err(|validation| {
                            format!("rollback was uncertain and recovery snapshot validation failed: {validation}")
                        })?;
                    temp.armed = false;
                    return Err(format!(
                        "{} or its prepared replacement changed at publication ({}) and rollback could not be proven; retained recovery snapshot {}, replacement {}, and displaced identity {}",
                        self.destination.display(),
                        mismatches.join("; "),
                        recovery_path.display(),
                        temp.path.display(),
                        displaced_path.display()
                    ));
                }

                let installed = installed.expect("successful replacement has installed state");
                self.published_generation.replace(Some(installed.clone()));
                let held_installed = match HeldIdentity::open_exact(
                    self.destination.clone(),
                    &installed,
                ) {
                    Ok(installed) => installed,
                    Err(hold_error) => {
                        let recovery_path = recovery
                            .as_mut()
                            .expect("existing replacement has a recovery snapshot")
                            .retain_for_recovery()
                            .map_err(|validation| {
                                format!("installed identity hold failed and recovery snapshot validation failed: {validation}")
                            })?;
                        temp.armed = false;
                        return Err(format!(
                            "published {} but could not hold its exact installed identity ({hold_error}); retained recovery snapshot {} and displaced path {}",
                            self.destination.display(),
                            recovery_path.display(),
                            displaced_path.display()
                        ));
                    }
                };
                let displaced = match HeldIdentity::open_exact(
                    displaced_path.clone(),
                    expected_generation,
                ) {
                    Ok(displaced) => displaced,
                    Err(hold_error) => {
                        let recovery_path = recovery
                            .as_mut()
                            .expect("existing replacement has a recovery snapshot")
                            .retain_for_recovery()
                            .map_err(|validation| {
                                format!("displaced identity hold failed and recovery snapshot validation failed: {validation}")
                            })?;
                        temp.armed = false;
                        return Err(format!(
                            "published {} but could not hold its exact displaced identity ({hold_error}); retained recovery snapshot {} and displaced path {}",
                            self.destination.display(),
                            recovery_path.display(),
                            displaced_path.display()
                        ));
                    }
                };
                self.published_recovery
                    .replace(Some(displaced_path.clone()));
                temp.armed = false;
                return Ok(PublicationGuard::replacement(
                    held_installed,
                    displaced,
                    recovery,
                ));
            }
            path_rules::PublicationKind::MoveWithoutReplacement => {
                // Omitting REPLACE_EXISTING gives expected-absent publication
                // an atomic never-overwrite guarantee.
                unsafe {
                    MoveFileExW(
                        PCWSTR(temp_wide.as_ptr()),
                        PCWSTR(destination_wide.as_ptr()),
                        MOVEFILE_WRITE_THROUGH,
                    )
                }
                .map_err(|error| {
                    format!(
                        "publish new destination {} without replacement: {error}",
                        self.destination.display()
                    )
                })?;
                let installed = match generation_at(&self.destination) {
                    Ok(Some(generation)) => generation,
                    Ok(None) => {
                        temp.armed = false;
                        return Err(format!(
                            "published destination {} disappeared; the prepared pathname was retained for recovery",
                            self.destination.display()
                        ));
                    }
                    Err(observation_error) => {
                        temp.armed = false;
                        return Err(format!(
                            "published destination {} but could not verify it ({observation_error}); retained the published pathname for recovery",
                            self.destination.display()
                        ));
                    }
                };
                if installed != temp.generation {
                    temp.armed = false;
                    return Err(format!(
                        "published destination {} no longer identifies the exact prepared replacement; retained its pathname for recovery",
                        self.destination.display()
                    ));
                }
                self.published_generation.replace(Some(installed.clone()));
                let held_installed = match HeldIdentity::open_exact(
                    self.destination.clone(),
                    &installed,
                ) {
                    Ok(installed) => installed,
                    Err(hold_error) => {
                        temp.armed = false;
                        return Err(format!(
                                "published destination {} but could not hold its exact installed identity ({hold_error}); retained the published pathname for recovery",
                                self.destination.display()
                            ));
                    }
                };
                temp.armed = false;
                return Ok(PublicationGuard::clean(held_installed));
            }
        }
    }

    pub(crate) fn sync_parent(&self) -> Result<(), String> {
        // Windows exposes no directory fsync and ReplaceFileW explicitly does
        // not support REPLACEFILE_WRITE_THROUGH. This is therefore an honest
        // exact-file FlushFileBuffers gate, not a claim that the namespace
        // transition itself is durable. Existing-file replacement keeps its
        // displaced original until the caller receives a degraded outcome.
        let destination_wide = wide(&self.destination);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(destination_wide.as_ptr()),
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| {
            format!(
                "open published destination {} for durability: {error}",
                self.destination.display()
            )
        })?;
        let expected = self.published_generation.borrow().clone().ok_or_else(|| {
            "no published identity available for durability validation".to_string()
        })?;
        let mut file = OwnedHandle(handle).into_file();
        let (_, _, before) = capture_stable_file(
            file.try_clone()
                .map_err(|error| format!("clone published file handle: {error}"))?,
            &self.destination,
        )?;
        if before != expected {
            return Err(format!(
                "published destination {} changed before durability flush",
                self.destination.display()
            ));
        }
        unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }.map_err(|error| {
            format!(
                "flush published destination {} after replacement: {error}",
                self.destination.display()
            )
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| format!("rewind published destination: {error}"))?;
        let (_, _, after) = capture_stable_file(file, &self.destination)?;
        if after != expected {
            return Err(format!(
                "published destination {} changed during durability flush",
                self.destination.display()
            ));
        }
        Ok(())
    }

    pub(crate) fn create_backup(&self, snapshot: &PlatformSnapshot) -> Result<BackupGuard, String> {
        self.create_backup_impl(snapshot, true)
    }

    fn create_backup_impl(
        &self,
        snapshot: &PlatformSnapshot,
        announce: bool,
    ) -> Result<BackupGuard, String> {
        let bytes = snapshot
            .bytes
            .as_deref()
            .ok_or_else(|| "cannot back up an absent destination".to_string())?;
        let name = backup_name(&self.destination, bytes);
        let path = self.parent.path.join(name);
        let path_wide = wide(&path);
        let owner_only = owner_only_descriptor()?;
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: owner_only.0 .0,
            bInheritHandle: BOOL(0),
        };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                (FILE_GENERIC_READ
                    | FILE_GENERIC_WRITE
                    | READ_CONTROL
                    | FILE_READ_ATTRIBUTES
                    | DELETE)
                    .0,
                FILE_SHARE_READ,
                Some(&security_attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| format!("create exclusive owner-only backup: {error}"))?;
        let mut file = OwnedHandle(handle).into_file();
        if let Err(error) = file.write_all(bytes) {
            let cleanup = mark_held_file_for_deletion(&file)
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!(
                "write backup from locked snapshot: {error}{cleanup}"
            ));
        }
        if let Err(error) = unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) } {
            let cleanup = mark_held_file_for_deletion(&file)
                .err()
                .map(|cleanup| format!("; cleanup also failed: {cleanup}"))
                .unwrap_or_default();
            return Err(format!("flush backup before update: {error}{cleanup}"));
        }
        let cleanup = CleanupCapability::from_created(file, &path, bytes)?;
        if !backup_name_matches(&path, &self.destination, &cleanup.generation) {
            let cleanup_error = cleanup
                .delete()
                .err()
                .map(|error| format!("; cleanup also failed: {error}"))
                .unwrap_or_default();
            return Err(format!(
                "new backup did not satisfy its provenance or owner-only security binding{cleanup_error}"
            ));
        }
        Ok(BackupGuard {
            path,
            destination: self.destination.clone(),
            cleanup: Some(cleanup),
            armed: true,
            announce_on_commit: announce,
            cleanup_failures: Rc::clone(&self.cleanup_failures),
        })
    }

    pub(crate) fn cleanup_old_backups(&self, keep: Option<&BackupGuard>) -> Result<(), String> {
        let entries = fs::read_dir(&self.parent.path)
            .map_err(|error| format!("enumerate transaction artifact directory: {error}"))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("enumerate transaction artifact entry: {error}"))?;
        let mut failures = Vec::new();

        let keep_backup = keep.map(|guard| guard.path.clone());
        let mut backups = Vec::new();
        for path in entries.iter().filter(|path| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with(BACKUP_MARKER)
                && keep_backup.as_ref() != Some(*path)
        }) {
            // A filename prefix is never deletion authority. The same
            // no-share-write DELETE handle must validate the complete content
            // binding, safe attributes, and protected owner-only DACL.
            let Ok(cleanup) = CleanupCapability::open(path) else {
                continue;
            };
            if backup_name_matches(path, &self.destination, &cleanup.generation) {
                backups.push((path.clone(), cleanup));
            }
        }
        backups.sort_by(|left, right| left.0.cmp(&right.0));
        let remove_backups = (backups.len() + usize::from(keep_backup.is_some()))
            .saturating_sub(ARTIFACT_RETENTION_LIMIT);
        for (old, cleanup) in backups.into_iter().take(remove_backups) {
            #[cfg(test)]
            OLD_BACKUP_CLEANUP_TEST_HOOK.with(|slot| {
                if let Some(hook) = slot.borrow_mut().as_mut() {
                    hook(&old);
                }
            });
            if let Err(error) = cleanup.delete() {
                failures.push(format!(
                    "delete provenance-bound old backup {}: {error}",
                    old.display()
                ));
            }
        }

        let keep_recovery = self.published_recovery.borrow().clone();
        let mut recoveries = Vec::new();
        for path in entries.iter().filter(|path| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with(DISPLACED_MARKER)
                && keep_recovery.as_ref() != Some(*path)
        }) {
            let Ok(cleanup) = CleanupCapability::open(path) else {
                continue;
            };
            if displaced_name_matches(path, &self.destination, &cleanup.generation) {
                recoveries.push((path.clone(), cleanup));
            }
        }
        recoveries.sort_by(|left, right| left.0.cmp(&right.0));
        let remove_recoveries = (recoveries.len() + usize::from(keep_recovery.is_some()))
            .saturating_sub(ARTIFACT_RETENTION_LIMIT);
        for (old, cleanup) in recoveries.into_iter().take(remove_recoveries) {
            if let Err(error) = cleanup.delete() {
                failures.push(format!(
                    "delete provenance-bound displaced recovery {}: {error}",
                    old.display()
                ));
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

pub(crate) struct TempGuard<'a> {
    _transaction: &'a PlatformTransaction,
    path: PathBuf,
    cleanup: Option<CleanupCapability>,
    generation: FileGeneration,
    armed: bool,
    cleanup_failures: Rc<RefCell<Vec<String>>>,
}

impl TempGuard<'_> {
    fn validate_name(&mut self) -> Result<(), String> {
        let capability = self
            .cleanup
            .as_mut()
            .ok_or_else(|| "prepared temporary cleanup capability is unavailable".to_string())?;
        capability.validate(&self.path)?;
        if capability.generation != self.generation {
            return Err(
                "temporary setup file changed before publication; refusing for safety".into(),
            );
        }
        Ok(())
    }

    fn release_for_publication(&mut self) -> Result<(), String> {
        self.validate_name()?;
        self.cleanup.take();
        if generation_at(&self.path)?.as_ref() != Some(&self.generation) {
            return Err("temporary setup file changed while releasing it for publication".into());
        }
        Ok(())
    }
}

impl Drop for TempGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let cleanup = match self.cleanup.take() {
            Some(cleanup) => Some(cleanup),
            None => match CleanupCapability::open_exact(&self.path, &self.generation) {
                Ok(Some(cleanup)) => Some(cleanup),
                Ok(None) => {
                    self.cleanup_failures.borrow_mut().push(format!(
                        "could not reacquire exact temporary identity {} for cleanup",
                        self.path.display()
                    ));
                    None
                }
                Err(error) => {
                    self.cleanup_failures.borrow_mut().push(format!(
                        "could not validate temporary identity {} for cleanup: {error}",
                        self.path.display()
                    ));
                    None
                }
            },
        };
        if let Some(cleanup) = cleanup {
            if let Err(error) = cleanup.delete() {
                self.cleanup_failures.borrow_mut().push(format!(
                    "could not scrub exact temporary identity {}: {error}",
                    self.path.display()
                ));
            }
        }
    }
}

pub(crate) struct BackupGuard {
    path: PathBuf,
    destination: PathBuf,
    cleanup: Option<CleanupCapability>,
    armed: bool,
    announce_on_commit: bool,
    cleanup_failures: Rc<RefCell<Vec<String>>>,
}

impl BackupGuard {
    fn validate(&mut self, purpose: &str) -> Result<(), String> {
        let cleanup = self
            .cleanup
            .as_mut()
            .ok_or_else(|| "backup cleanup capability is unavailable before commit".to_string())?;
        cleanup.validate(&self.path).map_err(|error| {
            format!(
                "backup {} changed before {purpose}: {error}",
                self.path.display(),
            )
        })?;
        if !backup_name_matches(&self.path, &self.destination, &cleanup.generation) {
            return Err(format!(
                "backup {} lost its provenance/security binding before {purpose}",
                self.path.display(),
            ));
        }
        Ok(())
    }

    pub(crate) fn commit(&mut self) -> Result<(), String> {
        self.validate("commit/announcement")?;
        self.armed = false;
        if self.announce_on_commit {
            eprintln!("tirith: backup at {}", self.path.display());
        }
        Ok(())
    }

    pub(crate) fn retain_for_recovery(&mut self) -> Result<PathBuf, String> {
        self.validate("recovery announcement")?;
        self.armed = false;
        Ok(self.path.clone())
    }
}

impl Drop for BackupGuard {
    fn drop(&mut self) {
        if self.armed {
            if let Some(cleanup) = self.cleanup.take() {
                if let Err(error) = cleanup.delete() {
                    self.cleanup_failures.borrow_mut().push(format!(
                        "could not scrub exact backup identity {}: {error}",
                        self.path.display()
                    ));
                }
            }
        }
    }
}

pub(crate) struct PublicationGuard {
    installed: HeldIdentity,
    displaced: Option<HeldIdentity>,
    recovery: Option<BackupGuard>,
}

impl PublicationGuard {
    fn clean(installed: HeldIdentity) -> Self {
        Self {
            installed,
            displaced: None,
            recovery: None,
        }
    }

    fn replacement(
        installed: HeldIdentity,
        displaced: HeldIdentity,
        recovery: Option<BackupGuard>,
    ) -> Self {
        Self {
            installed,
            displaced: Some(displaced),
            recovery,
        }
    }

    pub(crate) fn retain_for_recovery(&mut self) -> String {
        let installed = self
            .installed
            .validate()
            .map(|()| {
                format!(
                    "exact installed identity at {}",
                    self.installed.path.display()
                )
            })
            .unwrap_or_else(|error| format!("installed identity validation failed: {error}"));
        let displaced = self.displaced.as_ref().map(|identity| {
            identity
                .validate()
                .map(|()| format!("exact displaced original at {}", identity.path.display()))
                .unwrap_or_else(|error| format!("displaced original validation failed: {error}"))
        });
        let snapshot = self.recovery.as_mut().map(|backup| {
            backup
                .retain_for_recovery()
                .map(|path| format!("locked recovery snapshot at {}", path.display()))
                .unwrap_or_else(|error| format!("recovery snapshot validation failed: {error}"))
        });
        match (displaced, snapshot) {
            (Some(displaced), Some(snapshot)) => {
                format!("retained {installed}, {displaced}, and {snapshot}")
            }
            (Some(displaced), None) => format!("retained {installed} and {displaced}"),
            (None, Some(snapshot)) => format!("retained {installed} and {snapshot}"),
            (None, None) => format!("retained {installed}; no displaced original existed"),
        }
    }

    pub(crate) fn finish_after_durability(mut self) -> Result<PublicationOutcome, String> {
        if let Err(error) = self.installed.validate() {
            let displaced = self
                .displaced
                .as_ref()
                .map(|identity| {
                    format!(
                        "; retained displaced original at {}",
                        identity.path.display()
                    )
                })
                .unwrap_or_default();
            let recovery = self
                .recovery
                .as_mut()
                .map(BackupGuard::retain_for_recovery)
                .map(|result| match result {
                    Ok(path) => {
                        format!("; retained exact recovery snapshot at {}", path.display())
                    }
                    Err(error) => format!("; recovery snapshot validation failed: {error}"),
                })
                .unwrap_or_default();
            return Err(format!(
                "installed destination identity changed before transaction completion ({error}){displaced}{recovery}"
            ));
        }
        let Some(displaced) = self.displaced.as_ref() else {
            return Ok(PublicationOutcome::Clean);
        };
        if let Err(error) = displaced.validate() {
            let recovery = self
                .recovery
                .as_mut()
                .map(BackupGuard::retain_for_recovery)
                .map(|result| match result {
                    Ok(path) => {
                        format!("; retained exact recovery snapshot at {}", path.display())
                    }
                    Err(error) => format!("; recovery snapshot validation failed: {error}"),
                })
                .unwrap_or_default();
            return Ok(PublicationOutcome::RecoveryRetained(format!(
                "Windows replacement file flush completed, but the displaced identity could not be revalidated ({error}){recovery}"
            )));
        }
        let path = displaced.path.clone();
        // Dropping the private snapshot deletes only its still-held exact
        // identity. The API-provided displaced original remains as recovery.
        self.recovery.take();
        Ok(PublicationOutcome::RecoveryRetained(format!(
            "Windows flushed the installed file but cannot prove ReplaceFileW's directory/name transition durable; retained the exact displaced original at {}",
            path.display()
        )))
    }
}

/// Write a hook script. No executable bit needed on Windows.
pub fn write_hook_script(
    path: &Path,
    scope_root: &Path,
    content: &str,
    force: bool,
    dry_run: bool,
) -> Result<(), String> {
    let outcome = transactional_update(path, scope_root, dry_run, |snapshot| {
        if let Some(existing) = snapshot.text(path)? {
            if existing == content {
                if dry_run {
                    eprintln!(
                        "[dry-run] would skip {} (already up to date)",
                        path.display()
                    );
                } else {
                    eprintln!("tirith: {} already configured, up to date", path.display());
                }
                return Ok(FileUpdate::unchanged());
            }
            if !force {
                if dry_run {
                    eprintln!(
                        "[dry-run] would error: {} exists but content differs — use --force to update",
                        path.display()
                    );
                    return Ok(FileUpdate::unchanged());
                }
                return Err(format!(
                    "{} exists but content differs — use --force to update",
                    path.display()
                ));
            }
        }
        if dry_run {
            eprintln!(
                "[dry-run] would write {} ({} bytes)",
                path.display(),
                content.len()
            );
        }
        Ok(FileUpdate::write_text(content.to_string(), 0o644))
    })?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!("tirith: wrote {}{annotation}", path.display());
    }
    Ok(())
}

/// Validate that `dir` stays within `scope_root` after canonicalization.
pub fn validate_target_dir(dir: &Path, scope_root: Option<&Path>) -> Result<(), String> {
    let root = match scope_root {
        Some(r) => r,
        None => return Ok(()),
    };

    let root_canonical = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", root.display()))?;

    let mut check = dir.to_path_buf();
    loop {
        if check.exists() {
            let canonical = check
                .canonicalize()
                .map_err(|e| format!("canonicalize {}: {e}", check.display()))?;
            if !canonical.starts_with(&root_canonical) {
                return Err(format!(
                    "{} resolves outside project root {} — refusing for safety",
                    dir.display(),
                    root.display()
                ));
            }
            break;
        }
        if !check.pop() {
            return Err(format!(
                "cannot resolve {} — no existing ancestor found",
                dir.display()
            ));
        }
    }

    let mut path_so_far = PathBuf::new();
    for component in dir.components() {
        path_so_far.push(component);
        if path_so_far.exists() {
            if let Ok(meta) = fs::symlink_metadata(&path_so_far) {
                if meta.file_type().is_symlink() && path_so_far.starts_with(&root_canonical) {
                    return Err(format!(
                        "{} is a symlink inside project scope — refusing for safety",
                        path_so_far.display()
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Retire an obsolete content-addressed Codex gateway generation after its
/// registration has been replaced successfully. Windows deletion is bound to
/// the exact validated file handle while retained no-reparse parent handles
/// keep the destination inside the trusted setup root.
pub fn retire_codex_gateway_generation(path: &Path, scope_root: &Path) -> Result<(), String> {
    let lock = PlatformTransaction::lock(path, scope_root)?;
    let transaction = PlatformTransaction::begin(path, scope_root, lock)?;
    let snapshot = transaction.read_snapshot()?;
    let Some(bytes) = snapshot.bytes.as_deref() else {
        return Ok(());
    };
    let digest = Sha256::digest(bytes);
    let expected_name = format!("gateway-sha256-{}.yaml", hex_bytes(&digest));
    if path.file_name() != Some(OsStr::new(&expected_name)) {
        return Err(format!(
            "{} is not named for its exact gateway content; refusing retirement",
            path.display()
        ));
    }
    let SnapshotGeneration::Present(expected_generation) = &snapshot.generation else {
        return Err("gateway retirement snapshot has no stable file generation".into());
    };
    if expected_generation.reparse_tag.is_some()
        || !path_rules::attributes_are_safe(expected_generation.attributes, false)
        || !owner_only_security_descriptor(&expected_generation.security_descriptor)
    {
        return Err(format!(
            "{} is not an owner-only non-reparse file; refusing retirement",
            path.display()
        ));
    }
    transaction.validate_snapshot(&snapshot)?;
    let mut cleanup = CleanupCapability::open(&transaction.destination)?;
    if &cleanup.generation != expected_generation {
        return Err(format!("{} changed before retirement", path.display()));
    }
    cleanup.validate(&transaction.destination)?;
    cleanup.delete()?;
    if transaction.read_snapshot()?.bytes.is_some() {
        return Err(format!(
            "{} still exists after exact-handle retirement",
            path.display()
        ));
    }
    Ok(())
}

/// Run Codex with an explicitly selected project working directory. Codex's
/// global `-C` option preserves its project/user configuration semantics while the
/// supervised child itself keeps a loader-safe working directory on Windows.
pub fn run_codex_cli_in_dir(
    cwd: &Path,
    cmd: &str,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let executable = tirith_core::trusted_child::resolve_ambient(cmd)
        .map_err(|error| format!("{cmd} not found or untrusted: {error}"))?;
    let scoped_args = codex_scoped_args(cwd, args);
    run_cli_bounded(
        &executable,
        &scoped_args,
        tirith_core::trusted_child::ChildLimits::new(
            std::time::Duration::from_secs(30),
            4 * 1024 * 1024,
            4 * 1024 * 1024,
        ),
    )
}

fn codex_scoped_args(cwd: &Path, args: &[&str]) -> Vec<OsString> {
    let mut scoped = Vec::with_capacity(args.len() + 2);
    scoped.push(OsString::from("-C"));
    scoped.push(cwd.as_os_str().to_os_string());
    scoped.extend(args.iter().map(|arg| OsString::from(*arg)));
    scoped
}

fn run_cli_bounded<S: AsRef<OsStr>>(
    executable: &tirith_core::trusted_child::TrustedExecutable,
    args: &[S],
    limits: tirith_core::trusted_child::ChildLimits,
) -> Result<std::process::Output, String> {
    use tirith_core::trusted_child::{ChildOutcome, ChildSpec};

    let mut spec = ChildSpec::new(args.iter().map(AsRef::as_ref), limits).inherit_env(&[
        "HOME",
        "USER",
        "LOGNAME",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "CODEX_HOME",
        "SystemRoot",
        "WINDIR",
    ]);
    if let Some(path) = tirith_core::trusted_child::sanitized_ambient_path() {
        spec = spec.env("PATH", path);
    }
    match tirith_core::trusted_child::run(executable, &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => Ok(std::process::Output {
            status,
            stdout,
            stderr,
        }),
        ChildOutcome::SpawnError(reason) => Err(format!("failed to start: {reason}")),
        ChildOutcome::WaitError(reason) => Err(format!("wait failed: {reason}")),
        ChildOutcome::CleanupError(reason) => Err(format!("process-tree cleanup failed: {reason}")),
        ChildOutcome::Timeout {
            cleanup_succeeded: true,
        } => Err("timed out after 30s — check installation".into()),
        ChildOutcome::Timeout {
            cleanup_succeeded: false,
        } => Err("timed out and process-tree cleanup failed — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: true,
            ..
        } => Err("output limit exceeded — check installation".into()),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: false,
            ..
        } => Err("output limit exceeded and process-tree cleanup failed".into()),
    }
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn smaller_snapshot_cap_is_enforced_and_missing_parents_stay_absent() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("annotation.json");
        std::fs::write(&path, b"12345").unwrap();
        assert!(super::read_snapshot_scoped_capped(&path, root.path(), 4).is_err());
        let exact = super::read_snapshot_scoped_capped(&path, root.path(), 5).unwrap();
        assert_eq!(exact.bytes.as_deref(), Some(&b"12345"[..]));
        let absent = root.path().join("missing/entry");
        assert!(super::read_snapshot_scoped_capped(&absent, root.path(), 5)
            .unwrap()
            .bytes
            .is_none());
        assert!(!absent.parent().unwrap().exists());
    }
    use super::super::fs_transaction::{
        transactional_update_with_hook, FileUpdate, TestStage, TransactionOutcome,
    };
    use super::*;

    fn symlink_directory_or_explicitly_skip(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => true,
            Err(error) => {
                eprintln!(
                    "SKIP symlink reparse coverage: Windows denied symlink creation ({error})"
                );
                false
            }
        }
    }

    fn symlink_file_or_explicitly_skip(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_file(target, link) {
            Ok(()) => true,
            Err(error) => {
                eprintln!(
                    "SKIP backup reparse coverage: Windows denied symlink creation ({error})"
                );
                false
            }
        }
    }

    fn backup_paths(root: &Path) -> Vec<PathBuf> {
        let mut paths = fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .contains("tirith-backup")
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    fn temporary_setup_paths(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                name.starts_with(".tirith-setup-") && name.ends_with(".tmp")
            })
            .collect()
    }

    fn displaced_paths(root: &Path) -> Vec<PathBuf> {
        fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .contains("tirith-displaced")
            })
            .collect()
    }

    struct ReplaceHookReset;

    impl Drop for ReplaceHookReset {
        fn drop(&mut self) {
            REPLACE_FILE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    struct CleanupHookReset;

    impl Drop for CleanupHookReset {
        fn drop(&mut self) {
            OLD_BACKUP_CLEANUP_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    struct ArtifactCaptureHookReset;

    impl Drop for ArtifactCaptureHookReset {
        fn drop(&mut self) {
            CREATED_ARTIFACT_CAPTURE_TEST_HOOK.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn with_replace_hook<T>(
        hook: impl FnMut(&Path, &Path, &Path) -> Result<(), u32> + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        REPLACE_FILE_TEST_HOOK.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        let _reset = ReplaceHookReset;
        run()
    }

    fn with_cleanup_hook<T>(hook: impl FnMut(&Path) + 'static, run: impl FnOnce() -> T) -> T {
        OLD_BACKUP_CLEANUP_TEST_HOOK.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        let _reset = CleanupHookReset;
        run()
    }

    fn with_artifact_capture_hook<T>(
        hook: impl FnMut(&Path) + 'static,
        run: impl FnOnce() -> T,
    ) -> T {
        CREATED_ARTIFACT_CAPTURE_TEST_HOOK.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(Box::new(hook));
        });
        let _reset = ArtifactCaptureHookReset;
        run()
    }

    fn update_with_backup(path: &Path, root: &Path, content: &str) -> Result<(), String> {
        transactional_update(path, root, false, |_| {
            Ok(FileUpdate::write_text(content.to_string(), 0o644).with_backup(true))
        })?;
        Ok(())
    }

    fn descriptor_control(descriptor: &mut [u8]) -> u16 {
        use windows::Win32::Security::GetSecurityDescriptorControl;

        let descriptor = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast());
        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.unwrap();
        control
    }

    fn create_protected_owner_only_file(path: &Path, content: &[u8]) {
        let path_wide = wide(path);
        let owner_only = owner_only_descriptor().unwrap();
        let security_attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: owner_only.0 .0,
            bInheritHandle: BOOL(0),
        };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                Some(&security_attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .unwrap();
        let mut file = OwnedHandle(handle).into_file();
        file.write_all(content).unwrap();
        unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }.unwrap();
    }

    fn directory_security_for_test(path: &Path) -> Vec<u8> {
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide(path).as_ptr()),
                (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .unwrap();
        let held = OwnedHandle(handle);
        security_descriptor(held.0, path).unwrap()
    }

    #[test]
    fn private_directory_creation_is_protected_and_current_user_owned() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("managed").join("journals");
        ensure_private_directory(&path, fixture.path()).unwrap();
        ensure_private_directory(&path, fixture.path()).unwrap();
        // Every newly created component has explicit private security, including
        // the scope itself when its first child causes it to be materialized.
        for directory in [path.clone(), path.parent().unwrap().to_path_buf()] {
            assert!(owner_only_security_descriptor(
                &directory_security_for_test(&directory)
            ));
        }
        let new_scope = fixture.path().join("new-scope");
        ensure_private_directory(&new_scope, &new_scope).unwrap();
        assert!(owner_only_security_descriptor(
            &directory_security_for_test(&new_scope)
        ));
    }

    #[test]
    fn managed_private_directory_hardening_explicitly_protects_inheritance() {
        let fixture = tempfile::tempdir().unwrap();
        let directory = fixture.path().join("managed");
        let sid = current_user_sid_string().unwrap();
        let sddl: Vec<u16> = format!("O:{sid}D:(A;;FA;;;{sid})(A;;GR;;;WD)")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .unwrap();
        let descriptor = LocalSecurityDescriptor(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: BOOL(0),
        };
        unsafe { CreateDirectoryW(PCWSTR(wide(&directory).as_ptr()), Some(&attributes)) }.unwrap();
        ensure_private_directory(&directory, fixture.path()).unwrap();
        assert!(owner_only_security_descriptor(
            &directory_security_for_test(&directory)
        ));
    }

    #[test]
    fn control_ancestor_acl_distinguishes_effective_and_inherit_only_write_grants() {
        fn descriptor(sddl: &str) -> Vec<u8> {
            let encoded: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut value = PSECURITY_DESCRIPTOR::default();
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(encoded.as_ptr()),
                    SDDL_REVISION_1,
                    &mut value,
                    None,
                )
            }
            .unwrap();
            let value = LocalSecurityDescriptor(value);
            let len = unsafe { GetSecurityDescriptorLength(value.0) } as usize;
            unsafe { std::slice::from_raw_parts(value.0 .0.cast::<u8>(), len) }.to_vec()
        }
        let user = current_user_sid_string().unwrap();
        let private = descriptor(&format!("O:{user}D:P(A;;FA;;;{user})"));
        assert!(owner_only_security_descriptor(&private));
        assert!(control_ancestor_security_descriptor(&private));
        assert!(control_ancestor_security_descriptor(&descriptor(
            "O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)(A;OICIIO;GW;;;BU)"
        )));
        for rights in ["GW", "GA", "WD", "WO", "DC", "WDAC", "0x00000002"] {
            // WDAC is spelled numerically in SDDL; the other values are
            // filesystem or standard-right abbreviations.
            let rights = if rights == "WDAC" {
                "0x00040000"
            } else {
                rights
            };
            assert!(!control_ancestor_security_descriptor(&descriptor(
                &format!("O:SYD:(A;;FA;;;SY)(A;;{rights};;;BU)")
            )));
        }
        assert!(!control_ancestor_security_descriptor(&descriptor(
            "O:BUD:(A;;FA;;;SY)"
        )));
    }

    fn overwrite_same_length_and_restore_last_write(path: &Path, content: &[u8]) {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let handle = HANDLE(file.as_raw_handle());
        let before = handle_information(handle, path).unwrap();
        let original_size = ((before.nFileSizeHigh as u64) << 32) | before.nFileSizeLow as u64;
        assert_eq!(content.len() as u64, original_size);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(content).unwrap();
        file.flush().unwrap();
        unsafe {
            windows::Win32::Storage::FileSystem::SetFileTime(
                handle,
                None,
                None,
                Some(&before.ftLastWriteTime),
            )
        }
        .unwrap();
        unsafe { FlushFileBuffers(handle) }.unwrap();
    }

    #[test]
    fn up_to_date_hook_refuses_symlink_reparse_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("hook.cmd"), "expected").unwrap();
        if !symlink_directory_or_explicitly_skip(outside.path(), &root.path().join("hooks")) {
            return;
        }
        let result = write_hook_script(
            &root.path().join("hooks/hook.cmd"),
            root.path(),
            "expected",
            false,
            true,
        );
        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(outside.path().join("hook.cmd")).unwrap(),
            "expected"
        );
    }

    /// Create an NTFS junction (mount point) natively. `cmd.exe /c mklink /J`
    /// rejects the runner's paths outright, so coverage builds the reparse
    /// point through the same kernel interface Windows itself uses:
    /// `FSCTL_SET_REPARSE_POINT` with a `MountPointReparseBuffer` payload.
    /// Junctions, unlike symlinks, require no privilege.
    fn create_junction(link: &Path, target: &Path) -> Result<(), String> {
        use windows::Win32::System::Ioctl::FSCTL_SET_REPARSE_POINT;
        use windows::Win32::System::IO::DeviceIoControl;

        std::fs::create_dir(link).map_err(|error| format!("create junction dir: {error}"))?;
        let link_wide = wide(link);
        let handle = unsafe {
            CreateFileW(
                PCWSTR(link_wide.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .map_err(|error| format!("open junction dir: {error}"))?;
        let dir = OwnedHandle(handle).into_file();

        let rendered = target.display().to_string();
        let plain = rendered
            .strip_prefix(r"\\?\")
            .unwrap_or(rendered.as_str())
            .to_string();
        let substitute: Vec<u16> = format!(r"\??\{plain}").encode_utf16().collect();
        let print: Vec<u16> = plain.encode_utf16().collect();

        // REPARSE_DATA_BUFFER: tag u32, data-length u16, reserved u16, then the
        // MountPointReparseBuffer (four u16 offsets/lengths + path buffer with
        // NUL-terminated substitute and print names).
        let sub_bytes = substitute.len() * 2;
        let print_bytes = print.len() * 2;
        let reparse_data_length = 8 + sub_bytes + 2 + print_bytes + 2;
        let mut buffer = vec![0u8; 8 + reparse_data_length];
        buffer[0..4].copy_from_slice(&0xA000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
        buffer[4..6].copy_from_slice(&(reparse_data_length as u16).to_le_bytes());
        buffer[8..10].copy_from_slice(&0u16.to_le_bytes());
        buffer[10..12].copy_from_slice(&(sub_bytes as u16).to_le_bytes());
        buffer[12..14].copy_from_slice(&((sub_bytes + 2) as u16).to_le_bytes());
        buffer[14..16].copy_from_slice(&(print_bytes as u16).to_le_bytes());
        let mut cursor = 16;
        for unit in substitute
            .iter()
            .chain(std::iter::once(&0u16))
            .chain(print.iter())
            .chain(std::iter::once(&0u16))
        {
            buffer[cursor..cursor + 2].copy_from_slice(&unit.to_le_bytes());
            cursor += 2;
        }
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                HANDLE(dir.as_raw_handle()),
                FSCTL_SET_REPARSE_POINT,
                Some(buffer.as_ptr().cast()),
                buffer.len() as u32,
                None,
                0,
                Some(&mut returned),
                None,
            )
        }
        .map_err(|error| format!("set reparse point: {error}"))
    }

    #[test]
    fn junction_parent_swap_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let junction = root.path().join("junction");
        create_junction(&junction, outside.path())
            .unwrap_or_else(|error| panic!("junction coverage setup failed: {error}"));
        let path = junction.join("config.json");
        assert!(update_with_backup(&path, root.path(), "new").is_err());
        assert!(!outside.path().join("config.json").exists());
    }

    #[test]
    fn held_parent_handles_block_concurrent_parent_swap() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("configs");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("config.json");
        fs::write(&path, "before").unwrap();
        let moved = root.path().join("moved-configs");
        let mut swap_was_blocked = false;
        transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    swap_was_blocked = fs::rename(&parent, &moved).is_err();
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(swap_was_blocked);
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
        assert!(!moved.exists());
    }

    #[test]
    fn same_second_backups_are_unique_and_handle_bound_retention_keeps_five() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        update_with_backup(&path, root.path(), "one").unwrap();
        update_with_backup(&path, root.path(), "two").unwrap();
        assert_eq!(backup_paths(root.path()).len(), 2);
        for index in 0..6 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }
        let retained = backup_paths(root.path());
        assert_eq!(retained.len(), 5);
        assert!(retained
            .iter()
            .any(|backup| fs::read_to_string(backup).unwrap() == "value-4"));
    }

    #[test]
    fn backup_full_generation_is_revalidated_before_commit_announcement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let lock = PlatformTransaction::lock(&path, root.path()).unwrap();
        let transaction = PlatformTransaction::begin(&path, root.path(), lock).unwrap();
        let snapshot = transaction.read_snapshot().unwrap();
        let mut backup = transaction.create_backup(&snapshot).unwrap();
        let capability = backup.cleanup.as_mut().unwrap();
        capability.file.seek(SeekFrom::Start(0)).unwrap();
        capability.file.write_all(b"tamper").unwrap();
        unsafe { FlushFileBuffers(HANDLE(capability.file.as_raw_handle())) }.unwrap();

        let error = backup.commit().unwrap_err();
        assert!(error.contains("commit/announcement"));
    }

    #[test]
    fn old_backup_cleanup_handle_blocks_swap_before_deletion() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        for index in 0..5 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }
        let swap_was_blocked = Arc::new(AtomicBool::new(false));
        let observed = swap_was_blocked.clone();
        let moved = root.path().join("attacker-moved-old-backup");
        with_cleanup_hook(
            move |old| {
                if fs::rename(old, &moved).is_err() {
                    observed.store(true, Ordering::SeqCst);
                }
            },
            || update_with_backup(&path, root.path(), "updated").unwrap(),
        );

        assert!(swap_was_blocked.load(Ordering::SeqCst));
        assert!(!root.path().join("attacker-moved-old-backup").exists());
        assert_eq!(backup_paths(root.path()).len(), 5);
    }

    #[test]
    fn creation_handles_close_the_temp_and_backup_reopen_race() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let blocked = Arc::new(AtomicUsize::new(0));
        let observed = blocked.clone();
        let moved_root = root.path().to_path_buf();
        with_artifact_capture_hook(
            move |artifact| {
                let moved =
                    moved_root.join(format!("attacker-swap-{}", uuid::Uuid::new_v4().simple()));
                if fs::rename(artifact, moved).is_err() {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
            },
            || update_with_backup(&path, root.path(), "after").unwrap(),
        );

        assert_eq!(blocked.load(Ordering::SeqCst), 3);
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
    }

    #[test]
    fn precreated_regular_and_reparse_backup_names_are_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let regular = root
            .path()
            .join("config.json.tirith-backup-99999999-999999-attacker");
        fs::write(&regular, "attacker-regular").unwrap();
        let target = root.path().join("outside-secret");
        fs::write(&target, "attacker-target").unwrap();
        let link = root
            .path()
            .join("config.json.tirith-backup-99999999-999999-reparse");
        if !symlink_file_or_explicitly_skip(&target, &link) {
            return;
        }
        update_with_backup(&path, root.path(), "updated").unwrap();
        assert_eq!(fs::read_to_string(regular).unwrap(), "attacker-regular");
        assert_eq!(fs::read_to_string(target).unwrap(), "attacker-target");
    }

    #[test]
    fn retention_does_not_delete_unproven_backup_prefix_lookalikes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        let forged = root.path().join(format!(
            "{BACKUP_MARKER}{}-20260101-000000-000000000_{}_{}",
            destination_tag(&path),
            "0".repeat(64),
            "a".repeat(32)
        ));
        fs::write(&forged, "attacker-lookalike").unwrap();
        for index in 0..8 {
            update_with_backup(&path, root.path(), &format!("value-{index}")).unwrap();
        }
        assert_eq!(fs::read_to_string(forged).unwrap(), "attacker-lookalike");
        assert_eq!(backup_paths(root.path()).len(), 6);
    }

    #[test]
    fn displaced_recovery_retention_is_provenance_bound_and_capped_at_five() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "zero").unwrap();
        let forged = root.path().join(format!(
            "{DISPLACED_MARKER}{}-20260101-000000-000000000_{}_{}",
            destination_tag(&path),
            "0".repeat(64),
            "b".repeat(32)
        ));
        fs::write(&forged, "attacker-recovery-lookalike").unwrap();

        for index in 0..8 {
            let outcome = transactional_update(&path, root.path(), false, |_| {
                Ok(FileUpdate::write_text(format!("value-{index}"), 0o600))
            })
            .unwrap();
            assert_eq!(outcome, TransactionOutcome::WrittenWithRecovery);
        }

        assert_eq!(
            fs::read_to_string(&forged).unwrap(),
            "attacker-recovery-lookalike"
        );
        let recoveries = displaced_paths(root.path());
        assert_eq!(recoveries.len(), 6);
        assert!(recoveries
            .iter()
            .any(|recovery| fs::read_to_string(recovery).unwrap() == "value-6"));
    }

    #[test]
    fn non_cooperating_generation_change_is_rejected_and_temp_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    fs::write(&path, "editor-change").unwrap();
                }
                Ok(())
            },
        );
        let error = result.unwrap_err();
        assert!(error.contains("changed"), "unexpected refusal: {error}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "editor-change");
        assert!(!fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tirith-setup-")
                    && entry.path() != path
            }));
    }

    #[test]
    fn prepared_temp_handle_blocks_name_swap_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let mut deletion_was_blocked = false;
        transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let temp = fs::read_dir(root.path())
                        .unwrap()
                        .filter_map(Result::ok)
                        .find(|entry| {
                            let name = entry.file_name();
                            let name = name.to_string_lossy();
                            name.starts_with(".tirith-setup-") && name.ends_with(".tmp")
                        })
                        .unwrap()
                        .path();
                    deletion_was_blocked = fs::remove_file(temp).is_err();
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(deletion_was_blocked);
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
    }

    #[test]
    fn prepared_backup_handle_blocks_cleanup_name_swap() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let mut swap_was_blocked = false;
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let backup = backup_paths(root.path()).pop().unwrap();
                    swap_was_blocked =
                        fs::rename(&backup, root.path().join("swapped-backup")).is_err();
                    return Err("injected failure after backup race".into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("injected failure"));
        assert!(swap_was_blocked);
        assert!(backup_paths(root.path()).is_empty());
        assert_eq!(fs::read_to_string(path).unwrap(), "before");
    }

    #[test]
    fn prepared_backup_never_grants_write_sharing() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let mut write_was_blocked = false;
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    let backup = backup_paths(root.path()).pop().unwrap();
                    write_was_blocked = fs::OpenOptions::new().write(true).open(backup).is_err();
                    return Err("stop after write-sharing proof".into());
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.contains("write-sharing proof"));
        assert!(write_was_blocked);
    }

    #[test]
    fn destination_swap_after_validation_is_detected_and_competitor_is_restored() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let original_hold = root.path().join("original-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap().unwrap();
        let mut competitor_generation = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    fs::rename(&path, &original_hold).unwrap();
                    fs::write(&path, "competing-writer").unwrap();
                    competitor_generation = generation_at(&path).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "competing-writer");
        assert_eq!(generation_at(&path).unwrap(), competitor_generation);
        assert_eq!(fs::read_to_string(&original_hold).unwrap(), "original");
        assert_eq!(
            generation_at(&original_hold).unwrap(),
            Some(original_generation)
        );
        assert!(temporary_setup_paths(root.path()).is_empty());
        assert!(displaced_paths(root.path()).is_empty());
    }

    #[test]
    fn temp_swap_after_validation_never_publishes_attacker_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let held_prepared = root.path().join("prepared-held-by-writer");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap().unwrap();
        let mut attacker_path = None;
        let mut attacker_generation = None;
        let mut prepared_generation = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    let temp = temporary_setup_paths(root.path()).pop().unwrap();
                    prepared_generation = generation_at(&temp).unwrap();
                    fs::rename(&temp, &held_prepared).unwrap();
                    fs::write(&temp, "attacker-temp").unwrap();
                    attacker_generation = generation_at(&temp).unwrap();
                    attacker_path = Some(temp);
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(generation_at(&path).unwrap(), Some(original_generation));
        let attacker_path = attacker_path.unwrap();
        assert_eq!(fs::read_to_string(&attacker_path).unwrap(), "attacker-temp");
        // The aborted publication briefly installed the attacker's file at the
        // destination, where ReplaceFileW rewrote that file's own security
        // descriptor (the merge behavior the restore path exists to undo for
        // OUR files). Retention promises the attacker's exact identity and
        // bytes were kept out of the destination — not that the attacker's
        // descriptor survived the attempt unchanged.
        let mut retained = generation_at(&attacker_path).unwrap().unwrap();
        let mut expected = attacker_generation.unwrap();
        retained.security_descriptor.clear();
        expected.security_descriptor.clear();
        assert_eq!(retained, expected);
        assert_eq!(fs::read_to_string(&held_prepared).unwrap(), "tirith-update");
        assert_eq!(generation_at(&held_prepared).unwrap(), prepared_generation);
    }

    #[test]
    fn same_length_destination_change_with_restored_timestamp_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original-state").unwrap();

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update!".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    overwrite_same_length_and_restore_last_write(&path, b"attacker-state");
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(path).unwrap(), "attacker-state");
    }

    #[test]
    fn same_length_temp_change_with_restored_timestamp_is_never_accepted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let mut mutated_temp = None;

        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("tirith-update".into(), 0o644)),
            |stage| {
                if stage == TestStage::PublicationReady {
                    let temp = temporary_setup_paths(root.path()).pop().unwrap();
                    overwrite_same_length_and_restore_last_write(&temp, b"attack-update");
                    mutated_temp = Some(temp);
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("restored the competing destination"));
        assert_eq!(fs::read_to_string(path).unwrap(), "original");
        assert_eq!(
            fs::read_to_string(mutated_temp.unwrap()).unwrap(),
            "attack-update"
        );
    }

    #[test]
    fn unable_to_move_replacement_is_verified_as_clean_failure() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap().unwrap();

        let error = with_replace_hook(
            |_destination, _replacement, _displaced| Err(ERROR_UNABLE_TO_MOVE_REPLACEMENT.0),
            || {
                transactional_update(&path, root.path(), false, |_| {
                    Ok(FileUpdate::write_text("tirith-update".into(), 0o644))
                })
                .unwrap_err()
            },
        );

        assert!(error.contains("before moving either identity"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        assert_eq!(generation_at(&path).unwrap(), Some(original_generation));
        assert!(temporary_setup_paths(root.path()).is_empty());
        assert!(displaced_paths(root.path()).is_empty());
        assert!(backup_paths(root.path()).is_empty());
    }

    #[test]
    fn unable_to_move_replacement_2_retains_exact_identity_recovery() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "original").unwrap();
        let original_generation = generation_at(&path).unwrap().unwrap();

        let error = with_replace_hook(
            |destination, _replacement, displaced| {
                fs::rename(destination, displaced).unwrap();
                Err(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2.0)
            },
            || {
                transactional_update(&path, root.path(), false, |_| {
                    Ok(FileUpdate::write_text("tirith-update".into(), 0o644))
                })
                .unwrap_err()
            },
        );

        assert!(error.contains("partial Windows failure state"));
        assert!(!path.exists());
        let displaced = displaced_paths(root.path());
        assert_eq!(displaced.len(), 1);
        assert_eq!(fs::read_to_string(&displaced[0]).unwrap(), "original");
        assert_eq!(
            generation_at(&displaced[0]).unwrap(),
            Some(original_generation)
        );
        let prepared = temporary_setup_paths(root.path());
        assert_eq!(prepared.len(), 1);
        assert_eq!(fs::read_to_string(&prepared[0]).unwrap(), "tirith-update");
        let recovery = backup_paths(root.path());
        assert_eq!(recovery.len(), 1);
        assert_eq!(fs::read_to_string(&recovery[0]).unwrap(), "original");
    }

    #[test]
    fn publication_failure_rolls_back_only_its_backup_and_temp() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("ours".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::SnapshotValidated {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(backup_paths(root.path()).is_empty());
        assert!(!fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".tirith-setup-")
            }));
    }

    #[test]
    fn exact_handle_cleanup_failure_is_propagated_with_primary_error() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        DELETE_FAILURE_TEST_HOOK.with(|slot| slot.set(true));
        let result = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::TempSynced {
                    return Err("injected pre-publication failure".into());
                }
                Ok(())
            },
        );
        DELETE_FAILURE_TEST_HOOK.with(|slot| slot.set(false));

        let error = result.unwrap_err();
        assert!(error.contains("injected pre-publication failure"));
        assert!(error.contains("cleanup also failed"));
        assert_eq!(fs::read_to_string(path).unwrap(), "before");
    }

    #[test]
    fn post_publication_failure_retains_exact_original_recovery() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644).with_backup(true)),
            |stage| {
                if stage == TestStage::Published {
                    return Err("injected installed-file durability failure".into());
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("durability"));
        assert!(error.contains("exact displaced original"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "after");
        let displaced = displaced_paths(root.path());
        assert_eq!(displaced.len(), 1);
        assert_eq!(fs::read_to_string(&displaced[0]).unwrap(), "before");
        assert_eq!(backup_paths(root.path()).len(), 2);
    }

    #[test]
    fn held_installed_identity_blocks_name_swap_through_completion() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        let moved = root.path().join("writer-moved-install");
        fs::write(&path, "before").unwrap();
        let mut swap_was_blocked = false;
        transactional_update_with_hook(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("after".into(), 0o644)),
            |stage| {
                if stage == TestStage::Published {
                    swap_was_blocked = fs::rename(&path, &moved).is_err();
                }
                Ok(())
            },
        )
        .unwrap();

        assert!(swap_was_blocked);
        assert_eq!(fs::read_to_string(path).unwrap(), "after");
        assert!(!moved.exists());
    }

    fn wait_for_marker(path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for subprocess marker {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn subprocess_lock_child() {
        let Some(role) = std::env::var_os("TIRITH_SETUP_LOCK_CHILD_ROLE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("TIRITH_SETUP_LOCK_ROOT").unwrap());
        let path = root.join("config.txt");
        match role.to_string_lossy().as_ref() {
            "holder" => {
                let entered = root.join("holder-entered");
                let release = root.join("release-holder");
                transactional_update_with_hook(
                    &path,
                    &root,
                    |snapshot| {
                        let mut content = snapshot.text(&path)?.unwrap().to_string();
                        content.push_str("-holder");
                        Ok(FileUpdate::write_text(content, 0o644))
                    },
                    |stage| {
                        if stage == TestStage::TempSynced {
                            fs::write(&entered, b"locked").unwrap();
                            wait_for_marker(&release);
                        }
                        Ok(())
                    },
                )
                .unwrap();
            }
            "contender" => {
                assert!(PlatformTransaction::lock_is_contended(&path, &root).unwrap());
                fs::write(root.join("contender-observed-lock"), b"contended").unwrap();
                transactional_update(&path, &root, false, |snapshot| {
                    let mut content = snapshot.text(&path)?.unwrap().to_string();
                    content.push_str("-contender");
                    Ok(FileUpdate::write_text(content, 0o644))
                })
                .unwrap();
            }
            other => panic!("unknown setup lock child role {other}"),
        }
    }

    #[test]
    fn cooperative_transactions_overlap_in_distinct_processes_and_recompute() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.txt");
        fs::write(&path, "base").unwrap();
        let test_binary = std::env::current_exe().unwrap();
        let test_name = "cli::setup::fs_helpers::tests::subprocess_lock_child";

        let mut holder = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "holder")
            .env("TIRITH_SETUP_LOCK_ROOT", root.path())
            .spawn()
            .unwrap();
        wait_for_marker(&root.path().join("holder-entered"));

        let mut contender = std::process::Command::new(&test_binary)
            .args(["--exact", test_name, "--nocapture"])
            .env("TIRITH_SETUP_LOCK_CHILD_ROLE", "contender")
            .env("TIRITH_SETUP_LOCK_ROOT", root.path())
            .spawn()
            .unwrap();
        wait_for_marker(&root.path().join("contender-observed-lock"));
        assert!(holder.try_wait().unwrap().is_none());
        assert!(contender.try_wait().unwrap().is_none());

        fs::write(root.path().join("release-holder"), b"release").unwrap();
        assert!(holder.wait().unwrap().success());
        assert!(contender.wait().unwrap().success());
        let content = fs::read_to_string(path).unwrap();
        assert!(content.contains("-holder") && content.contains("-contender"));
    }

    #[test]
    fn cooperative_transactions_serialize_and_recompute() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.txt");
        fs::write(&path, "base").unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for suffix in ["-one", "-two"] {
            let path = path.clone();
            let root = root.path().to_path_buf();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                transactional_update(&path, &root, false, |snapshot| {
                    let mut content = snapshot.text(&path)?.unwrap().to_string();
                    content.push_str(suffix);
                    Ok(FileUpdate::write_text(content, 0o644))
                })
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let result = fs::read_to_string(path).unwrap();
        assert!(result.contains("-one") && result.contains("-two"));
    }

    #[test]
    fn oversized_snapshot_is_rejected_at_cap_plus_one() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("huge.json");
        fs::write(
            &path,
            vec![b'x'; super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1],
        )
        .unwrap();
        assert!(read_to_string_scoped(&path, root.path()).is_err());
    }

    #[test]
    fn transformed_payload_cap_is_enforced_before_parent_creation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("missing").join("too-large.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap_err();
        assert!(error.contains("setup file limit"));
        assert!(!root.path().join("missing").exists());
    }

    #[test]
    fn drifted_transform_is_recomputed_and_capped_before_artifacts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "base").unwrap();
        let oversized = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES + 1);
        let error = transactional_update_with_hook(
            &path,
            root.path(),
            |snapshot| {
                if snapshot.text(&path)? == Some("base") {
                    Ok(FileUpdate::write_text("small".into(), 0o600).with_backup(true))
                } else {
                    Ok(FileUpdate::write_text(oversized.clone(), 0o600).with_backup(true))
                }
            },
            |stage| {
                if stage == TestStage::PreflightReady {
                    fs::write(&path, "drift").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();

        assert!(error.contains("setup file limit"));
        assert_eq!(fs::read_to_string(path).unwrap(), "drift");
        assert!(backup_paths(root.path()).is_empty());
        assert!(temporary_setup_paths(root.path()).is_empty());
        assert!(displaced_paths(root.path()).is_empty());
    }

    #[test]
    fn transformed_payload_exact_cap_is_accepted() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("exact-cap.json");
        let payload = "x".repeat(super::super::fs_transaction::MAX_SETUP_FILE_BYTES);
        transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text(payload.clone(), 0o600))
        })
        .unwrap();
        assert_eq!(fs::metadata(path).unwrap().len(), payload.len() as u64);
    }

    #[test]
    fn replace_file_preserves_original_dacl_descriptor() {
        use windows::Win32::Security::SE_DACL_PROTECTED;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        let before_handle = open_existing(&path).unwrap().unwrap();
        let mut before = security_descriptor(before_handle.0, &path).unwrap();
        assert_eq!(
            descriptor_control(&mut before) & SE_DACL_PROTECTED.0,
            0,
            "fixture must exercise an inheriting DACL"
        );
        drop(before_handle);
        transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text("after".into(), 0o644))
        })
        .unwrap();
        let after_handle = open_existing(&path).unwrap().unwrap();
        let after = security_descriptor(after_handle.0, &path).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn replace_file_preserves_protected_dacl_descriptor() {
        use windows::Win32::Security::SE_DACL_PROTECTED;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        create_protected_owner_only_file(&path, b"before");
        let before_handle = open_existing(&path).unwrap().unwrap();
        let mut before = security_descriptor(before_handle.0, &path).unwrap();
        assert_ne!(
            descriptor_control(&mut before) & SE_DACL_PROTECTED.0,
            0,
            "fixture must exercise a protected DACL"
        );
        drop(before_handle);
        transactional_update(&path, root.path(), false, |_| {
            Ok(FileUpdate::write_text("after".into(), 0o644))
        })
        .unwrap();
        let after_handle = open_existing(&path).unwrap().unwrap();
        let after = security_descriptor(after_handle.0, &path).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn backup_dacl_is_protected_and_owner_only() {
        use windows::Win32::Security::{
            AclSizeInformation, GetAclInformation, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, ACL, ACL_SIZE_INFORMATION, SE_DACL_PROTECTED,
        };

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config.json");
        fs::write(&path, "before").unwrap();
        update_with_backup(&path, root.path(), "after").unwrap();
        let backup = backup_paths(root.path()).pop().unwrap();
        let handle = open_existing(&backup).unwrap().unwrap();
        let mut descriptor = security_descriptor(handle.0, &backup).unwrap();
        let descriptor = PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr().cast());
        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.unwrap();
        assert_ne!(control & SE_DACL_PROTECTED.0, 0);
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            .unwrap();
        assert!(present.as_bool() && !dacl.is_null());
        let mut size = ACL_SIZE_INFORMATION::default();
        unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .unwrap();
        assert_eq!(size.AceCount, 1);
    }

    fn cmd() -> tirith_core::trusted_child::TrustedExecutable {
        let root = std::env::var_os("SystemRoot").expect("SystemRoot");
        tirith_core::trusted_child::TrustedExecutable::from_absolute(
            &PathBuf::from(root).join("System32").join("cmd.exe"),
            &[],
        )
        .expect("trusted system cmd.exe")
    }

    #[test]
    fn windows_setup_runner_preserves_short_legitimate_output() {
        // Room to spare on both streams: this case proves legitimate output
        // survives the supervisor, and any host-dependent extra bytes surface
        // in the assertion below instead of as an opaque limit refusal. The
        // limit path itself is covered by the next test.
        let output = run_cli_bounded(
            &cmd(),
            &["/D", "/S", "/C", "<nul set /p =setup-ok"],
            tirith_core::trusted_child::ChildLimits::new(
                std::time::Duration::from_secs(5),
                4096,
                4096,
            ),
        )
        .unwrap();
        // `set /p` reports errorlevel 1 when its input reaches EOF, which the
        // `<nul` redirect guarantees, so the exit code carries no signal here.
        // What this case proves is that the supervisor hands back the child's
        // exact bytes.
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "setup-ok",
            "status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn windows_setup_runner_surfaces_output_limit() {
        let error = run_cli_bounded(
            &cmd(),
            &["/D", "/S", "/C", "<nul set /p =12345"],
            tirith_core::trusted_child::ChildLimits::new(std::time::Duration::from_secs(5), 4, 64),
        )
        .unwrap_err();
        assert!(error.contains("output limit"));
    }

    #[test]
    fn codex_scope_uses_cli_cd_without_mutating_child_cwd() {
        let cwd = Path::new(r"C:\Users\operator\codex-scope");
        let args = codex_scoped_args(cwd, &["mcp", "list", "--json"]);
        assert_eq!(args[0], OsString::from("-C"));
        assert_eq!(args[1], cwd.as_os_str());
        assert_eq!(args[2..], ["mcp", "list", "--json"].map(OsString::from));
    }
}
