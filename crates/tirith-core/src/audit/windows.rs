//! Native private audit files. Creation publishes the current-user owner and
//! protected DACL atomically. Existing files keep their identity and are only
//! hardened after their owner and regular single-link type are proved on the
//! same retained handle. Read/write sharing remains compatible with old writers.
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFileType, BY_HANDLE_FILE_INFORMATION, CREATE_NEW,
    FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};

pub(super) fn open_log(path: &Path) -> io::Result<File> {
    match open_file(path, true, true) {
        Ok(file) => Ok(file),
        Err(error)
            if error.raw_os_error().is_some_and(|code| {
                code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
            }) =>
        {
            open_file(path, false, true)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn create_head(path: &Path) -> io::Result<File> {
    open_file(path, true, false)
}

fn open_file(path: &Path, create_new: bool, append: bool) -> io::Result<File> {
    let mut encoded: Vec<u16> = path.as_os_str().encode_wide().collect();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit path contains NUL",
        ));
    }
    encoded.push(0);
    let mut security = OwnerOnlySecurity::new()?;
    let attributes = security.security_attributes();
    // FILE_APPEND_DATA without FILE_WRITE_DATA makes each write append even
    // after bounded tail/head reads reposition this handle. GENERIC_READ also
    // permits LockFileEx; the old writer holds that same inode lock.
    let write = if append {
        FILE_APPEND_DATA
    } else {
        FILE_GENERIC_WRITE
    };
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            FILE_GENERIC_READ | write | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if create_new {
                &attributes
            } else {
                std::ptr::null()
            },
            if create_new {
                CREATE_NEW
            } else {
                OPEN_EXISTING
            },
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    validate_regular_single_link(&file)?;
    // A no-op open must not rewrite the DACL/generation of an already-private
    // log. Retention plans and held append-failure probes bind that generation.
    if !create_new && verify_private(&file).is_err() {
        harden_owned_file(&file, &security)?;
    }
    verify_private(&file)?;
    Ok(file)
}

fn validate_regular_single_link(file: &File) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit file must be a regular single-link non-reparse file",
        ));
    }
    Ok(())
}

fn harden_owned_file(file: &File, security: &OwnerOnlySecurity) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{
        GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    let _descriptor = LocalSecurityDescriptor(descriptor);
    if !owner_matches(owner, security._user.sid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit file is not owned by the current user",
        ));
    }
    // No OWNER_SECURITY_INFORMATION: this is an authorized privacy tightening
    // of this operator's existing audit file, never a foreign-owner takeover.
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            security.acl(),
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}

fn owner_matches(
    owner: windows_sys::Win32::Security::PSID,
    current_user: windows_sys::Win32::Security::PSID,
) -> bool {
    use windows_sys::Win32::Security::{EqualSid, IsValidSid};
    !owner.is_null()
        && unsafe { IsValidSid(owner) } != 0
        && unsafe { EqualSid(owner, current_user) } != 0
}

struct TokenHandle(windows_sys::Win32::Foundation::HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

struct CurrentUserSid {
    _storage: Vec<usize>,
    sid: windows_sys::Win32::Security::PSID,
}

impl CurrentUserSid {
    fn load() -> std::io::Result<Self> {
        use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE};
        use windows_sys::Win32::Security::{
            GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut raw_token: HANDLE = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = TokenHandle(raw_token);
        let mut needed = 0u32;
        if unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed) }
            != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "TokenUser size query unexpectedly succeeded",
            ));
        }
        let size_error = std::io::Error::last_os_error();
        if size_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || needed == 0 {
            return Err(size_error);
        }
        let word_size = std::mem::size_of::<usize>();
        let mut storage = vec![0usize; (needed as usize).div_ceil(word_size)];
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let token_user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
        if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "current process token contains an invalid user SID",
            ));
        }
        Ok(Self {
            sid: token_user.User.Sid,
            _storage: storage,
        })
    }
}

struct OwnerOnlySecurity {
    _user: CurrentUserSid,
    acl: Vec<usize>,
    descriptor: windows_sys::Win32::Security::SECURITY_DESCRIPTOR,
}

impl OwnerOnlySecurity {
    fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::Security::{
            AddAccessAllowedAceEx, GetLengthSid, InitializeAcl, InitializeSecurityDescriptor,
            SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
            ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        };
        use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

        let user = CurrentUserSid::load()?;
        let sid_size = unsafe { GetLengthSid(user.sid) } as usize;
        if sid_size == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let acl_bytes = std::mem::size_of::<ACL>()
            .checked_add(std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>())
            .and_then(|size| size.checked_add(sid_size))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Windows ACL size overflow")
            })?;
        let word_size = std::mem::size_of::<usize>();
        let mut acl = vec![0usize; acl_bytes.div_ceil(word_size)];
        let acl_ptr = acl.as_mut_ptr().cast::<ACL>();
        if unsafe { InitializeAcl(acl_ptr, acl_bytes as u32, ACL_REVISION) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { AddAccessAllowedAceEx(acl_ptr, ACL_REVISION, 0, FILE_ALL_ACCESS, user.sid) }
            == 0
        {
            return Err(std::io::Error::last_os_error());
        }

        let mut descriptor = SECURITY_DESCRIPTOR::default();
        if unsafe {
            InitializeSecurityDescriptor(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            SetSecurityDescriptorOwner(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                user.sid,
                0,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            SetSecurityDescriptorDacl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                1,
                acl_ptr,
                0,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe {
            SetSecurityDescriptorControl(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            _user: user,
            acl,
            descriptor,
        })
    }

    fn security_attributes(&mut self) -> windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: (&mut self.descriptor
                as *mut windows_sys::Win32::Security::SECURITY_DESCRIPTOR)
                .cast(),
            bInheritHandle: 0,
        }
    }

    fn acl(&self) -> *const windows_sys::Win32::Security::ACL {
        self.acl.as_ptr().cast()
    }
}

struct LocalSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0.cast());
        }
    }
}

fn verify_private(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        IsValidSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    let current_user = CurrentUserSid::load()?;
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows object has no security descriptor",
        ));
    }
    let _owned_descriptor = LocalSecurityDescriptor(descriptor);

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if !owner_matches(owner, current_user.sid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows audit object is not owned by the current user",
        ));
    }

    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows audit DACL is not protected from inheritance",
        ));
    }

    let mut dacl_present = 0;
    let mut dacl_defaulted = 0;
    let mut dacl = std::ptr::null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if dacl_present == 0 || dacl.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows audit object has an absent or null DACL",
        ));
    }
    let mut acl_info = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if acl_info.AceCount != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows audit DACL is not owner-only",
        ));
    }
    let mut raw_ace = std::ptr::null_mut();
    if unsafe { GetAce(dacl, 0, &mut raw_ace) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows audit DACL contains a truncated access entry",
        ));
    }
    let expected_sid_size = unsafe { GetLengthSid(current_user.sid) } as usize;
    let required_ace_size = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)
        .checked_add(expected_sid_size)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Windows ACE size overflow")
        })?;
    if (header.AceSize as usize) < required_ace_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows audit DACL contains a truncated owner SID",
        ));
    }
    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
    if ace.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
        || ace.Header.AceFlags & INHERITED_ACE as u8 != 0
        || ace.Mask != FILE_ALL_ACCESS
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows audit DACL contains an unexpected access entry",
        ));
    }
    let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
    if unsafe { IsValidSid(ace_sid) } == 0 || unsafe { EqualSid(ace_sid, current_user.sid) } == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows audit DACL grants a principal other than its owner",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn audit_log_creation_is_private_and_appends_after_reads() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("audit.jsonl");
        let mut log = open_log(&path).unwrap();
        verify_private(&log).unwrap();
        log.write_all(b"first\n").unwrap();
        log.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = [0; 2];
        log.read_exact(&mut bytes).unwrap();
        log.write_all(b"second\n").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
        // Old read/write opens and filesystem locking remain compatible.
        let old_writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        fs2::FileExt::lock_exclusive(&old_writer).unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&log).is_err());
        fs2::FileExt::unlock(&old_writer).unwrap();
        drop(log);
        verify_private(&open_log(&path).unwrap()).unwrap();
    }

    #[test]
    fn legacy_current_user_owned_log_is_hardened_without_replacing_its_identity() {
        use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION,
        };
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("audit.jsonl");
        let mut original = open_log(&path).unwrap();
        original.write_all(b"existing\n").unwrap();
        // Model an old broad DACL on an explicitly current-user-owned fixture.
        // No foreign owner is accepted or silently changed by the repair.
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    original.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        assert!(verify_private(&original).is_err());
        let mut repaired = open_log(&path).unwrap();
        verify_private(&original).unwrap();
        repaired.write_all(b"later\n").unwrap();
        original.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        original.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"existing\nlater\n");
    }

    #[test]
    fn native_writer_keeps_signed_head_and_log_private_and_verifiable() {
        let mut environment = tirith_test_support::GlobalStateGuard::new().unwrap();
        environment.set_env("TIRITH_LOG", "1");
        let directory = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&directory).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
        create_head(&directory.join("audit-signing.key"))
            .unwrap()
            .write_all(&key.to_bytes())
            .unwrap();
        std::fs::write(
            directory.join("audit-signing.pub"),
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        crate::audit::log_hook_event("test", "windows-private", "first", None, None);
        crate::audit::log_hook_event("test", "windows-private", "second", None, None);
        let path = crate::audit::audit_log_path().unwrap();
        verify_private(&File::open(&path).unwrap()).unwrap();
        verify_private(&File::open(super::super::head_path(&path)).unwrap()).unwrap();
        let result = crate::audit::verify_audit_log(&path, None);
        assert!(result.ok, "{:?}", result.problems);
        assert_eq!(result.signed_lines, 2);
        assert!(result.signing_expected);
    }

    #[test]
    fn foreign_owner_is_rejected_without_taking_ownership_or_changing_bytes() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER, ERROR_PRIVILEGE_NOT_HELD,
        };
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, SetSecurityDescriptorOwner, WinBuiltinAdministratorsSid,
            SECURITY_DESCRIPTOR,
        };
        let mut security = OwnerOnlySecurity::new().unwrap();
        let mut foreign_storage = [0usize; 16];
        let foreign = foreign_storage.as_mut_ptr().cast();
        let mut size = std::mem::size_of_val(&foreign_storage) as u32;
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    WinBuiltinAdministratorsSid,
                    std::ptr::null_mut(),
                    foreign,
                    &mut size,
                )
            },
            0
        );
        // These assertions always run, including standard-user native hosts
        // whose tokens cannot assign an administrator-group file owner.
        assert!(owner_matches(security._user.sid, security._user.sid));
        assert!(!owner_matches(foreign, security._user.sid));
        assert!(!owner_matches(std::ptr::null_mut(), security._user.sid));
        assert_ne!(
            unsafe {
                SetSecurityDescriptorOwner(
                    (&mut security.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    foreign,
                    0,
                )
            },
            0
        );
        let attributes = security.security_attributes();
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("foreign-owned.jsonl");
        let encoded: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // This only uses rights already present in the process token. Never
        // enable privileges or modify a real user's object to construct a test.
        let handle = unsafe {
            CreateFileW(
                encoded.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            assert!(
                matches!(error.raw_os_error(), Some(code) if
                code == ERROR_INVALID_OWNER as i32 || code == ERROR_PRIVILEGE_NOT_HELD as i32
                    || code == ERROR_ACCESS_DENIED as i32),
                "{error}"
            );
            eprintln!("native foreign-owner file fixture unavailable to this token; native SID rejection assertions passed");
            return;
        }
        let mut held = unsafe { File::from_raw_handle(handle) };
        held.write_all(b"foreign fixture unchanged\n").unwrap();
        assert!(verify_private(&held).is_err());
        let error = open_log(&path).unwrap_err();
        assert!(
            error.to_string().contains("not owned by the current user"),
            "{error}"
        );
        assert!(verify_private(&held).is_err(), "owner was silently changed");
        held.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        held.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"foreign fixture unchanged\n");
    }

    #[test]
    fn linked_existing_log_is_refused_without_changing_bytes_or_privacy() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("audit.jsonl");
        let mut log = open_log(&path).unwrap();
        log.write_all(b"original\n").unwrap();
        drop(log);
        std::fs::hard_link(&path, fixture.path().join("second-name")).unwrap();
        assert!(open_log(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"original\n");
    }

    #[test]
    fn signed_head_temporary_files_are_private_and_never_clobber_a_squatter() {
        let fixture = tempfile::tempdir().unwrap();
        let head = fixture.path().join("audit.jsonl.head");
        let squatter = fixture.path().join("audit.jsonl.head.tmp");
        std::fs::write(&squatter, b"untouched").unwrap();
        let (actual, file) = super::super::open_head_tmp(&head).unwrap();
        assert_ne!(actual, squatter);
        verify_private(&file).unwrap();
        assert_eq!(std::fs::read(&squatter).unwrap(), b"untouched");
    }
}
