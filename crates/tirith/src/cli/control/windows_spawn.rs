//! Fixed dashboard service spawn with an explicit Windows handle allowlist.
//!
//! Null standard streams alone do not exclude the launcher's other inheritable
//! handles (including captured output writers). Only the NUL handle below may
//! cross this spawn. Job inheritance and the existing detach flags are retained.

use std::ffi::OsStr;
use std::io;
use std::marker::PhantomData;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, HANDLE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
};

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only from a successful owning API
        // result, never from a borrowed, pseudo, or discovered handle.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub(super) struct ServiceChild {
    process: OwnedHandle,
}

impl ServiceChild {
    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        // The retained process handle cannot be redirected by PID reuse. Wait
        // before reading the code: 259 is also a legitimate completed exit code.
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                unsafe { GetExitCodeProcess(self.process.0, &mut code) }.map_err(win_error)?;
                Ok(Some(ExitStatus::from_raw(code)))
            }
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected service process wait result")),
        }
    }
}

fn win_error(error: windows::core::Error) -> io::Error {
    // The windows dependency disables its std feature; do not require its
    // optional std::error::Error implementation through feature unification.
    io::Error::other(error.to_string())
}

/// The caller retains and revalidates its executable and directory identities
/// around startup. This helper does not resolve another executable, use a shell,
/// switch working directory, or request a Job breakaway.
pub(super) fn spawn(exe: &Path, cwd: &Path, startup_id: &str) -> io::Result<ServiceChild> {
    let id = uuid::Uuid::parse_str(startup_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid service startup id"))?;
    if id.is_nil() || id.to_string() != startup_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "noncanonical service startup id",
        ));
    }
    spawn_arguments(
        exe,
        cwd,
        &[
            OsStr::new("dashboard"),
            OsStr::new("control-serve"),
            OsStr::new("--startup-id"),
            OsStr::new(startup_id),
        ],
    )
}

fn wide_nul(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "embedded NUL"));
    }
    wide.push(0);
    Ok(wide)
}

/// Quote native UTF-16 without a lossy UTF-8 round trip. Quotes are always
/// present; backslashes are doubled only before a quote or the closing quote.
fn quoted(value: &OsStr) -> io::Result<Vec<u16>> {
    let wide = wide_nul(value)?;
    let mut result = vec![b'"' as u16];
    let mut slashes = 0;
    for &unit in &wide[..wide.len() - 1] {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        result.extend(std::iter::repeat_n(b'\\' as u16, slashes));
        if unit == b'"' as u16 {
            result.extend(std::iter::repeat_n(b'\\' as u16, slashes + 1));
        }
        slashes = 0;
        result.push(unit);
    }
    result.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    result.push(b'"' as u16);
    Ok(result)
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct AttributeStorage([u8; 16]);

struct HandleList<'a> {
    // Match the native heap's 16-byte alignment; moving the Vec does not move
    // its allocation. The API retains the borrowed handle list
    // until CreateProcessW returns, so encode that lifetime as well.
    storage: Vec<AttributeStorage>,
    _handles: PhantomData<&'a [HANDLE]>,
}

impl<'a> HandleList<'a> {
    fn new(handles: &'a [HANDLE]) -> io::Result<Self> {
        let mut size = 0;
        // The sizing call deliberately fails with insufficient buffer.
        match unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) } {
            Err(error) if error.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
            _ => return Err(io::Error::other("cannot size service handle list")),
        }
        if size == 0 || size > 65536 {
            return Err(io::Error::other("invalid service handle list size"));
        }
        let mut storage = vec![AttributeStorage([0; 16]); size.div_ceil(16)];
        let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(pointer), 1, None, &mut size) }
            .map_err(win_error)?;
        let mut list = Self {
            storage,
            _handles: PhantomData,
        };
        unsafe {
            UpdateProcThreadAttribute(
                list.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr().cast()),
                std::mem::size_of_val(handles),
                None,
                None,
            )
        }
        .map_err(win_error)?;
        Ok(list)
    }

    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.storage.as_mut_ptr().cast())
    }
}

impl Drop for HandleList<'_> {
    fn drop(&mut self) {
        // Only an initialized list can enter this wrapper.
        unsafe { DeleteProcThreadAttributeList(self.pointer()) };
    }
}

fn spawn_arguments(exe: &Path, cwd: &Path, args: &[&OsStr]) -> io::Result<ServiceChild> {
    if !exe.is_absolute() || !cwd.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service executable and directory must be absolute",
        ));
    }
    let application = wide_nul(exe.as_os_str())?;
    let directory = wide_nul(cwd.as_os_str())?;
    let mut command_line = quoted(exe.as_os_str())?;
    for arg in args {
        command_line.push(b' ' as u16);
        command_line.extend(quoted(arg)?);
    }
    command_line.push(0);
    if command_line.len() > 32767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service command line exceeds the Windows limit",
        ));
    }

    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: true.into(),
        ..Default::default()
    };
    let nul_name = wide_nul(OsStr::new("NUL"))?;
    // NUL supports input EOF and discarded output with this shared read/write
    // handle. No parent stdio, directory, lock, or executable handle is listed.
    let nul = OwnedHandle(
        unsafe {
            CreateFileW(
                PCWSTR(nul_name.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                Some(&security),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(win_error)?,
    );
    let handles = [nul.0];
    let mut attributes = HandleList::new(&handles)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = nul.0;
    startup.StartupInfo.hStdOutput = nul.0;
    startup.StartupInfo.hStdError = nul.0;
    startup.lpAttributeList = attributes.pointer();
    let mut information = PROCESS_INFORMATION::default();

    // SAFETY: all path/command buffers and the initialized attribute list remain
    // live through this call; the command line is mutable and NUL-terminated.
    // bInheritHandles must be TRUE for HANDLE_LIST. The explicit list restricts
    // inheritance to our NUL handle. A null environment preserves the ordinary
    // inherited environment. No BREAKAWAY flag: an enclosing Job still owns the
    // child from creation, including during native qualification.
    unsafe {
        CreateProcessW(
            PCWSTR(application.as_ptr()),
            Some(PWSTR(command_line.as_mut_ptr())),
            None,
            None,
            true,
            CREATE_NO_WINDOW
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            None,
            PCWSTR(directory.as_ptr()),
            &startup as *const STARTUPINFOEXW as *const STARTUPINFOW,
            &mut information,
        )
    }
    .map_err(win_error)?;
    let process = OwnedHandle(information.hProcess);
    let _thread = OwnedHandle(information.hThread);
    // Dropping ServiceChild later closes its handle; it must not terminate the
    // persistent service when the short-lived public launcher exits.
    Ok(ServiceChild { process })
}

#[cfg(test)]
#[path = "windows_spawn_tests.rs"]
mod tests;
