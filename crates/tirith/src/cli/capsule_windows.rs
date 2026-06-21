//! Windows capsule executor (Stack E, unit E4): the `windows`-crate Win32 half.
//!
//! This module is the **apply** side of the Windows capsule. It consumes a pure,
//! pre-validated [`tirith_core::capsule::windows::WindowsLaunchPlan`] (built in
//! `tirith-core`, with the containment level already checked and the egress level
//! refused if it cannot be honestly enforced) and materializes it with the Win32
//! AppContainer / ACL / Job Object / process-creation APIs:
//!
//! 1. **AppContainer profile + package SID** — `CreateAppContainerProfile`
//!    (idempotent; an already-existing profile is reused) then
//!    `DeriveAppContainerSidFromAppContainerName` for the package SID the child runs
//!    under. No networking capability is ever passed (the plan grants none), so the
//!    container has no outbound socket access.
//! 2. **ACL grants (tracked + revoked)** — for each [`AclGrant`], add an
//!    `EXPLICIT_ACCESS_W` ACE granting the container package SID the requested
//!    access to the path's DACL via `SetEntriesInAclW` + `SetNamedSecurityInfoW`.
//!    Each grant is recorded so it can be **revoked** after the child exits (a
//!    [`AclGuard`] restores the original DACL).
//! 3. **STARTUPINFOEXW with SECURITY_CAPABILITIES** — an attribute list carrying
//!    `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` so the child is created *inside*
//!    the AppContainer (the package SID + capabilities are bound at creation, not
//!    after).
//! 4. **CreateProcessW, suspended, no inherited handles** — `CREATE_SUSPENDED |
//!    EXTENDED_STARTUPINFO_PRESENT`, `bInheritHandles = FALSE`, an explicit
//!    scrubbed environment block, so the child exists but has not run a single
//!    instruction yet.
//! 5. **Job Object** — `CreateJobObjectW` + `SetInformationJobObject`
//!    (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` plus the plan's CPU / memory /
//!    active-process caps), `AssignProcessToJobObject`, **then** `ResumeThread`. The
//!    child therefore cannot do anything before it is inside a kill-on-close Job.
//!
//! ## Fail closed
//!
//! Every step is checked; on ANY failure the function returns an error WITHOUT
//! resuming the child (the suspended process and its thread are terminated and
//! closed, the Job handle is dropped — which kills the process if it was already
//! assigned — and every ACL grant is revoked). It NEVER falls through to running an
//! uncontained child. The pure plan already refused an allow-listed-domains spec,
//! so this executor only ever runs a `DenyAll` (no-network) containment, matching
//! E4's honest coverage.
//!
//! ## Why a custom launch instead of `std::process::Command`
//!
//! `std::process::Command` cannot pass a `STARTUPINFOEXW` attribute list, which is
//! the only way to create a process *inside* an AppContainer with a
//! `SECURITY_CAPABILITIES` blob. So the launch is hand-rolled with `CreateProcessW`;
//! the command line is built by the pure
//! [`tirith_core::capsule::windows::command_line_for`] (CRT-correct quoting) and the
//! executable is resolved from `lpApplicationName`, closing the search-path
//! ambiguity.
//!
//! This module is `#[cfg(windows)]`-gated: it is compiled and checked only on the
//! Windows runner. The pure planning + honesty logic it depends on lives in
//! `tirith-core` and is tested on every platform.
#![cfg(windows)]
// The launch entry point is consumed by E5 (which routes `runner.rs` / `temp_run.rs`
// / the package-firewall install / the gateway upstream spawn through the capsule).
// Until that wiring lands, the public surface here is exercised only by this
// module's own tests; keep the not-yet-wired API from tripping `-D warnings`.
#![allow(dead_code)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;

use windows::core::{Error as WinError, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, GENERIC_EXECUTE, GENERIC_READ,
    GENERIC_WRITE, HANDLE, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
    GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    FreeSid, ACE_FLAGS, ACL, DACL_SECURITY_INFORMATION, NO_MULTIPLE_TRUSTEE, PSECURITY_DESCRIPTOR,
    PSID, SECURITY_CAPABILITIES, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, ResumeThread,
    TerminateProcess, UpdateProcThreadAttribute, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW, STARTUPINFOW,
};

use tirith_core::capsule::windows::{command_line_for, AclAccess, AclGrant, WindowsLaunchPlan};
use tirith_core::capsule::{CapsuleSpec, EnvironmentPolicy};

/// A failure while applying a Windows capsule launch. Carries a short context and
/// the underlying Win32 error where one is available, so the caller can audit a
/// fail-closed denial without leaking secrets.
#[derive(Debug)]
pub enum WindowsLaunchError {
    /// Creating or deriving the AppContainer identity failed.
    AppContainer(String, WinError),
    /// Applying or reverting an ACL grant failed.
    Acl(String, WIN32_ERROR),
    /// Building the process-thread attribute list failed.
    AttributeList(String, WinError),
    /// `CreateProcessW` failed.
    CreateProcess(String, WinError),
    /// Creating or configuring the Job Object failed.
    JobObject(String, WinError),
    /// Encoding a string for a Win32 wide-string argument failed (interior NUL).
    Encoding(String),
}

impl std::fmt::Display for WindowsLaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowsLaunchError::AppContainer(m, e) => write!(f, "appcontainer: {m}: {e}"),
            WindowsLaunchError::Acl(m, e) => write!(f, "acl: {m}: {e:?}"),
            WindowsLaunchError::AttributeList(m, e) => write!(f, "attribute-list: {m}: {e}"),
            WindowsLaunchError::CreateProcess(m, e) => write!(f, "create-process: {m}: {e}"),
            WindowsLaunchError::JobObject(m, e) => write!(f, "job-object: {m}: {e}"),
            WindowsLaunchError::Encoding(m) => write!(f, "encoding: {m}"),
        }
    }
}

impl std::error::Error for WindowsLaunchError {}

/// A successfully launched, contained child. Holding it keeps the Job Object handle
/// open; dropping it closes the Job, which (because the Job is
/// `KILL_ON_JOB_CLOSE`) terminates the child and its descendants. The ACL grants
/// are revoked when the contained run completes (the caller calls
/// [`ContainedChild::finish`], or the [`AclGuard`]s drop).
pub struct ContainedChild {
    /// The Job Object the child is assigned to (kill-on-close).
    job: OwnedHandle,
    /// The child process handle (for waiting / exit code).
    process: OwnedHandle,
    /// The primary thread handle (already resumed).
    thread: OwnedHandle,
    /// The ACL grants to revoke when the run is done. Held so the grants outlive
    /// the child but are reverted afterward.
    acl_guards: Vec<AclGuard>,
}

impl ContainedChild {
    /// The raw child process handle, for the caller to wait on / read an exit code.
    pub fn process_handle(&self) -> HANDLE {
        self.process.0
    }

    /// Revert every ACL grant now (the child has exited). Idempotent: each guard
    /// reverts once. Returns the first revert error if any, but always attempts all.
    pub fn finish(&mut self) -> Result<(), WindowsLaunchError> {
        let mut first_err = None;
        for guard in &mut self.acl_guards {
            if let Err(e) = guard.revert_now() {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

/// Launch `program` + `args` contained per `spec`, on the current Windows host.
///
/// This is the E4 entry point E5 routes consumers through. It builds the pure plan
/// in `tirith-core` (which fails closed on a level E4 cannot enforce), then applies
/// it: create the AppContainer, ACL the read/write roots to its SID, create the
/// child suspended inside the container with no inherited handles and a scrubbed
/// environment, put it in a kill-on-close Job with the resource caps, and resume.
///
/// On success the returned [`ContainedChild`] owns the Job (kill-on-close) and the
/// process/thread handles; the caller waits on `process_handle()` and then calls
/// [`ContainedChild::finish`] to revert the ACL grants. On ANY failure the child is
/// terminated and every partial change is undone — it NEVER returns an uncontained,
/// running child.
pub fn launch_contained(
    spec: &CapsuleSpec,
    program: &str,
    args: &[String],
) -> Result<ContainedChild, WindowsLaunchError> {
    let plan = tirith_core::capsule::windows::windows_launch_plan(spec, program, args)
        .map_err(|e| WindowsLaunchError::Encoding(e.to_string()))?;
    apply_plan(&plan, &spec.environment)
}

/// Apply an already-built [`WindowsLaunchPlan`]. Split out from
/// [`launch_contained`] so the ordering (the security-critical part) is one
/// reviewable unit. See the module docs for the exact sequence.
fn apply_plan(
    plan: &WindowsLaunchPlan,
    env: &EnvironmentPolicy,
) -> Result<ContainedChild, WindowsLaunchError> {
    // 1. AppContainer profile (idempotent) + package SID.
    let container_sid = create_or_open_appcontainer(plan)?;
    // `container_sid` owns the PSID and frees it on drop.

    // 2. ACL grants — tracked so they are reverted on any later failure or when the
    //    child finishes.
    let mut acl_guards = Vec::with_capacity(plan.acl_grants.len());
    for grant in &plan.acl_grants {
        match apply_acl_grant(grant, container_sid.psid()) {
            Ok(guard) => acl_guards.push(guard),
            Err(e) => {
                // Revert any grants already applied, then fail closed.
                revert_all(&mut acl_guards);
                return Err(e);
            }
        }
    }

    // 3. STARTUPINFOEXW with the SECURITY_CAPABILITIES attribute, so the child is
    //    created INSIDE the AppContainer.
    let mut caps = SECURITY_CAPABILITIES {
        AppContainerSid: container_sid.psid(),
        Capabilities: std::ptr::null_mut(),
        CapabilityCount: 0,
        ..Default::default()
    };
    let mut attr_list = match ProcThreadAttributeList::with_security_capabilities(&mut caps) {
        Ok(l) => l,
        Err(e) => {
            revert_all(&mut acl_guards);
            return Err(e);
        }
    };

    // 4. CreateProcessW: suspended, extended startupinfo, NO inherited handles, a
    //    scrubbed environment block.
    let launched = match create_process(plan, env, &mut attr_list) {
        Ok(l) => l,
        Err(e) => {
            revert_all(&mut acl_guards);
            return Err(e);
        }
    };
    // From here the process exists (suspended). Any failure must terminate it.

    // 5. Job Object: create, configure (kill-on-close + caps), assign, then resume.
    let job = match create_and_assign_job(plan, launched.process.0) {
        Ok(j) => j,
        Err(e) => {
            // Terminate the suspended child and revert ACLs.
            terminate_quietly(launched.process.0);
            revert_all(&mut acl_guards);
            return Err(e);
        }
    };

    // Resume only after the child is inside the kill-on-close Job.
    // SAFETY: `launched.thread.0` is the valid primary-thread handle returned by
    // CreateProcessW; ResumeThread takes ownership of nothing.
    let resume_rc = unsafe { ResumeThread(launched.thread.0) };
    if resume_rc == u32::MAX {
        let err = WinError::from_win32();
        terminate_quietly(launched.process.0);
        // Dropping `job` closes the Job and (kill-on-close) the process too.
        drop(job);
        revert_all(&mut acl_guards);
        return Err(WindowsLaunchError::CreateProcess(
            "ResumeThread failed".to_string(),
            err,
        ));
    }

    Ok(ContainedChild {
        job,
        process: launched.process,
        thread: launched.thread,
        acl_guards,
    })
}

/// A PSID that owns its allocation and frees it on drop via `FreeSid`. Used for the
/// AppContainer package SID returned by `CreateAppContainerProfile` /
/// `DeriveAppContainerSidFromAppContainerName`.
struct OwnedSid(PSID);

impl OwnedSid {
    fn psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            // SAFETY: `self.0` is a PSID we obtained from the AppContainer APIs and
            // have not freed; FreeSid is the matching deallocator.
            unsafe {
                let _ = FreeSid(self.0);
            }
            self.0 = PSID(std::ptr::null_mut());
        }
    }
}

/// Create the AppContainer profile (or reuse an existing one) and return its package
/// SID. `CreateAppContainerProfile` returns the SID directly; if the profile already
/// exists it fails with `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`, in which case we
/// derive the SID from the name instead (idempotent reuse). No capabilities are ever
/// passed (the plan grants none), so the container has no networking capability.
fn create_or_open_appcontainer(plan: &WindowsLaunchPlan) -> Result<OwnedSid, WindowsLaunchError> {
    let name = wide_nul(&plan.profile.name)
        .map_err(|_| WindowsLaunchError::Encoding("appcontainer name has NUL".to_string()))?;
    let display = wide_nul(&plan.profile.display_name)
        .map_err(|_| WindowsLaunchError::Encoding("display name has NUL".to_string()))?;

    // First try to create. `pcapabilities = None` -> no capabilities, so no network.
    // SAFETY: the wide strings are NUL-terminated and outlive the call.
    let created = unsafe {
        CreateAppContainerProfile(
            PCWSTR(name.as_ptr()),
            PCWSTR(display.as_ptr()),
            PCWSTR(display.as_ptr()),
            None,
        )
    };
    match created {
        Ok(psid) => Ok(OwnedSid(psid)),
        Err(_) => {
            // Most likely ERROR_ALREADY_EXISTS: derive the SID from the existing
            // profile. (Any other error surfaces here too, with a derive failure.)
            let mut psid = PSID(std::ptr::null_mut());
            // SAFETY: `name` is NUL-terminated; `psid` is a valid out-pointer.
            let derived = unsafe {
                DeriveAppContainerSidFromAppContainerName(PCWSTR(name.as_ptr()), &mut psid)
            };
            match derived {
                Ok(()) => Ok(OwnedSid(psid)),
                Err(e) => Err(WindowsLaunchError::AppContainer(
                    "create and derive both failed".to_string(),
                    e,
                )),
            }
        }
    }
}

/// An ACL grant that has been applied to a path's DACL and remembers how to revert
/// it. On revert it re-installs the path's **original** DACL (the one we read before
/// adding our ACE), so the grant leaves no residue.
///
/// **Ownership:** `security_descriptor` is the `PSECURITY_DESCRIPTOR` that
/// `GetNamedSecurityInfoW` allocated; `original_dacl` points *inside* it. The guard
/// therefore owns the descriptor and `LocalFree`s it only after the final revert, so
/// `original_dacl` is never dangled (the use-after-free that would result from
/// freeing the descriptor while the guard still holds the inner DACL pointer).
struct AclGuard {
    /// The path whose DACL we modified (NUL-terminated wide string).
    path_wide: Vec<u16>,
    /// The security descriptor backing `original_dacl` (owned; `LocalFree`d on drop).
    security_descriptor: PSECURITY_DESCRIPTOR,
    /// The original DACL to restore on revert (points into `security_descriptor`;
    /// may be null == "no explicit DACL").
    original_dacl: *const ACL,
    /// Whether this guard has already reverted.
    reverted: bool,
}

impl AclGuard {
    /// Revert the grant now (restore the original DACL). Idempotent.
    fn revert_now(&mut self) -> Result<(), WindowsLaunchError> {
        if self.reverted {
            return Ok(());
        }
        self.reverted = true;
        // SAFETY: `path_wide` is NUL-terminated; `original_dacl` points into the
        // still-live `security_descriptor` (freed only in Drop, after this revert).
        let rc = unsafe {
            SetNamedSecurityInfoW(
                PCWSTR(self.path_wide.as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(self.original_dacl),
                None,
            )
        };
        if rc.is_ok() {
            Ok(())
        } else {
            Err(WindowsLaunchError::Acl(
                "restore original DACL".to_string(),
                rc,
            ))
        }
    }
}

impl Drop for AclGuard {
    fn drop(&mut self) {
        // Best-effort revert on drop; an explicit `finish()` reports errors. The
        // revert reads `original_dacl`, so it MUST happen before we free the backing
        // descriptor.
        let _ = self.revert_now();
        if !self.security_descriptor.0.is_null() {
            // SAFETY: `security_descriptor` was allocated by GetNamedSecurityInfoW and
            // is freed exactly once here; `original_dacl` is not used after this.
            unsafe {
                let _ = LocalFree(HLOCAL(self.security_descriptor.0));
            }
            self.security_descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        }
    }
}

/// Revert every guard, swallowing individual errors (used on a fail-closed path
/// where we are already returning an error and just want to undo state).
fn revert_all(guards: &mut [AclGuard]) {
    for g in guards.iter_mut() {
        let _ = g.revert_now();
    }
}

/// Map an [`AclAccess`] to a Win32 generic access mask.
fn access_mask(access: AclAccess) -> u32 {
    match access {
        // Read + execute (traverse/list/read).
        AclAccess::ReadExecute => (GENERIC_READ | GENERIC_EXECUTE).0,
        // Read + write + execute. A write root implies read. Deliberately NOT
        // GENERIC_ALL (which would also grant WRITE_DAC / WRITE_OWNER, letting the
        // contained child rewrite the very DACL we use to confine it).
        AclAccess::Modify => (GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE).0,
    }
}

/// Apply one ACL grant: read the path's current DACL, add an ACE granting the
/// container SID the requested access (inheriting to sub-objects), and write the new
/// DACL back. Returns an [`AclGuard`] that restores the original DACL on revert.
///
/// We use `GetNamedSecurityInfoW` to fetch the existing DACL so the grant is
/// ADDITIVE (we never clobber existing permissions); `SetEntriesInAclW` merges our
/// new ACE into it; `SetNamedSecurityInfoW` installs the merged DACL.
fn apply_acl_grant(grant: &AclGrant, container_sid: PSID) -> Result<AclGuard, WindowsLaunchError> {
    let path_str = grant
        .path
        .to_str()
        .ok_or_else(|| WindowsLaunchError::Encoding(format!("non-UTF-8 path: {:?}", grant.path)))?;
    let path_wide =
        wide_nul(path_str).map_err(|_| WindowsLaunchError::Encoding("path has NUL".to_string()))?;

    // Read the existing DACL (so our grant is additive).
    let mut existing_dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `path_wide` is NUL-terminated; out-pointers are valid.
    let get_rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl as *mut *mut ACL),
            None,
            &mut sd,
        )
    };
    if get_rc.is_err() {
        return Err(WindowsLaunchError::Acl(
            "read existing DACL".to_string(),
            get_rc,
        ));
    }

    // Build the explicit-access entry granting the container SID our access mask.
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access_mask(grant.access),
        grfAccessMode: GRANT_ACCESS,
        // Inherit to contained sub-objects so a directory grant covers its tree.
        grfInheritance: ACE_FLAGS(SUB_CONTAINERS_AND_OBJECTS_INHERIT),
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: PWSTR(container_sid.0 as *mut u16),
        },
    };

    // Merge our ACE into the existing DACL.
    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    let entries = [ea];
    // SAFETY: `entries` lives for the call; `existing_dacl` is the DACL we just read;
    // `new_dacl` is a valid out-pointer the API allocates into.
    let set_rc = unsafe {
        SetEntriesInAclW(
            Some(&entries),
            Some(existing_dacl as *const ACL),
            &mut new_dacl as *mut *mut ACL,
        )
    };
    if set_rc.is_err() {
        // Free the descriptor we read (existing_dacl points into it) before bailing.
        // SAFETY: `sd` was allocated by GetNamedSecurityInfoW; freed once here.
        unsafe {
            let _ = LocalFree(HLOCAL(sd.0));
        }
        return Err(WindowsLaunchError::Acl("merge ACE".to_string(), set_rc));
    }

    // Install the merged DACL.
    // SAFETY: `path_wide` is NUL-terminated; `new_dacl` is the merged DACL.
    let apply_rc = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl as *const ACL),
            None,
        )
    };
    // `SetNamedSecurityInfoW` copies the DACL into the object, so the merged
    // `new_dacl` buffer (allocated by SetEntriesInAclW) is ours to free now,
    // regardless of success.
    // SAFETY: `new_dacl` was allocated by SetEntriesInAclW; freed exactly once.
    unsafe {
        let _ = LocalFree(HLOCAL(new_dacl as *mut core::ffi::c_void));
    }
    if apply_rc.is_err() {
        // Free the read descriptor; we never built a guard.
        // SAFETY: `sd` was allocated by GetNamedSecurityInfoW; freed once here.
        unsafe {
            let _ = LocalFree(HLOCAL(sd.0));
        }
        return Err(WindowsLaunchError::Acl(
            "install DACL".to_string(),
            apply_rc,
        ));
    }

    Ok(AclGuard {
        path_wide,
        // The guard OWNS `sd` and frees it on drop (after the final revert);
        // `existing_dacl` points into it and is the original DACL to restore.
        security_descriptor: sd,
        original_dacl: existing_dacl as *const ACL,
        reverted: false,
    })
}

/// The handles produced by a successful `CreateProcessW` (before the child is
/// resumed): the process and its primary thread, each owned and closed on drop.
struct Launched {
    process: OwnedHandle,
    thread: OwnedHandle,
}

/// Create the child process: suspended, extended startupinfo (so the
/// SECURITY_CAPABILITIES attribute binds), `bInheritHandles = FALSE`, and a scrubbed
/// environment block. The executable is resolved from `lpApplicationName`; the
/// command line (CRT-correctly quoted) is the conventional argv the child sees.
fn create_process(
    plan: &WindowsLaunchPlan,
    env: &EnvironmentPolicy,
    attr_list: &mut ProcThreadAttributeList,
) -> Result<Launched, WindowsLaunchError> {
    let app = wide_nul(&plan.program)
        .map_err(|_| WindowsLaunchError::Encoding("program path has NUL".to_string()))?;
    // CreateProcessW may modify the command-line buffer in place, so it must be a
    // writable, owned wide buffer.
    let mut cmdline = wide_nul(&command_line_for(plan))
        .map_err(|_| WindowsLaunchError::Encoding("command line has NUL".to_string()))?;

    // Scrubbed environment block (double-NUL-terminated UTF-16).
    let mut env_block = build_environment_block(env);

    let mut si = STARTUPINFOEXW::default();
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list.as_ptr();

    let mut pi = PROCESS_INFORMATION::default();

    // SAFETY: `app` and `cmdline` are NUL-terminated wide buffers that outlive the
    // call; `cmdline` is writable (CreateProcessW may edit it). The attribute list is
    // valid for the call. `env_block` is a double-NUL-terminated UTF-16 block. The
    // STARTUPINFOEXW is reinterpreted as STARTUPINFOW as the API expects when
    // EXTENDED_STARTUPINFO_PRESENT is set.
    let ok = unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            Some(PWSTR(cmdline.as_mut_ptr())),
            None,
            None,
            // bInheritHandles = FALSE — the honest handle closure (HandlePolicy).
            false,
            // CREATE_UNICODE_ENVIRONMENT is mandatory because `env_block` is UTF-16;
            // without it Windows reads the block as ANSI and corrupts the scrubbed
            // environment. CREATE_SUSPENDED so the child does nothing before it is
            // inside the Job; EXTENDED_STARTUPINFO_PRESENT so the SECURITY_CAPABILITIES
            // attribute binds the AppContainer at creation.
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            Some(env_block.as_mut_ptr() as *const c_void),
            PCWSTR::null(),
            &si as *const STARTUPINFOEXW as *const STARTUPINFOW,
            &mut pi,
        )
    };
    if let Err(e) = ok {
        return Err(WindowsLaunchError::CreateProcess(
            "CreateProcessW failed".to_string(),
            e,
        ));
    }

    Ok(Launched {
        process: OwnedHandle(pi.hProcess),
        thread: OwnedHandle(pi.hThread),
    })
}

/// Build a scrubbed, double-NUL-terminated UTF-16 environment block from the
/// policy's surviving variables. Sensitive variables are stripped
/// ([`EnvironmentPolicy::surviving_vars`]); when `temporary_home`, HOME / USERPROFILE
/// / TEMP / TMP are pointed at an isolated temp directory.
///
/// The returned `Vec<u16>` is the `lpEnvironment` block: `KEY=VALUE\0KEY=VALUE\0\0`.
fn build_environment_block(policy: &EnvironmentPolicy) -> Vec<u16> {
    let present: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .collect();
    let survivors = policy.surviving_vars(present.iter().map(|s| s.as_str()));

    // Isolated HOME/TEMP for the child when temporary_home is set.
    let temp_home = if policy.temporary_home {
        std::env::temp_dir().join(format!("tirith-capsule-{}", std::process::id()))
    } else {
        std::path::PathBuf::new()
    };

    let mut block: Vec<u16> = Vec::new();
    for name in &survivors {
        // Skip the HOME/TEMP family here; we set them below from temp_home so the
        // child cannot reach the real user profile.
        if policy.temporary_home && is_home_or_temp(name) {
            continue;
        }
        if let Ok(val) = std::env::var(name) {
            push_env_entry(&mut block, name, &val);
        }
    }
    if policy.temporary_home {
        let home = temp_home.to_string_lossy().to_string();
        for key in [
            "USERPROFILE",
            "HOME",
            "TEMP",
            "TMP",
            "LOCALAPPDATA",
            "APPDATA",
        ] {
            push_env_entry(&mut block, key, &home);
        }
    }
    // An environment block is `KEY=VALUE\0...\0` terminated by an extra NUL. An EMPTY
    // block must still be a double NUL (`\0\0`) for CreateProcessW. Each entry already
    // ended in a NUL, so one more NUL terminates a non-empty block; for the empty case
    // we emit two so the block is a valid (empty) double-NUL block.
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// Whether `name` is part of the HOME/TEMP family we override under
/// `temporary_home` (so we drop the parent's value and substitute the isolated dir).
fn is_home_or_temp(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "USERPROFILE" | "HOME" | "TEMP" | "TMP" | "LOCALAPPDATA" | "APPDATA"
    )
}

/// Append one `KEY=VALUE\0` entry (UTF-16) to an environment block.
fn push_env_entry(block: &mut Vec<u16>, key: &str, value: &str) {
    block.extend(OsStr::new(key).encode_wide());
    block.push(u16::from(b'='));
    block.extend(OsStr::new(value).encode_wide());
    block.push(0);
}

/// An owned `PROC_THREAD_ATTRIBUTE_LIST` heap buffer, initialized for exactly one
/// attribute (the SECURITY_CAPABILITIES blob). Frees the list on drop.
struct ProcThreadAttributeList {
    buf: Vec<u8>,
}

impl ProcThreadAttributeList {
    /// Initialize an attribute list carrying `caps` as
    /// `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`. The first
    /// `InitializeProcThreadAttributeList` returns `ERROR_INSUFFICIENT_BUFFER`
    /// (expected) to report the size; we allocate, initialize for real, then set the
    /// one attribute.
    fn with_security_capabilities(
        caps: &mut SECURITY_CAPABILITIES,
    ) -> Result<Self, WindowsLaunchError> {
        let mut size: usize = 0;
        // First call: size the buffer. It "fails" with ERROR_INSUFFICIENT_BUFFER.
        // SAFETY: passing None + a valid size out-pointer is the documented sizing
        // call.
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
        if size == 0 {
            return Err(WindowsLaunchError::AttributeList(
                "sizing returned zero".to_string(),
                WinError::from(ERROR_INSUFFICIENT_BUFFER),
            ));
        }
        let mut buf = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut c_void);
        // Real initialization.
        // SAFETY: `list` points at a `size`-byte buffer; `size` matches the sizing
        // call.
        let init = unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut size) };
        if let Err(e) = init {
            return Err(WindowsLaunchError::AttributeList(
                "InitializeProcThreadAttributeList".to_string(),
                e,
            ));
        }
        // Set the SECURITY_CAPABILITIES attribute.
        // SAFETY: `caps` outlives the attribute list usage (the caller keeps it
        // alive until after CreateProcessW); the attribute id + size are correct.
        let upd = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some(caps as *const SECURITY_CAPABILITIES as *const c_void),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
        };
        if let Err(e) = upd {
            // Delete the partially-initialized list before returning.
            // SAFETY: `list` was initialized above.
            unsafe { DeleteProcThreadAttributeList(list) };
            return Err(WindowsLaunchError::AttributeList(
                "UpdateProcThreadAttribute".to_string(),
                e,
            ));
        }
        Ok(ProcThreadAttributeList { buf })
    }

    /// The raw attribute-list pointer for `STARTUPINFOEXW::lpAttributeList`.
    fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buf.as_mut_ptr() as *mut c_void)
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(self.buf.as_mut_ptr() as *mut c_void);
        // SAFETY: `list` was initialized in `with_security_capabilities`.
        unsafe { DeleteProcThreadAttributeList(list) };
    }
}

/// Create a Job Object configured per the plan (kill-on-close + caps), assign the
/// process to it, and return the owned Job handle. Dropping the handle closes the
/// Job, which (kill-on-close) terminates the process.
fn create_and_assign_job(
    plan: &WindowsLaunchPlan,
    process: HANDLE,
) -> Result<OwnedHandle, WindowsLaunchError> {
    // SAFETY: an anonymous Job; no name, default security.
    let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|e| WindowsLaunchError::JobObject("CreateJobObjectW".to_string(), e))?;
    let job = OwnedHandle(job);

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut basic = JOBOBJECT_BASIC_LIMIT_INFORMATION::default();
    let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if let Some(ticks) = plan.job_limits.per_job_user_time_100ns {
        basic.PerJobUserTimeLimit = ticks as i64;
        flags |= JOB_OBJECT_LIMIT_JOB_TIME;
    }
    if let Some(procs) = plan.job_limits.active_process_limit {
        basic.ActiveProcessLimit = procs;
        flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    }
    basic.LimitFlags = flags;
    info.BasicLimitInformation = basic;
    if let Some(mem) = plan.job_limits.job_memory_bytes {
        info.JobMemoryLimit = mem as usize;
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
    }

    // SAFETY: `info` is a valid, fully-initialized extended-limit struct for the
    // duration of the call; the size matches the type.
    let set = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if let Err(e) = set {
        return Err(WindowsLaunchError::JobObject(
            "SetInformationJobObject".to_string(),
            e,
        ));
    }

    // Assign the (suspended) process to the Job BEFORE it runs.
    // SAFETY: both handles are valid; the process is suspended.
    let assign = unsafe { AssignProcessToJobObject(job.0, process) };
    if let Err(e) = assign {
        return Err(WindowsLaunchError::JobObject(
            "AssignProcessToJobObject".to_string(),
            e,
        ));
    }
    Ok(job)
}

/// Terminate a process handle, swallowing the result (used on fail-closed paths).
fn terminate_quietly(process: HANDLE) {
    // SAFETY: `process` is a valid handle; TerminateProcess takes ownership of
    // nothing. Exit code 1 marks an aborted contained launch.
    unsafe {
        let _ = TerminateProcess(process, 1);
    }
}

/// A HANDLE that is closed on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `self.0` is a valid handle we own and have not closed.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Encode `s` as a NUL-terminated UTF-16 buffer for a Win32 wide-string argument.
/// Errors (via `None`) if `s` contains an interior NUL, which would truncate the
/// string.
fn wide_nul(s: &str) -> Result<Vec<u16>, ()> {
    if s.contains('\0') {
        return Err(());
    }
    let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
    v.push(0);
    Ok(v)
}

// `SUB_CONTAINERS_AND_OBJECTS_INHERIT` lives in the WinNT security headers; the
// windows crate exposes it as a u32 inheritance flag we wrap into ACE_FLAGS. Defined
// here as the documented constant value to avoid pulling a broader feature just for
// one flag.
const SUB_CONTAINERS_AND_OBJECTS_INHERIT: u32 = 0x3;

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::capsule::windows::windows_launch_plan;
    use tirith_core::capsule::CapsuleSpec;

    #[test]
    fn wide_nul_encodes_and_terminates() {
        let w = wide_nul("ab").expect("encode");
        assert_eq!(w, vec![b'a' as u16, b'b' as u16, 0]);
    }

    #[test]
    fn wide_nul_rejects_interior_nul() {
        assert!(wide_nul("a\0b").is_err());
    }

    #[test]
    fn access_mask_modify_includes_write() {
        let m = access_mask(AclAccess::Modify);
        assert!(m & GENERIC_WRITE.0 != 0, "modify must include write");
        let r = access_mask(AclAccess::ReadExecute);
        assert!(
            r & GENERIC_WRITE.0 == 0,
            "read-execute must not include write"
        );
        assert!(r & GENERIC_READ.0 != 0, "read-execute must include read");
    }

    #[test]
    fn environment_block_strips_sensitive_and_double_nul_terminates() {
        // Build a block from a policy that inherits the parent env but strips
        // sensitive names; assert a sensitive var is absent and the block ends in NUL.
        std::env::set_var("TIRITH_TEST_BENIGN", "ok");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "shh");
        let policy = EnvironmentPolicy {
            inherit: true,
            allow: Vec::new(),
            deny_sensitive: true,
            temporary_home: false,
        };
        let block = build_environment_block(&policy);
        // Decode to a string for substring checks (entries are KEY=VALUE\0...).
        let decoded = String::from_utf16_lossy(&block);
        assert!(decoded.contains("TIRITH_TEST_BENIGN=ok"));
        assert!(
            !decoded.contains("AWS_SECRET_ACCESS_KEY"),
            "sensitive var must be stripped from the child env block"
        );
        assert_eq!(*block.last().unwrap(), 0, "block must end with a NUL");
        std::env::remove_var("TIRITH_TEST_BENIGN");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    #[test]
    fn environment_block_overrides_home_under_temporary_home() {
        std::env::set_var("USERPROFILE", "C:/Users/real");
        let policy = EnvironmentPolicy {
            inherit: true,
            allow: Vec::new(),
            deny_sensitive: true,
            temporary_home: true,
        };
        let block = build_environment_block(&policy);
        let decoded = String::from_utf16_lossy(&block);
        // The real profile path must NOT survive; an isolated temp dir replaces it.
        assert!(
            !decoded.contains("C:/Users/real"),
            "real USERPROFILE must be replaced under temporary_home"
        );
        assert!(decoded.contains("USERPROFILE="));
        std::env::remove_var("USERPROFILE");
    }

    #[test]
    fn apply_plan_refuses_allowlisted_via_core_plan() {
        // The pure plan builder refuses an allow-list spec; launch_contained surfaces
        // that as an error WITHOUT touching any Win32 API.
        let mut spec = CapsuleSpec::locked_down();
        spec.network = tirith_core::capsule::NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        // We can build the (refused) plan directly to assert the contract without
        // spawning anything.
        assert!(windows_launch_plan(&spec, "C:/cmd.exe", &[]).is_err());
    }
}
