//! Compatibility harness for CLI tests that mutate process-global state.
//!
//! [`ENV_LOCK`] now enters the workspace-wide [`tirith_test_support::GlobalStateGuard`]
//! domain, so CLI tests serialize with every other crate using the shared test
//! support. [`EnvGuard`] and [`CwdGuard`] retain the existing narrow override
//! API for callers that need a value different from the fresh application
//! roots installed by the shared guard.

use std::ffi::OsString;
use std::panic;
use std::path::{Path, PathBuf};
use std::sync::LockResult;

/// Compatibility facade retaining the former `ENV_LOCK.lock()` API while
/// acquiring the workspace-wide process-global state guard.
pub(crate) struct EnvLock;

impl EnvLock {
    // This source-compatible facade deliberately retains the former
    // `Mutex::lock` return shape for existing tests. It is always `Ok` because
    // `GlobalStateGuard` recovers a poisoned shared lock internally.
    #[allow(clippy::result_large_err)]
    pub(crate) fn lock(&self) -> LockResult<tirith_test_support::GlobalStateGuard> {
        Ok(tirith_test_support::GlobalStateGuard::new()
            .expect("create isolated process-global CLI test state"))
    }
}

pub(crate) static ENV_LOCK: EnvLock = EnvLock;

/// RAII guard that restores (or removes) an env var on Drop.
pub(crate) struct EnvGuard {
    key: &'static str,
    old: Option<OsString>,
}

impl EnvGuard {
    pub(crate) fn set(key: &'static str, val: &Path) -> Self {
        let old = std::env::var_os(key);
        unsafe { std::env::set_var(key, val) };
        Self { key, old }
    }

    /// Remove `key` for the test's duration, restoring the prior value on Drop.
    pub(crate) fn remove(key: &'static str) -> Self {
        let old = std::env::var_os(key);
        unsafe { std::env::remove_var(key) };
        Self { key, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(v) => unsafe { std::env::set_var(self.key, v) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

/// RAII guard that restores the previous cwd on Drop.
pub(crate) struct CwdGuard {
    old: PathBuf,
}

impl CwdGuard {
    pub(crate) fn set(new: &Path) -> Self {
        let old = std::env::current_dir().expect("current_dir");
        std::env::set_current_dir(new).expect("set_current_dir");
        Self { old }
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.old);
    }
}

/// Run `f` with `HOME` (and optionally `cwd`) pointed at fresh temp dirs,
/// holding `ENV_LOCK` across the closure and restoring state on Drop even if
/// `f` panics. The closure gets `(home_path, cwd_path)`, `cwd_path` `Some` iff
/// `set_cwd`.
pub(crate) fn with_fake_env<F, R>(set_cwd: bool, f: F) -> R
where
    F: panic::UnwindSafe + FnOnce(&Path, Option<&Path>) -> R,
{
    // GlobalStateGuard always installs a fresh cwd. Preserve the compatibility
    // contract for `set_cwd == false` by temporarily returning to the caller's
    // cwd inside the shared guard's lifetime; CwdGuard restores the isolated
    // cwd before GlobalStateGuard restores the original process state.
    let original_cwd = (!set_cwd).then(|| std::env::current_dir().expect("current_dir"));
    let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _cwd_guard = original_cwd.as_deref().map(CwdGuard::set);

    let home_path = lock.roots().home.clone();
    let isolated_cwd = set_cwd.then(|| {
        std::fs::canonicalize(&lock.roots().cwd).unwrap_or_else(|_| lock.roots().cwd.to_path_buf())
    });

    // Hand back the canonical path. macOS puts temp dirs under the /var ->
    // /private/var symlink, so code that observes its own cwd (or canonicalizes
    // one) sees /private/var/... while the tempdir handle reports /var/...;
    // tests that compare the two forms would fail on macOS only.
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        f(&home_path, isolated_cwd.as_deref())
    }));
    match result {
        Ok(v) => v,
        Err(e) => panic::resume_unwind(e),
    }
}
