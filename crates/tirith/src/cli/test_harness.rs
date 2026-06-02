//! Shared test harness for tests that mutate process-global state (`HOME`,
//! `cwd`, shell-profile env vars). `ENV_LOCK` serializes them crate-wide so
//! parallel tests can't clobber each other's `set_var`.

use std::ffi::OsString;
use std::panic;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Crate-wide lock for tests that mutate `HOME`, `cwd`, or shell-profile
/// env vars. Tolerates poisoned locks so a single panicking test doesn't
/// cascade-fail every later test.
pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home_tmp = tempfile::tempdir().expect("home tempdir");
    // The `home` crate reads `$HOME` (Unix) / `%USERPROFILE%` (Windows) — set
    // both so `home::home_dir()` is isolated on either platform.
    let _home_guard = EnvGuard::set("HOME", home_tmp.path());
    let _userprofile_guard = EnvGuard::set("USERPROFILE", home_tmp.path());

    let cwd_tmp = if set_cwd {
        Some(tempfile::tempdir().expect("cwd tempdir"))
    } else {
        None
    };
    let _cwd_guard = cwd_tmp.as_ref().map(|t| CwdGuard::set(t.path()));

    let cwd_path = cwd_tmp.as_ref().map(|t| t.path().to_path_buf());
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        f(home_tmp.path(), cwd_path.as_deref())
    }));
    match result {
        Ok(v) => v,
        Err(e) => panic::resume_unwind(e),
    }
}
