//! Shared, panic-safe isolation for tests that mutate process-global state.
//!
//! A [`GlobalStateGuard`] takes the process-global state lock EXCLUSIVELY,
//! installs fresh application roots, and restores the exact prior state on
//! drop. Child processes should be configured through
//! [`GlobalStateGuard::apply_to_command`], which starts from `env_clear()` and
//! inherits only the isolated roots plus the small platform launch allowlist.
//!
//! A [`SharedStateGuard`] takes the same lock SHARED. Tests that only READ
//! process-global state (HOME/XDG/`TIRITH_*`-based policy, trust, threat-DB or
//! state discovery, or the cwd) hold one so they never observe another test's
//! temporary roots: readers run concurrently with each other, but never while
//! a [`GlobalStateGuard`] is alive.

use std::cell::Cell;
use std::ffi::{OsStr, OsString};
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Readers ([`SharedStateGuard`]) share it; mutators ([`GlobalStateGuard`])
/// hold it exclusively.
static GLOBAL_STATE_LOCK: RwLock<()> = RwLock::new(());

thread_local! {
    /// Shared guards alive on this thread. Only the outermost one holds the
    /// read lock, so nesting never re-enters the RwLock (a nested read behind
    /// a queued writer would deadlock).
    static SHARED_DEPTH: Cell<usize> = const { Cell::new(0) };
    /// Exclusive guards alive on this thread. A shared guard taken while this
    /// thread already excludes everyone else is a no-op.
    static EXCLUSIVE_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Shared (read) side of the process-global test state lock.
///
/// Hold one for the whole test when the test (or code it calls) reads HOME,
/// XDG/`APPDATA` roots, `TIRITH_*` overrides or the cwd without changing them.
/// While it is alive no [`GlobalStateGuard`] can install or restore isolated
/// roots, so discovery sees one consistent environment. Nested shared guards
/// on one thread and a shared guard taken under this thread's own
/// [`GlobalStateGuard`] are allowed. Taking a [`GlobalStateGuard`] while this
/// thread holds a shared guard panics instead of deadlocking.
pub struct SharedStateGuard {
    _lock: Option<RwLockReadGuard<'static, ()>>,
    // Thread-local depth accounting requires dropping on the acquiring thread.
    _not_send: PhantomData<*const ()>,
}

impl SharedStateGuard {
    /// Wait until no [`GlobalStateGuard`] is alive, then hold the lock shared.
    /// Poison-tolerant like [`GlobalStateGuard::new`].
    pub fn acquire() -> Self {
        let lock = if EXCLUSIVE_DEPTH.with(Cell::get) > 0 || SHARED_DEPTH.with(Cell::get) > 0 {
            None
        } else {
            Some(
                GLOBAL_STATE_LOCK
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
        };
        SHARED_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self {
            _lock: lock,
            _not_send: PhantomData,
        }
    }
}

impl Drop for SharedStateGuard {
    fn drop(&mut self) {
        SHARED_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Hold the shared side of the process-global test state lock; see
/// [`SharedStateGuard`].
pub fn shared_global_state() -> SharedStateGuard {
    SharedStateGuard::acquire()
}

/// Exclusive side; tracks this thread's ownership for [`SharedStateGuard`].
struct ExclusiveLock {
    _lock: RwLockWriteGuard<'static, ()>,
}

impl ExclusiveLock {
    fn acquire() -> Self {
        assert_eq!(
            SHARED_DEPTH.with(Cell::get),
            0,
            "GlobalStateGuard::new() on a thread that holds a SharedStateGuard \
             would deadlock: take only the GlobalStateGuard in this test"
        );
        let lock = GLOBAL_STATE_LOCK
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        EXCLUSIVE_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self { _lock: lock }
    }
}

impl Drop for ExclusiveLock {
    fn drop(&mut self) {
        EXCLUSIVE_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

const CHILD_PASSTHROUGH_ENV: &[&str] = &[
    "PATH",
    // Windows needs these to launch ordinary child processes after env_clear.
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
];

/// Temp-directory selectors are installed on env-cleared child commands, but
/// not process-globally. `tempfile` consults these variables in otherwise
/// unrelated tests; repointing them at this guard's owned root lets those tests
/// create files that disappear when the guard drops.
const CHILD_ONLY_ISOLATED_ENV: &[&str] = &["TMPDIR", "TMP", "TEMP"];

/// Every fresh filesystem location installed by [`GlobalStateGuard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedRoots {
    pub root: PathBuf,
    pub home: PathBuf,
    pub xdg_config: PathBuf,
    pub xdg_config_dirs: PathBuf,
    pub xdg_data: PathBuf,
    pub xdg_state: PathBuf,
    pub xdg_cache: PathBuf,
    pub xdg_runtime: PathBuf,
    pub appdata: PathBuf,
    pub local_appdata: PathBuf,
    pub temp: PathBuf,
    pub kubernetes: PathBuf,
    pub kubeconfig: PathBuf,
    pub threatdb: PathBuf,
    pub threatdb_supplemental: PathBuf,
    pub policy: PathBuf,
    pub tirith_state: PathBuf,
    pub cwd: PathBuf,
}

impl IsolatedRoots {
    fn create(root: &Path) -> io::Result<Self> {
        let roots = Self {
            root: root.to_path_buf(),
            home: root.join("home"),
            // `xdg-user-dir` sources files from XDG_CONFIG_HOME, so setup
            // deliberately accepts that root only when it is contained by the
            // selected HOME. Keep the shared fixture realistic: a sibling of
            // HOME is isolated, but it is not a valid user configuration root.
            xdg_config: root.join("home").join(".config"),
            xdg_config_dirs: root.join("xdg-config-dirs"),
            xdg_data: root.join("xdg-data"),
            xdg_state: root.join("xdg-state"),
            xdg_cache: root.join("xdg-cache"),
            xdg_runtime: root.join("xdg-runtime"),
            appdata: root.join("appdata"),
            local_appdata: root.join("local-appdata"),
            temp: root.join("temp"),
            kubernetes: root.join("kubernetes"),
            kubeconfig: root.join("kubernetes/config"),
            threatdb: root.join("threatdb/primary.json"),
            threatdb_supplemental: root.join("threatdb/supplemental.json"),
            policy: root.join("policy"),
            tirith_state: root.join("tirith-state"),
            cwd: root.join("cwd"),
        };
        for directory in [
            roots.home.as_path(),
            roots.xdg_config.as_path(),
            roots.xdg_config_dirs.as_path(),
            roots.xdg_data.as_path(),
            roots.xdg_state.as_path(),
            roots.xdg_cache.as_path(),
            roots.xdg_runtime.as_path(),
            roots.appdata.as_path(),
            roots.local_appdata.as_path(),
            roots.temp.as_path(),
            roots.kubernetes.as_path(),
            roots.threatdb.parent().expect("threatdb has a parent"),
            roots.policy.as_path(),
            roots.tirith_state.as_path(),
            roots.cwd.as_path(),
        ] {
            std::fs::create_dir_all(directory)?;
        }
        Ok(roots)
    }

    fn assignments(&self) -> Vec<(&'static str, &OsStr)> {
        vec![
            ("HOME", self.home.as_os_str()),
            ("USERPROFILE", self.home.as_os_str()),
            ("XDG_CONFIG_HOME", self.xdg_config.as_os_str()),
            ("XDG_CONFIG_DIRS", self.xdg_config_dirs.as_os_str()),
            ("XDG_DATA_HOME", self.xdg_data.as_os_str()),
            ("XDG_STATE_HOME", self.xdg_state.as_os_str()),
            ("XDG_CACHE_HOME", self.xdg_cache.as_os_str()),
            ("XDG_RUNTIME_DIR", self.xdg_runtime.as_os_str()),
            ("APPDATA", self.appdata.as_os_str()),
            ("LOCALAPPDATA", self.local_appdata.as_os_str()),
            ("TMPDIR", self.temp.as_os_str()),
            ("TMP", self.temp.as_os_str()),
            ("TEMP", self.temp.as_os_str()),
            ("KUBECONFIG", self.kubeconfig.as_os_str()),
            ("TIRITH_THREATDB_PATH", self.threatdb.as_os_str()),
            (
                "TIRITH_THREATDB_SUPPLEMENTAL_PATH",
                self.threatdb_supplemental.as_os_str(),
            ),
            ("TIRITH_POLICY_ROOT", self.policy.as_os_str()),
            ("TIRITH_SETUP_LOCK_ROOT", self.tirith_state.as_os_str()),
        ]
    }
}

type RestoreCallback = Box<dyn FnOnce() + 'static>;

/// Owns the process-global test lock exclusively and restores all state even
/// during unwind.
///
/// Construction is fallible so a missing original cwd or an unusable temp root
/// cannot turn into a half-installed environment. The lock is poison-tolerant:
/// a previous panicking test does not cascade into every later test.
pub struct GlobalStateGuard {
    temp_root: Option<tempfile::TempDir>,
    roots: IsolatedRoots,
    previous_env: Vec<(&'static str, Option<OsString>)>,
    previous_cwd: PathBuf,
    child_env: Vec<(OsString, OsString)>,
    after_restore: Vec<RestoreCallback>,
    _lock: ExclusiveLock,
}

impl GlobalStateGuard {
    /// Acquire the process-global lock exclusively and install a fully
    /// isolated environment plus a fresh cwd.
    ///
    /// # Panics
    /// When the calling thread holds a [`SharedStateGuard`] (that would
    /// otherwise deadlock).
    pub fn new() -> io::Result<Self> {
        let lock = ExclusiveLock::acquire();
        let previous_cwd = std::env::current_dir()?;
        let temp_root = tempfile::Builder::new()
            .prefix("tirith-test-state-")
            .tempdir()?;
        let roots = IsolatedRoots::create(temp_root.path())?;
        let assignments = roots.assignments();
        let previous_env: Vec<(&'static str, Option<OsString>)> = assignments
            .iter()
            .filter(|(key, _)| !CHILD_ONLY_ISOLATED_ENV.contains(key))
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();

        // SAFETY: the guard owns GLOBAL_STATE_LOCK from the first mutation until
        // Drop has restored every key and the original cwd.
        unsafe {
            for (key, value) in assignments
                .iter()
                .filter(|(key, _)| !CHILD_ONLY_ISOLATED_ENV.contains(key))
            {
                std::env::set_var(key, value);
            }
        }

        if let Err(error) = std::env::set_current_dir(&roots.cwd) {
            restore_environment(&previous_env);
            return Err(error);
        }

        let mut child_env: Vec<(OsString, OsString)> = assignments
            .into_iter()
            .map(|(key, value)| (OsString::from(key), value.to_os_string()))
            .collect();
        for key in CHILD_PASSTHROUGH_ENV {
            if child_env
                .iter()
                .any(|(present, _)| present.as_os_str() == OsStr::new(key))
            {
                continue;
            }
            if let Some(value) = std::env::var_os(key) {
                child_env.push((OsString::from(key), value));
            }
        }

        Ok(Self {
            temp_root: Some(temp_root),
            roots,
            previous_env,
            previous_cwd,
            child_env,
            after_restore: Vec::new(),
            _lock: lock,
        })
    }

    /// All isolated roots for fixtures and assertions.
    pub fn roots(&self) -> &IsolatedRoots {
        &self.roots
    }

    /// Process cwd observed after acquiring the global-state lock and before
    /// installing the isolated cwd. Compatibility harnesses that deliberately
    /// need the caller cwd must use this value rather than sampling cwd before
    /// lock acquisition, when another test may still own a temporary cwd.
    pub fn previous_cwd(&self) -> &Path {
        &self.previous_cwd
    }

    /// Value of one standard isolated variable before this guard installed its
    /// replacement. Test fixtures that must exercise a trust boundary outside
    /// the isolated temporary roots can use this snapshot without racing a
    /// different guard's process-global mutation.
    pub fn previous_env(&self, key: &str) -> Option<&OsStr> {
        self.previous_env
            .iter()
            .find(|(present, _)| *present == key)
            .and_then(|(_, value)| value.as_deref())
    }

    /// Set an additional process variable for the guard's lifetime. The exact
    /// original `Option<OsString>` is captured only on the first mutation, and
    /// the value is also inherited by [`Self::apply_to_command`].
    pub fn set_env<V>(&mut self, key: &'static str, value: V)
    where
        V: AsRef<OsStr>,
    {
        self.remember_env(key);
        let value = value.as_ref().to_os_string();
        // SAFETY: this guard owns GLOBAL_STATE_LOCK.
        unsafe { std::env::set_var(key, &value) };
        self.child_env
            .retain(|(present, _)| present.as_os_str() != OsStr::new(key));
        self.child_env.push((OsString::from(key), value));
    }

    /// Remove a process variable for the guard's lifetime, restoring whether it
    /// was set and its exact bytes on drop. The variable is also absent from an
    /// env-cleared child.
    pub fn remove_env(&mut self, key: &'static str) {
        self.remember_env(key);
        // SAFETY: this guard owns GLOBAL_STATE_LOCK.
        unsafe { std::env::remove_var(key) };
        self.child_env
            .retain(|(present, _)| present.as_os_str() != OsStr::new(key));
    }

    /// Change the process cwd for this guard's lifetime. Drop always restores
    /// the cwd captured by [`Self::new`], including during unwinding.
    pub fn set_cwd<P>(&mut self, path: P) -> io::Result<()>
    where
        P: AsRef<Path>,
    {
        std::env::set_current_dir(path)
    }

    /// Register cleanup/verification to run after cwd and environment restore,
    /// but while the global lock is still held and the temp root still exists.
    pub fn after_restore<F>(&mut self, callback: F)
    where
        F: FnOnce() + 'static,
    {
        self.after_restore.push(Box::new(callback));
    }

    /// Apply the isolated environment to a child without inheriting ambient
    /// credentials or test-runner state. The child cwd is fixed explicitly.
    pub fn apply_to_command<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        command.env_clear();
        command.envs(self.child_env.iter().map(|(key, value)| (key, value)));
        command.current_dir(&self.roots.cwd)
    }

    fn remember_env(&mut self, key: &'static str) {
        if !self.previous_env.iter().any(|(present, _)| *present == key) {
            self.previous_env.push((key, std::env::var_os(key)));
        }
    }
}

impl Drop for GlobalStateGuard {
    fn drop(&mut self) {
        // Restore cwd first: deleting a temp tree while the process is still
        // inside it is unreliable on Unix and fails outright on Windows.
        let _ = std::env::set_current_dir(&self.previous_cwd);
        restore_environment(&self.previous_env);

        let already_panicking = std::thread::panicking();
        let mut callback_panic = None;
        for callback in self.after_restore.drain(..).rev() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback));
            if callback_panic.is_none() {
                callback_panic = result.err();
            }
        }

        // Explicitly remove the root before the lock field is released. This is
        // also after cwd restoration on every normal and unwinding drop path.
        drop(self.temp_root.take());

        if !already_panicking {
            if let Some(payload) = callback_panic {
                std::panic::resume_unwind(payload);
            }
        }
    }
}

/// Paths [`remove_at_exit`] deletes when the test process exits, with the pid
/// that registered them.
#[cfg(unix)]
static EXIT_REMOVALS: std::sync::Mutex<Vec<(u32, PathBuf)>> = std::sync::Mutex::new(Vec::new());

/// Remove `path` and everything under it when this test process exits.
///
/// Integration suites keep one hermetic root per process in a `static`
/// (`OnceLock<tempfile::TempDir>`). Rust never runs destructors for statics, so
/// that `TempDir` never deletes its directory: every run of the suite would
/// leave its whole tree (hundreds of MB for `cli_integration`) in the system
/// temp dir. Register the root here when it is created.
///
/// The removal runs from a C `atexit` handler, which libc calls both when the
/// test harness returns from `main` and when it calls `std::process::exit`
/// after a failure. It is best effort (errors are ignored) and only runs in
/// the process that registered the path, so a forked child that calls `exit`
/// cannot delete its parent's root. Unix only: elsewhere it is a no-op and the
/// root is left behind as before (that exit path has not been verified).
pub fn remove_at_exit(path: &Path) {
    #[cfg(unix)]
    {
        static REGISTER_HOOK: std::sync::Once = std::sync::Once::new();
        EXIT_REMOVALS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((std::process::id(), path.to_path_buf()));
        REGISTER_HOOK.call_once(|| {
            extern "C" {
                fn atexit(callback: extern "C" fn()) -> std::os::raw::c_int;
            }
            // SAFETY: `atexit` is the C standard library function; the callback
            // is a plain `extern "C" fn` that never unwinds.
            unsafe {
                atexit(remove_registered_paths_at_exit);
            }
        });
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(unix)]
extern "C" fn remove_registered_paths_at_exit() {
    let paths = std::mem::take(
        &mut *EXIT_REMOVALS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    let pid = std::process::id();
    for (owner, path) in paths {
        if owner == pid {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

fn restore_environment(previous: &[(&'static str, Option<OsString>)]) {
    // SAFETY: every caller owns GLOBAL_STATE_LOCK. Restore in reverse mutation
    // order and preserve Option<OsString> exactly, including non-UTF-8 values.
    unsafe {
        for (key, value) in previous.iter().rev() {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Barrier, Mutex, MutexGuard};
    use std::time::Duration;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    const CHILD_PROBE: &str = "TIRITH_TEST_SUPPORT_CHILD_PROBE";
    const EXPECTED_HOME: &str = "TIRITH_TEST_SUPPORT_EXPECTED_HOME";
    const EXPECTED_ROOT: &str = "TIRITH_TEST_SUPPORT_EXPECTED_ROOT";
    const AMBIENT_SECRET: &str = "TIRITH_TEST_SUPPORT_AMBIENT_SECRET";
    const CHILD_CUSTOM: &str = "TIRITH_TEST_SUPPORT_CHILD_CUSTOM";

    fn test_lock() -> MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn restore_one(key: &'static str, value: Option<OsString>) {
        // SAFETY: each test holds TEST_LOCK and no production consumer exists in
        // this crate's own test binary.
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn exact_set_and_unset_values_are_restored() {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStringExt as _;

        let _serial = test_lock();
        let old_home = std::env::var_os("HOME");
        let old_supplemental = std::env::var_os("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
        let old_custom = std::env::var_os(CHILD_CUSTOM);
        #[cfg(unix)]
        let sentinel = OsString::from_vec(b"tirith-test-original-home-\xff".to_vec());
        #[cfg(not(unix))]
        let sentinel = OsString::from("tirith-test-original-home");
        // SAFETY: serialized by TEST_LOCK; GlobalStateGuard takes the global
        // mutation lock before changing either key.
        unsafe {
            std::env::set_var("HOME", &sentinel);
            std::env::remove_var("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
            std::env::remove_var(CHILD_CUSTOM);
        }
        {
            let mut guard = GlobalStateGuard::new().expect("create guard");
            assert_eq!(guard.previous_env("HOME"), Some(sentinel.as_os_str()));
            guard.set_env(CHILD_CUSTOM, "temporary");
            guard.remove_env("TIRITH_THREATDB_SUPPLEMENTAL_PATH");
            assert_ne!(std::env::var_os("HOME"), Some(sentinel.clone()));
            assert_eq!(std::env::var_os(CHILD_CUSTOM), Some("temporary".into()));
            assert_eq!(std::env::var_os("TIRITH_THREATDB_SUPPLEMENTAL_PATH"), None);
            drop(guard);
        }
        assert_eq!(std::env::var_os("HOME"), Some(sentinel));
        assert_eq!(std::env::var_os("TIRITH_THREATDB_SUPPLEMENTAL_PATH"), None);
        assert_eq!(std::env::var_os(CHILD_CUSTOM), None);
        restore_one("HOME", old_home);
        restore_one("TIRITH_THREATDB_SUPPLEMENTAL_PATH", old_supplemental);
        restore_one(CHILD_CUSTOM, old_custom);
    }

    #[test]
    fn panic_restores_cwd_environment_and_removes_the_temp_root() {
        let _serial = test_lock();
        let original_cwd = std::env::current_dir().expect("original cwd");
        let original_home = std::env::var_os("HOME");
        let observed_root = Arc::new(Mutex::new(None::<PathBuf>));
        let from_unwind = Arc::clone(&observed_root);

        let result = std::panic::catch_unwind(move || {
            let guard = GlobalStateGuard::new().expect("create guard");
            *from_unwind.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(guard.roots().root.clone());
            assert_eq!(
                std::fs::canonicalize(std::env::current_dir().expect("isolated cwd"))
                    .expect("canonical isolated cwd"),
                std::fs::canonicalize(&guard.roots().cwd).expect("canonical guard cwd")
            );
            panic!("intentional unwind");
        });
        assert!(result.is_err());
        assert_eq!(std::env::current_dir().expect("restored cwd"), original_cwd);
        assert_eq!(std::env::var_os("HOME"), original_home);
        let root = observed_root
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .expect("captured root");
        assert!(
            !root.exists(),
            "temp root survived unwind: {}",
            root.display()
        );
    }

    #[test]
    fn a_poisoned_global_lock_does_not_block_later_guards() {
        let _serial = test_lock();
        let joined = std::thread::spawn(|| {
            let _lock = GLOBAL_STATE_LOCK
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("poison the global state lock");
        })
        .join();
        assert!(joined.is_err());
        let guard = GlobalStateGuard::new().expect("poison-tolerant guard");
        assert!(guard.roots().home.is_dir());
        drop(guard);
        let _shared = SharedStateGuard::acquire();
    }

    /// The isolation contract readers rely on: while a SharedStateGuard is
    /// alive, no GlobalStateGuard can install its roots, so HOME/cwd seen by a
    /// discovery-reading test cannot change underneath it.
    #[test]
    fn exclusive_guard_waits_for_every_shared_reader() {
        let _serial = test_lock();
        let home_before = std::env::var_os("HOME");
        let cwd_before = std::env::current_dir().expect("cwd");
        let shared = SharedStateGuard::acquire();

        let (installed_tx, installed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            let guard = GlobalStateGuard::new().expect("writer guard");
            installed_tx
                .send(guard.roots().home.clone())
                .expect("report install");
            release_rx.recv().expect("release writer");
            drop(guard);
        });

        // The writer must still be blocked: state the reader sees is stable.
        for _ in 0..20 {
            assert!(
                installed_rx
                    .recv_timeout(Duration::from_millis(10))
                    .is_err(),
                "GlobalStateGuard installed roots while a SharedStateGuard was alive"
            );
            assert_eq!(std::env::var_os("HOME"), home_before);
            assert_eq!(std::env::current_dir().expect("cwd"), cwd_before);
        }
        drop(shared);
        let isolated_home = installed_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("writer proceeds once the reader is gone");
        assert_eq!(std::env::var_os("HOME"), Some(isolated_home.into()));
        release_tx.send(()).expect("release");
        writer.join().expect("writer thread");
        assert_eq!(std::env::var_os("HOME"), home_before);
    }

    /// A reader that arrives while a GlobalStateGuard is alive waits for the
    /// exact prior state to be restored instead of reading the temporary roots.
    #[test]
    fn shared_reader_waits_for_exclusive_restore() {
        let _serial = test_lock();
        let home_before = std::env::var_os("HOME");
        let guard = GlobalStateGuard::new().expect("writer guard");
        let isolated_home = guard.roots().home.clone();

        let (seen_tx, seen_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let _shared = SharedStateGuard::acquire();
            seen_tx.send(std::env::var_os("HOME")).expect("report HOME");
        });
        assert!(
            seen_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "SharedStateGuard was granted while a GlobalStateGuard was alive"
        );
        assert_eq!(std::env::var_os("HOME"), Some(isolated_home.into()));
        drop(guard);
        let seen = seen_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("reader proceeds after restore");
        assert_eq!(seen, home_before, "reader observed a temporary HOME");
        reader.join().expect("reader thread");
    }

    #[test]
    fn shared_readers_run_concurrently() {
        let _serial = test_lock();
        let barrier = Arc::new(Barrier::new(2));
        let other = Arc::clone(&barrier);
        let _mine = SharedStateGuard::acquire();
        let peer = std::thread::spawn(move || {
            let _theirs = SharedStateGuard::acquire();
            // Both readers hold the lock at this rendezvous; a second
            // exclusive-style lock would hang here.
            other.wait();
        });
        barrier.wait();
        peer.join().expect("peer reader");
    }

    #[test]
    fn nested_and_under_exclusive_shared_guards_do_not_deadlock() {
        let _serial = test_lock();
        {
            let _outer = SharedStateGuard::acquire();
            let _inner = shared_global_state();
        }
        let guard = GlobalStateGuard::new().expect("writer guard");
        let home = std::env::var_os("HOME");
        {
            let _shared_under_own_writer = SharedStateGuard::acquire();
            assert_eq!(std::env::var_os("HOME"), home);
        }
        drop(guard);
        // Depth accounting returned to zero: a fresh exclusive guard works.
        drop(GlobalStateGuard::new().expect("second writer guard"));
    }

    #[test]
    fn exclusive_guard_under_a_shared_guard_panics_instead_of_deadlocking() {
        let _serial = test_lock();
        let shared = SharedStateGuard::acquire();
        let result = std::panic::catch_unwind(|| GlobalStateGuard::new().map(drop));
        assert!(result.is_err(), "nested exclusive acquisition must panic");
        drop(shared);
        drop(GlobalStateGuard::new().expect("lock is not left poisoned or held"));
    }

    #[test]
    fn sequential_guards_receive_unique_roots_and_unique_subroots() {
        let _serial = test_lock();
        let first = {
            let guard = GlobalStateGuard::new().expect("first guard");
            let root = guard.roots().root.clone();
            let subroots = [
                &guard.roots().home,
                &guard.roots().xdg_config,
                &guard.roots().xdg_data,
                &guard.roots().xdg_state,
                &guard.roots().xdg_cache,
                &guard.roots().appdata,
                &guard.roots().local_appdata,
                &guard.roots().temp,
                &guard.roots().kubernetes,
                &guard.roots().policy,
                &guard.roots().tirith_state,
                &guard.roots().cwd,
            ];
            let unique: BTreeSet<PathBuf> = subroots.iter().map(|path| (*path).clone()).collect();
            assert_eq!(unique.len(), subroots.len());
            root
        };
        let second = GlobalStateGuard::new()
            .expect("second guard")
            .roots()
            .root
            .clone();
        assert_ne!(first, second);
        assert!(!first.exists());
    }

    #[test]
    fn parent_temp_selectors_are_stable_while_children_receive_isolated_ones() {
        let _serial = test_lock();
        let before = ["TMPDIR", "TMP", "TEMP"].map(std::env::var_os);
        let guard = GlobalStateGuard::new().expect("create guard");

        assert_eq!(
            ["TMPDIR", "TMP", "TEMP"].map(std::env::var_os),
            before,
            "a guard must not redirect unrelated parent-process tempfile users"
        );
        for key in ["TMPDIR", "TMP", "TEMP"] {
            let child_value = guard
                .child_env
                .iter()
                .find(|(present, _)| present == OsStr::new(key))
                .map(|(_, value)| value)
                .expect("child receives isolated temp selector");
            assert_eq!(child_value, guard.roots().temp.as_os_str());
        }
    }

    #[test]
    fn after_restore_callbacks_observe_restored_state_before_root_cleanup() {
        let _serial = test_lock();
        let original_cwd = std::env::current_dir().expect("original cwd");
        let original_home = std::env::var_os("HOME");
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);
        let mut guard = GlobalStateGuard::new().expect("create guard");
        let root = guard.roots().root.clone();
        guard.after_restore(move || {
            assert_eq!(std::env::current_dir().expect("callback cwd"), original_cwd);
            assert_eq!(std::env::var_os("HOME"), original_home);
            assert!(root.exists(), "root was removed before restore callback");
            callback_called.store(true, Ordering::SeqCst);
        });
        drop(guard);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn child_application_clears_ambient_state_and_inherits_isolated_roots() {
        let _serial = test_lock();
        let old_secret = std::env::var_os(AMBIENT_SECRET);
        // SAFETY: serialized by TEST_LOCK. The child command is env-cleared, so
        // this sentinel must not cross the boundary.
        unsafe { std::env::set_var(AMBIENT_SECRET, "must-not-leak") };
        let mut guard = GlobalStateGuard::new().expect("create guard");
        guard.remove_env(AMBIENT_SECRET);
        guard.set_env(CHILD_CUSTOM, "inherited-custom-value");
        let mut command = Command::new(std::env::current_exe().expect("current test binary"));
        command.args(["--exact", "tests::child_environment_probe", "--nocapture"]);
        guard
            .apply_to_command(&mut command)
            .env(CHILD_PROBE, "1")
            .env(EXPECTED_HOME, &guard.roots().home);
        command.env(EXPECTED_ROOT, &guard.roots().root);
        let output = command.output().expect("run child probe");
        assert!(
            output.status.success(),
            "child probe failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        drop(guard);
        restore_one(AMBIENT_SECRET, old_secret);
    }

    #[test]
    fn child_environment_probe() {
        if std::env::var_os(CHILD_PROBE).is_none() {
            return;
        }
        assert_eq!(std::env::var_os("HOME"), std::env::var_os(EXPECTED_HOME));
        let expected_root =
            PathBuf::from(std::env::var_os(EXPECTED_ROOT).expect("parent supplied expected root"));
        let canonical_expected_root = expected_root
            .canonicalize()
            .unwrap_or_else(|_| expected_root.clone());
        for key in [
            "HOME",
            "USERPROFILE",
            "XDG_CONFIG_HOME",
            "XDG_CONFIG_DIRS",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "APPDATA",
            "LOCALAPPDATA",
            "TMPDIR",
            "TMP",
            "TEMP",
            "KUBECONFIG",
            "TIRITH_THREATDB_PATH",
            "TIRITH_THREATDB_SUPPLEMENTAL_PATH",
            "TIRITH_POLICY_ROOT",
            "TIRITH_SETUP_LOCK_ROOT",
        ] {
            let value = PathBuf::from(std::env::var_os(key).expect("isolated child variable"));
            assert!(
                value.starts_with(&expected_root),
                "{key} escaped isolated root: {}",
                value.display()
            );
        }
        let child_cwd = std::env::current_dir().expect("child cwd");
        assert!(
            child_cwd.starts_with(&expected_root)
                || child_cwd.starts_with(&canonical_expected_root),
            "child cwd escaped isolated root: {}",
            child_cwd.display()
        );
        assert_eq!(std::env::var_os(AMBIENT_SECRET), None);
        assert_eq!(
            std::env::var_os(CHILD_CUSTOM),
            Some(OsString::from("inherited-custom-value"))
        );
    }

    #[cfg(unix)]
    const EXIT_REMOVAL_ROOT: &str = "TIRITH_TEST_SUPPORT_EXIT_REMOVAL_ROOT";

    /// Child half of `registered_roots_are_removed_when_the_process_exits`:
    /// builds a tree, registers it and exits. A no-op in an ordinary run.
    #[cfg(unix)]
    #[test]
    fn exit_removal_child_probe() {
        let Some(root) = std::env::var_os(EXIT_REMOVAL_ROOT) else {
            return;
        };
        let root = PathBuf::from(root);
        std::fs::create_dir_all(root.join("nested/deeper")).expect("create tree");
        std::fs::write(root.join("nested/deeper/file"), b"left by the child").expect("write");
        remove_at_exit(&root);
        assert!(root.exists(), "registration must not remove the root early");
    }

    #[cfg(unix)]
    #[test]
    fn registered_roots_are_removed_when_the_process_exits() {
        let parent = tempfile::tempdir().expect("parent temp dir");
        let root = parent.path().join("suite-root");
        let output = Command::new(std::env::current_exe().expect("current test binary"))
            .args(["--exact", "tests::exit_removal_child_probe", "--nocapture"])
            .env(EXIT_REMOVAL_ROOT, &root)
            .output()
            .expect("run child probe");
        assert!(
            output.status.success(),
            "child probe failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "the child must have run the probe: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !root.exists(),
            "a root registered with remove_at_exit must be gone once its process exits"
        );
    }

    #[cfg(unix)]
    #[test]
    fn exit_removal_skips_roots_registered_by_another_process() {
        let _serial = test_lock();
        let parent = tempfile::tempdir().expect("parent temp dir");
        let own = parent.path().join("own");
        let foreign = parent.path().join("foreign");
        std::fs::create_dir_all(own.join("sub")).expect("own tree");
        std::fs::create_dir_all(foreign.join("sub")).expect("foreign tree");
        // Keep whatever the process has registered so far; restore it below.
        let saved = std::mem::take(
            &mut *EXIT_REMOVALS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        EXIT_REMOVALS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend([
                (std::process::id(), own.clone()),
                // What a forked child sees: an entry its parent registered.
                (std::process::id().wrapping_add(1), foreign.clone()),
            ]);
        remove_registered_paths_at_exit();
        *EXIT_REMOVALS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = saved;
        assert!(!own.exists(), "this process's root is removed");
        assert!(foreign.exists(), "another process's root is left alone");
    }
}
