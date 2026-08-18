//! Shared, panic-safe isolation for tests that mutate process-global state.
//!
//! A [`GlobalStateGuard`] serializes environment and current-directory changes,
//! installs fresh application roots, and restores the exact prior state on
//! drop. Child processes should be configured through
//! [`GlobalStateGuard::apply_to_command`], which starts from `env_clear()` and
//! inherits only the isolated roots plus the small platform launch allowlist.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard};

static GLOBAL_STATE_LOCK: Mutex<()> = Mutex::new(());

const CHILD_PASSTHROUGH_ENV: &[&str] = &[
    "PATH",
    // Windows needs these to launch ordinary child processes after env_clear.
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
];

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
            xdg_config: root.join("xdg-config"),
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

/// Owns the process-global test lock and restores all state even during unwind.
///
/// Construction is fallible so a missing original cwd or an unusable temp root
/// cannot turn into a half-installed environment. The mutex is poison-tolerant:
/// a previous panicking test does not cascade into every later test.
pub struct GlobalStateGuard {
    temp_root: Option<tempfile::TempDir>,
    roots: IsolatedRoots,
    previous_env: Vec<(&'static str, Option<OsString>)>,
    previous_cwd: PathBuf,
    child_env: Vec<(OsString, OsString)>,
    after_restore: Vec<RestoreCallback>,
    _lock: MutexGuard<'static, ()>,
}

impl GlobalStateGuard {
    /// Acquire the process-global lock and install a fully isolated environment
    /// plus a fresh cwd.
    pub fn new() -> io::Result<Self> {
        let lock = GLOBAL_STATE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous_cwd = std::env::current_dir()?;
        let temp_root = tempfile::Builder::new()
            .prefix("tirith-test-state-")
            .tempdir()?;
        let roots = IsolatedRoots::create(temp_root.path())?;
        let assignments = roots.assignments();
        let previous_env: Vec<(&'static str, Option<OsString>)> = assignments
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();

        // SAFETY: the guard owns GLOBAL_STATE_LOCK from the first mutation until
        // Drop has restored every key and the original cwd.
        unsafe {
            for (key, value) in &assignments {
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
    use std::sync::Arc;

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
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("poison the global state lock");
        })
        .join();
        assert!(joined.is_err());
        let guard = GlobalStateGuard::new().expect("poison-tolerant guard");
        assert!(guard.roots().home.is_dir());
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
}
