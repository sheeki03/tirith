//! Shared personal shell targets. Discovery is not evidence of live interception.
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Platform {
    Unix,
    Macos,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ProfileTarget {
    pub path: PathBuf,
    /// The explicitly selected configuration root, for scoped transactions.
    pub scope: PathBuf,
    pub startup: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ShellTarget {
    pub shell: String,
    pub operator_home: PathBuf,
    pub operator_uid: Option<u32>,
    pub executable: Option<PathBuf>,
    pub process_id: Option<u32>,
    pub identity_source: String,
    /// Unknown until measured against this executable, never inferred from its name.
    pub version: Option<String>,
    pub startup_mode: String,
    pub profiles: Vec<ProfileTarget>,
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct TargetInputs {
    pub platform: Platform,
    pub home: PathBuf,
    pub xdg_config: Option<PathBuf>,
    pub zdotdir: Option<PathBuf>,
    pub appdata: Option<PathBuf>,
    pub documents: Option<PathBuf>,
}

fn absolute_root(value: Option<PathBuf>, name: &str) -> Result<Option<PathBuf>, String> {
    value
        .map(|path| {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                Err(format!(
                    "{name} must be an absolute path without parent traversal"
                ))
            } else {
                Ok(path)
            }
        })
        .transpose()
}

impl TargetInputs {
    pub(crate) fn current(home: PathBuf) -> Result<Self, String> {
        let env_path = |key| {
            std::env::var_os(key)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Ok(Self {
            platform: if cfg!(windows) {
                Platform::Windows
            } else if cfg!(target_os = "macos") {
                Platform::Macos
            } else {
                Platform::Unix
            },
            home,
            xdg_config: absolute_root(env_path("XDG_CONFIG_HOME"), "XDG_CONFIG_HOME")?,
            zdotdir: absolute_root(env_path("ZDOTDIR"), "ZDOTDIR")?,
            appdata: absolute_root(env_path("APPDATA"), "APPDATA")?,
            documents: native_documents(),
        })
    }
}

/// Respect native Documents redirection (including OneDrive); do not infer it
/// from USERPROFILE. On Unix the field is unused.
#[cfg(windows)]
fn native_documents() -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_Documents, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    // SAFETY: the known-folder API allocates a NUL-terminated string with COM's allocator.
    unsafe {
        let value = SHGetKnownFolderPath(&FOLDERID_Documents, KF_FLAG_DEFAULT, None).ok()?;
        let path = value.to_string().ok().map(PathBuf::from);
        CoTaskMemFree(Some(value.0.cast()));
        path
    }
}

#[cfg(not(windows))]
fn native_documents() -> Option<PathBuf> {
    None
}

/// Resolve startup paths with an injected existence check, so native platform
/// contracts can be exercised without pretending to have executed those hosts.
pub(crate) fn profiles_for(
    shell: &str,
    input: &TargetInputs,
    mut exists: impl FnMut(&Path) -> Result<bool, String>,
) -> Result<Vec<ProfileTarget>, String> {
    // Native Windows Bash names can be WSL launchers, whose Unix home/config
    // cannot be inferred from USERPROFILE. Keep those manual environments intact.
    if input.platform == Platform::Windows && matches!(shell, "bash" | "zsh" | "fish") {
        return Ok(Vec::new());
    }
    let home = &input.home;
    let xdg = input
        .xdg_config
        .clone()
        .unwrap_or_else(|| home.join(".config"));
    let target = |root: &Path, suffix: &str, startup: &str| ProfileTarget {
        path: root.join(suffix),
        scope: if root.starts_with(home) {
            home.clone()
        } else {
            root.to_path_buf()
        },
        startup: startup.into(),
    };
    Ok(match shell {
        "zsh" => vec![target(
            input.zdotdir.as_deref().unwrap_or(home),
            ".zshrc",
            "interactive",
        )],
        "bash" => {
            // Login Bash loads only the first existing profile, whereas a
            // non-login interactive Bash reads .bashrc. Configure both routes.
            let mut login = ".bash_profile";
            for name in [".bash_profile", ".bash_login", ".profile"] {
                if exists(&home.join(name))? {
                    login = name;
                    break;
                }
            }
            vec![
                target(home, ".bashrc", "interactive-non-login"),
                target(home, login, "interactive-login"),
            ]
        }
        "fish" => vec![target(&xdg, "fish/config.fish", "interactive")],
        "nu" | "nushell" => {
            let root = input
                .xdg_config
                .clone()
                .unwrap_or_else(|| match input.platform {
                    Platform::Macos => home.join("Library/Application Support"),
                    Platform::Windows => input
                        .appdata
                        .clone()
                        .unwrap_or_else(|| home.join("AppData/Roaming")),
                    Platform::Unix => home.join(".config"),
                });
            vec![target(&root, "nushell/config.nu", "interactive")]
        }
        "powershell" | "pwsh" => {
            let root = if input.platform == Platform::Windows {
                let docs = input.documents.as_ref().ok_or("native Documents directory is unavailable; use $PROFILE for manual PowerShell setup")?;
                docs.join(if shell == "powershell" {
                    "WindowsPowerShell"
                } else {
                    "PowerShell"
                })
            } else {
                xdg.join("powershell")
            };
            vec![target(
                &root,
                "Microsoft.PowerShell_profile.ps1",
                "console-host",
            )]
        }
        _ => Vec::new(),
    })
}

/// HOME is honored for an ordinary user. Under sudo, read the intended user's
/// home from the account database, not root's HOME or caller supplied SUDO_USER.
pub(crate) fn operator_home() -> Result<(PathBuf, Option<u32>), String> {
    #[cfg(unix)]
    {
        let effective = unsafe { libc::geteuid() };
        if effective == 0 {
            if let Some(uid) = std::env::var_os("SUDO_UID") {
                let uid = uid
                    .to_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .ok_or("invalid SUDO_UID")?;
                if uid != 0 {
                    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
                    let mut result = std::ptr::null_mut();
                    let mut buffer = vec![0u8; 64 * 1024];
                    // SAFETY: all pointers are valid for the call and the returned
                    // C string lives in buffer until copied below.
                    let rc = unsafe {
                        libc::getpwuid_r(
                            uid,
                            &mut entry,
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                            &mut result,
                        )
                    };
                    if rc != 0 || result.is_null() || entry.pw_dir.is_null() {
                        return Err("cannot resolve sudo operator home".into());
                    }
                    use std::os::unix::ffi::OsStrExt;
                    let home = unsafe { std::ffi::CStr::from_ptr(entry.pw_dir) }.to_bytes();
                    return Ok((PathBuf::from(std::ffi::OsStr::from_bytes(home)), Some(uid)));
                }
            }
        }
        home::home_dir()
            .map(|home| (home, Some(effective)))
            .ok_or_else(|| "could not determine operator home".into())
    }
    #[cfg(not(unix))]
    home::home_dir()
        .map(|home| (home, None))
        .ok_or_else(|| "could not determine operator home".into())
}

pub(crate) fn require_personal_writer(target: &ShellTarget) -> Result<(), String> {
    #[cfg(unix)]
    if target
        .operator_uid
        .is_some_and(|uid| uid != unsafe { libc::geteuid() })
    {
        return Err("personal shell setup must run as the intended user without sudo; privileged installation must not create root-owned personal files".into());
    }
    #[cfg(not(unix))]
    let _ = target;
    Ok(())
}

pub(crate) fn resolve_for_shell(shell: &str) -> Result<ShellTarget, String> {
    let (home, uid) = operator_home()?;
    let inputs = TargetInputs::current(home.clone())?;
    let profiles = profiles_for(shell, &inputs, |path| {
        match std::fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!(
                "cannot inspect shell startup file {}: {e}",
                path.display()
            )),
        }
    })?;
    Ok(ShellTarget {
        shell: shell.into(),
        operator_home: home,
        operator_uid: uid,
        executable: None,
        process_id: None,
        identity_source: "requested-shell-family".into(),
        version: None,
        startup_mode: "unknown".into(),
        unsupported_reason: profiles
            .is_empty()
            .then(|| "unsupported shell; preserve manual setup".into()),
        profiles,
    })
}

pub(crate) fn resolve_current() -> Result<ShellTarget, String> {
    let identity = super::init::detect_shell_identity();
    let mut target = resolve_for_shell(identity.shell)?;
    target.executable = identity.executable;
    target.process_id = identity.process_id;
    target.identity_source = identity.source.into();
    target.startup_mode = identity.startup_mode.into();
    qualify_startup(&mut target);
    Ok(target)
}

/// Explicit inspection may measure a version, unlike prompt/poll discovery.
/// Only the observed ancestor executable is run, with a sanitized environment,
/// output limits and a deadline. Missing provenance stays unknown.
pub(crate) fn inspect_current() -> Result<ShellTarget, String> {
    use tirith_core::trusted_child::{ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable};
    let mut target = resolve_current()?;
    if target.identity_source != "observed-ancestor-process" {
        return Ok(target);
    }
    if let Some(path) = &target.executable {
        if let Ok(executable) = TrustedExecutable::from_absolute(path, &[]) {
            let args = if matches!(target.shell.as_str(), "powershell" | "pwsh") {
                vec![
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "$PSVersionTable.PSVersion.ToString()",
                ]
            } else {
                vec!["--version"]
            };
            let spec = ChildSpec::new(
                args,
                ChildLimits::new(std::time::Duration::from_secs(2), 4096, 4096),
            );
            if let ChildOutcome::Completed { status, stdout, .. } =
                tirith_core::trusted_child::run(&executable, &spec)
            {
                if status.success() {
                    target.version = String::from_utf8(stdout).ok().and_then(|s| {
                        s.lines()
                            .next()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                    });
                }
            }
            #[cfg(windows)]
            if matches!(target.shell.as_str(), "powershell" | "pwsh") {
                observe_windows_startup(&mut target, &executable);
            }
        }
    }
    qualify_startup(&mut target);
    Ok(target)
}

fn qualify_startup(target: &mut ShellTarget) {
    if matches!(
        target.startup_mode.as_str(),
        "custom-profile" | "no-profile"
    ) {
        target.unsupported_reason = Some(format!("{} uses {} startup; preserve this custom session and configure its intended profile manually with tirith init --shell {}", target.shell, target.startup_mode, target.shell));
    }
}

#[cfg(windows)]
fn observe_windows_startup(
    target: &mut ShellTarget,
    executable: &tirith_core::trusted_child::TrustedExecutable,
) {
    use tirith_core::trusted_child::{ChildLimits, ChildOutcome, ChildSpec};
    let Some(pid) = target.process_id else {
        return;
    };
    // Query only the already-observed ancestor. Its command line is kept
    // private, parsed for startup switches, then discarded.
    let script = format!("$p = Get-CimInstance -ClassName Win32_Process -Filter 'ProcessId = {pid}' -ErrorAction Stop; [Console]::Out.Write($p.CommandLine)");
    let spec = ChildSpec::new(
        [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ],
        ChildLimits::new(std::time::Duration::from_secs(2), 16 * 1024, 1024),
    );
    let ChildOutcome::Completed { status, stdout, .. } =
        tirith_core::trusted_child::run(executable, &spec)
    else {
        return;
    };
    if !status.success() {
        return;
    }
    let Ok(command) = String::from_utf8(stdout) else {
        return;
    };
    let encoded: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();
    let mut count = 0;
    // SAFETY: input is NUL-terminated; CommandLineToArgvW owns the returned
    // array until LocalFree, and each string is copied before freeing it.
    unsafe {
        let args = windows::Win32::UI::Shell::CommandLineToArgvW(
            windows::core::PCWSTR(encoded.as_ptr()),
            &mut count,
        );
        if args.is_null() {
            return;
        }
        let parsed: Option<Vec<String>> = std::slice::from_raw_parts(args, count.max(0) as usize)
            .iter()
            .map(|arg| arg.to_string().ok())
            .collect();
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            args.cast(),
        )));
        if let Some(parsed) = parsed {
            target.startup_mode =
                super::init::startup_mode_from_args(&target.shell, &parsed).into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn inputs(platform: Platform) -> TargetInputs {
        TargetInputs {
            platform,
            home: "/fixture/user".into(),
            xdg_config: None,
            zdotdir: None,
            appdata: Some("/fixture/Roaming".into()),
            documents: Some("/fixture/OneDrive/Documents".into()),
        }
    }
    #[test]
    fn bash_login_and_nonlogin_are_distinct_and_priority_is_exact() {
        let input = inputs(Platform::Unix);
        let paths = profiles_for("bash", &input, |p| {
            Ok(p.ends_with(".bash_login") || p.ends_with(".profile"))
        })
        .unwrap();
        assert!(paths[0].path.ends_with(".bashrc"));
        assert!(paths[1].path.ends_with(".bash_login"));
        let changed = profiles_for("bash", &input, |_| Ok(true)).unwrap();
        assert!(changed[1].path.ends_with(".bash_profile"));
    }
    #[test]
    fn custom_roots_are_shared_by_every_consumer() {
        let mut input = inputs(Platform::Unix);
        input.xdg_config = Some("/custom/config".into());
        input.zdotdir = Some("/custom/zsh".into());
        for (shell, expected) in [
            ("zsh", "/custom/zsh/.zshrc"),
            ("fish", "/custom/config/fish/config.fish"),
            ("nushell", "/custom/config/nushell/config.nu"),
            (
                "pwsh",
                "/custom/config/powershell/Microsoft.PowerShell_profile.ps1",
            ),
        ] {
            assert_eq!(
                profiles_for(shell, &input, |_| Ok(false)).unwrap()[0].path,
                Path::new(expected)
            );
        }
    }
    #[test]
    fn native_powershell_variants_and_redirected_documents_remain_separate() {
        let input = inputs(Platform::Windows);
        let legacy = profiles_for("powershell", &input, |_| Ok(false)).unwrap();
        let modern = profiles_for("pwsh", &input, |_| Ok(false)).unwrap();
        assert_eq!(
            legacy[0].path,
            Path::new(
                "/fixture/OneDrive/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"
            )
        );
        assert_eq!(
            modern[0].path,
            Path::new("/fixture/OneDrive/Documents/PowerShell/Microsoft.PowerShell_profile.ps1")
        );
        assert_ne!(legacy[0].path, modern[0].path);
    }
    #[test]
    fn nushell_uses_platform_native_config_before_xdg_override() {
        for (platform, expected) in [
            (Platform::Unix, "/fixture/user/.config/nushell/config.nu"),
            (
                Platform::Macos,
                "/fixture/user/Library/Application Support/nushell/config.nu",
            ),
            (Platform::Windows, "/fixture/Roaming/nushell/config.nu"),
        ] {
            assert_eq!(
                profiles_for("nushell", &inputs(platform), |_| Ok(false)).unwrap()[0].path,
                Path::new(expected)
            );
        }
    }
    #[test]
    fn unsupported_shell_is_never_given_a_default_bash_target() {
        assert!(
            profiles_for("unknown", &inputs(Platform::Unix), |_| Ok(false))
                .unwrap()
                .is_empty()
        );
        assert!(absolute_root(Some("relative/root".into()), "XDG_CONFIG_HOME").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn native_windows_drive_and_redirected_unc_profile_paths() {
        let input = TargetInputs {
            platform: Platform::Windows,
            home: r"C:\Users\Operator".into(),
            xdg_config: None,
            zdotdir: None,
            appdata: Some(r"C:\Users\Operator\AppData\Roaming".into()),
            documents: Some(r"\\profile-server\users\Operator\Documents".into()),
        };
        let powershell = profiles_for("powershell", &input, |_| Ok(false)).unwrap();
        let pwsh = profiles_for("pwsh", &input, |_| Ok(false)).unwrap();
        assert!(powershell[0].path.is_absolute());
        assert_eq!(
            powershell[0].path,
            PathBuf::from(
                r"\\profile-server\users\Operator\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
            )
        );
        assert_eq!(
            pwsh[0].path,
            PathBuf::from(
                r"\\profile-server\users\Operator\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
            )
        );
        assert_eq!(
            profiles_for("nushell", &input, |_| Ok(false)).unwrap()[0].path,
            PathBuf::from(r"C:\Users\Operator\AppData\Roaming\nushell\config.nu")
        );
        assert!(profiles_for("bash", &input, |_| Ok(false))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unsupported_startup_modes_preserve_manual_activation() {
        let mut target = ShellTarget {
            shell: "bash".into(),
            operator_home: "/fixture".into(),
            operator_uid: None,
            executable: Some("/bin/bash".into()),
            process_id: Some(123),
            identity_source: "observed-ancestor-process".into(),
            version: Some("5.3".into()),
            startup_mode: "custom-profile".into(),
            profiles: vec![],
            unsupported_reason: None,
        };
        qualify_startup(&mut target);
        assert!(target
            .unsupported_reason
            .as_ref()
            .unwrap()
            .contains("manually"));
        target.startup_mode = "no-profile".into();
        qualify_startup(&mut target);
        assert!(target
            .unsupported_reason
            .as_ref()
            .unwrap()
            .contains("no-profile"));
    }
}
