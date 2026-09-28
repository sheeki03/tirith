//! Explicit native path observations; no profile installation or hook activation.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use tirith_core::trusted_child::{ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable};

const QUERY: &str = r#"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [Console]::Out.Write(([ordered]@{profile=[string]$PROFILE;current_user_current_host=[string]$PROFILE.CurrentUserCurrentHost;documents=[Environment]::GetFolderPath('MyDocuments');home=[string]$HOME;version=$PSVersionTable.PSVersion.ToString();major=$PSVersionTable.PSVersion.Major;minor=$PSVersionTable.PSVersion.Minor;edition=[string]$PSVersionTable.PSEdition;host_name=$Host.Name;executable=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName;xdg=$env:XDG_CONFIG_HOME}|ConvertTo-Json -Compress))"#;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeProfile {
    profile: PathBuf,
    current_user_current_host: PathBuf,
    documents: PathBuf,
    home: PathBuf,
    version: String,
    major: u32,
    minor: u32,
    edition: String,
    host_name: String,
    executable: PathBuf,
    xdg: Option<String>,
}

fn require(value: bool, reason: &str) -> Result<(), String> {
    value.then_some(()).ok_or_else(|| reason.into())
}

fn hash_file(path: &Path, cap: u64) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    require(
        file.metadata().map_err(|e| e.to_string())?.len() <= cap,
        "input exceeds hash bound",
    )?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut bytes = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut bytes).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        require(total <= cap, "input grew beyond hash bound")?;
        hash.update(&bytes[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn profile_state(path: &Path) -> Result<serde_json::Value, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(serde_json::json!({"exists": false}))
        }
        Err(error) => return Err(error.to_string()),
    };
    // Never follow an existing profile symlink to inspect its contents.
    let content = if metadata.file_type().is_symlink() {
        serde_json::json!({"symlink": std::fs::read_link(path).map_err(|e| e.to_string())?})
    } else if metadata.is_file() {
        serde_json::json!({"sha256": hash_file(path, 4 * 1024 * 1024)?})
    } else {
        return Err("profile target is neither a regular file nor a symlink".into());
    };
    Ok(
        serde_json::json!({"exists": true, "length": metadata.len(), "content": content,
        "modified": format!("{:?}", metadata.modified().map_err(|e| e.to_string())?),
        "permissions": format!("{:?}", metadata.permissions())}),
    )
}

fn validate_observation(
    shell: &str,
    target: &ShellTarget,
    documents: Option<&Path>,
    observed: &NativeProfile,
) -> Result<(), String> {
    require(
        target.profiles.len() == 1 && target.unsupported_reason.is_none(),
        "resolver returned an unsupported or ambiguous target",
    )?;
    require(
        observed.host_name == "ConsoleHost",
        "native host is not ConsoleHost",
    )?;
    require(
        observed.profile.is_absolute() && observed.profile == observed.current_user_current_host,
        "$PROFILE does not identify CurrentUserCurrentHost",
    )?;
    require(
        observed.profile == target.profiles[0].path,
        "native $PROFILE differs from the shared resolver",
    )?;
    require(
        observed.home == target.operator_home,
        "native home differs from the intended operator",
    )?;
    require(
        !observed.version.is_empty() && observed.version.len() <= 128,
        "native version is missing or oversized",
    )?;
    if shell == "powershell" {
        require(
            observed.major == 5 && observed.minor == 1 && observed.edition == "Desktop",
            "Windows PowerShell 5.1 Desktop is required",
        )?;
    } else {
        require(
            shell == "pwsh" && observed.major == 7 && observed.edition == "Core",
            "PowerShell 7 Core is required",
        )?;
    }
    if let Some(documents) = documents {
        require(
            documents.is_absolute() && observed.documents == documents,
            "native Documents differs from the known-folder API",
        )?;
    }
    Ok(())
}

#[test]
#[ignore = "requires an explicit native PowerShell executable and fresh evidence output"]
fn native_powershell_profile_matches_resolver() {
    let output = std::env::var_os("TIRITH_NATIVE_PROFILE_REPORT")
        .map(PathBuf::from)
        .expect("explicit native resolver evidence output is required");
    assert!(
        output.is_absolute() && !output.exists(),
        "fresh absolute report required"
    );
    let mut report = serde_json::json!({"schema_version": 1, "passed": false,
        "status": "refused", "scope": "native_current_user_console_profile_resolution_only",
        "profile_writes": false, "profile_loaded": false, "automatic_adapter_qualified": false});
    let result = (|| -> Result<(), String> {
        let test_binary = std::env::current_exe().map_err(|e| e.to_string())?;
        let test_sha = hash_file(&test_binary, 512 * 1024 * 1024)?;
        require(
            std::env::var("TIRITH_NATIVE_PROFILE_TEST_SHA256").map_err(|e| e.to_string())?
                == test_sha,
            "native test executable digest differs",
        )?;
        report["test_binary"] =
            serde_json::json!({"path": test_binary, "sha256": test_sha, "pid": std::process::id()});
        let shell = std::env::var("TIRITH_NATIVE_PROFILE_SHELL").map_err(|e| e.to_string())?;
        require(
            shell == "pwsh" || (cfg!(windows) && shell == "powershell"),
            "unsupported native shell/platform combination",
        )?;
        let path = PathBuf::from(
            std::env::var_os("TIRITH_NATIVE_PROFILE_EXECUTABLE")
                .ok_or("explicit native executable required")?,
        );
        require(path.is_absolute(), "absolute native executable required")?;
        let expected = std::env::var("TIRITH_NATIVE_PROFILE_SHA256").map_err(|e| e.to_string())?;
        require(
            expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()),
            "native executable SHA-256 required",
        )?;
        require(
            hash_file(&path, 256 * 1024 * 1024)? == expected,
            "native executable digest differs",
        )?;
        let executable = TrustedExecutable::from_absolute(&path, &[]).map_err(|e| e.to_string())?;
        let target = resolve_for_shell(&shell)?;
        #[cfg(unix)]
        require(
            target.operator_uid == Some(unsafe { libc::geteuid() }),
            "native observation must run as the intended operator without sudo",
        )?;
        let inputs = TargetInputs::current(target.operator_home.clone())?;
        require(target.profiles.len() == 1, "missing native profile target")?;
        let profile = &target.profiles[0].path;
        let before = profile_state(profile)?;
        report["shell"] = serde_json::json!(shell);
        report["target"] = serde_json::to_value(&target).map_err(|e| e.to_string())?;
        report["documents"] = serde_json::json!(inputs.documents);
        report["xdg_config"] = serde_json::json!(inputs.xdg_config);
        report["native_executable"] =
            serde_json::json!({"path": executable.path(), "sha256": expected});
        report["profile_before"] = before.clone();
        let spec = ChildSpec::new(
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                QUERY,
            ],
            ChildLimits::new(std::time::Duration::from_secs(20), 32 * 1024, 4096),
        )
        .inherit_env(&[
            "HOME",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
            "XDG_CONFIG_HOME",
            "SystemRoot",
            "WINDIR",
            "APPDATA",
            "LOCALAPPDATA",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
        ])
        .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
        .env("POWERSHELL_UPDATECHECK", "Off")
        .env(
            "PSModuleAnalysisCachePath",
            output.with_extension("module-cache"),
        )
        .cwd(output.parent().ok_or("missing output parent")?);
        let outcome = tirith_core::trusted_child::run(&executable, &spec);
        let after = profile_state(profile)?;
        report["profile_after"] = after.clone();
        report["profile_unchanged"] = serde_json::json!(before == after);
        let stdout = match outcome {
            ChildOutcome::Completed {
                status,
                stdout,
                stderr,
            } => {
                report["child"] = serde_json::json!({"outcome": "completed", "success": status.success(),
                    "stdout_bytes": stdout.len(), "stderr_bytes": stderr.len(), "supervised_cleanup_confirmed": true,
                    "stdout_sha256": format!("{:x}", Sha256::digest(&stdout)),
                    "stderr": String::from_utf8_lossy(&stderr)});
                require(status.success(), "native PowerShell query failed")?;
                stdout
            }
            other => {
                report["child"] = serde_json::json!({"outcome": format!("{other:?}")});
                return Err("native PowerShell query did not complete with proven cleanup".into());
            }
        };
        let observed: NativeProfile = serde_json::from_slice(&stdout).map_err(|e| e.to_string())?;
        report["observed"] = serde_json::to_value(&observed).map_err(|e| e.to_string())?;
        validate_observation(&shell, &target, inputs.documents.as_deref(), &observed)?;
        require(
            std::fs::canonicalize(&observed.executable).map_err(|e| e.to_string())?
                == std::fs::canonicalize(&path).map_err(|e| e.to_string())?,
            "native process executable differs",
        )?;
        require(
            observed
                .xdg
                .as_deref()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                == inputs.xdg_config,
            "native XDG environment differs",
        )?;
        executable.revalidate().map_err(|e| e.to_string())?;
        require(
            hash_file(&path, 256 * 1024 * 1024)? == expected && before == after,
            "native input or personal profile changed",
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        report["error"] = serde_json::json!(error);
    } else {
        report["passed"] = serde_json::json!(true);
        report["status"] = serde_json::json!("native_target_matched");
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .unwrap();
    serde_json::to_writer_pretty(&mut file, &report).unwrap();
    file.write_all(b"\n").unwrap();
    assert!(
        result.is_ok(),
        "native resolver qualification refused: {result:?}"
    );
}

#[test]
fn profile_and_version_mismatches_are_not_native_success() {
    let home = PathBuf::from(if cfg!(windows) {
        r"C:\fixture\user"
    } else {
        "/fixture/user"
    });
    let path = home.join(".config/powershell/Microsoft.PowerShell_profile.ps1");
    let target = ShellTarget {
        shell: "pwsh".into(),
        operator_home: home.clone(),
        operator_uid: None,
        executable: None,
        process_id: None,
        identity_source: "fixture".into(),
        version: None,
        startup_mode: "unknown".into(),
        profiles: vec![ProfileTarget {
            path: path.clone(),
            scope: home.clone(),
            startup: "console-host".into(),
        }],
        unsupported_reason: None,
    };
    let mut observed = NativeProfile {
        profile: path.clone(),
        current_user_current_host: path,
        documents: PathBuf::new(),
        home,
        version: "7.6.6".into(),
        major: 7,
        minor: 6,
        edition: "Core".into(),
        host_name: "ConsoleHost".into(),
        executable: "/fixture/pwsh".into(),
        xdg: None,
    };
    // These are parser/decision controls; only the ignored explicit probe can
    // establish a native host match.
    assert!(validate_observation("pwsh", &target, None, &observed).is_ok());
    observed.current_user_current_host = "/different/profile".into();
    assert!(validate_observation("pwsh", &target, None, &observed).is_err());
    observed.current_user_current_host = observed.profile.clone();
    observed.major = 5;
    assert!(validate_observation("pwsh", &target, None, &observed).is_err());
    observed.major = 7;
    assert!(validate_observation(
        "pwsh",
        &target,
        Some(Path::new("/redirected/Documents")),
        &observed
    )
    .is_err());
    observed.home = "/other/operator".into();
    assert!(validate_observation("pwsh", &target, None, &observed).is_err());
}
