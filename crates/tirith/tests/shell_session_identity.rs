//! Fresh-hook session ownership, not interception or execution-proof tests.
//! Each fixture uses a private HOME and config-free, noninteractive shell. PATH
//! is empty so sourcing cannot start Tirith, a snapshot worker, or a service.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PARENT_SESSION: &str = "parent-multiplexer-shared-session";
const OUTPUT_CAP: u64 = 64 * 1024;

struct Startup {
    child: Child,
    pid: u32,
    root: tempfile::TempDir,
    reaped: bool,
}

impl Drop for Startup {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn shell(name: &str) -> Option<PathBuf> {
    let file = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let mut paths: Vec<_> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    paths.extend([PathBuf::from("/bin"), PathBuf::from("/usr/bin")]);
    paths
        .into_iter()
        .map(|p| p.join(&file))
        .find(|p| p.is_file())
}

fn start(binary: &Path, family: &str, hook: &Path, inherited_guard: bool) -> Startup {
    let root = tempfile::tempdir().unwrap();
    let stdout = File::create(root.path().join("stdout")).unwrap();
    let stderr = File::create(root.path().join("stderr")).unwrap();
    let (script, guard) = match family {
        "bash" | "zsh" => (
            r#"source "$1"
first=$TIRITH_SESSION_ID
source "$1"
builtin printf 'SESSION_FIRST=%s\nSESSION_SECOND=%s\nSESSION_PID=%s\n' "$first" "$TIRITH_SESSION_ID" "$$"
"#,
            if family == "bash" {
                "_TIRITH_BASH_LOADED"
            } else {
                "_TIRITH_ZSH_LOADED"
            },
        ),
        "fish" => (
            r#"source "$argv[1]"
set -l first "$TIRITH_SESSION_ID"
source "$argv[1]"
builtin printf 'SESSION_FIRST=%s\nSESSION_SECOND=%s\nSESSION_PID=%s\n' "$first" "$TIRITH_SESSION_ID" "$fish_pid"
"#,
            "_TIRITH_FISH_LOADED",
        ),
        "pwsh" => (
            r#"param([string]$Hook)
. $Hook
$first = $env:TIRITH_SESSION_ID
. $Hook
Write-Output "SESSION_FIRST=$first" "SESSION_SECOND=$env:TIRITH_SESSION_ID" "SESSION_PID=$PID"
"#,
            "_TIRITH_PS_LOADED",
        ),
        _ => unreachable!(),
    };
    let mut command = Command::new(binary);
    match family {
        "bash" => {
            command
                .args(["--noprofile", "--norc", "-c", script, "session-fixture"])
                .arg(hook);
        }
        "zsh" => {
            command
                .args(["-f", "-c", script, "session-fixture"])
                .arg(hook);
        }
        "fish" => {
            command.args(["--no-config", "-c", script]).arg(hook);
        }
        "pwsh" => {
            let file = root.path().join("session.ps1");
            fs::write(&file, script).unwrap();
            command
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
                .arg(file)
                .arg(hook);
        }
        _ => unreachable!(),
    }
    command
        .env_clear()
        .env("HOME", root.path())
        .env("USERPROFILE", root.path())
        .env("ZDOTDIR", root.path())
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env("TMPDIR", root.path())
        .env("TEMP", root.path())
        .env("TMP", root.path())
        .env("PATH", "")
        .env("TIRITH_SESSION_ID", PARENT_SESSION)
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    // Windows needs its OS installation path even in an otherwise isolated
    // environment; this is runtime location metadata, not user configuration.
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    if inherited_guard {
        command.env(guard, "1");
    }
    let child = command.spawn().expect("start native shell session fixture");
    Startup {
        pid: child.id(),
        child,
        root,
        reaped: false,
    }
}

fn read_output(path: &Path) -> String {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(OUTPUT_CAP + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() as u64 <= OUTPUT_CAP,
        "startup output exceeded its cap"
    );
    String::from_utf8(bytes).expect("startup output is UTF-8")
}

fn finish(mut startup: Startup, deadline: Instant) -> String {
    let status = loop {
        if let Some(status) = startup.child.try_wait().unwrap() {
            startup.reaped = true;
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "native shell startup deadline exceeded"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = read_output(&startup.root.path().join("stdout"));
    let stderr = read_output(&startup.root.path().join("stderr"));
    assert!(
        status.success(),
        "startup failed: {status}; stdout={stdout}; stderr={stderr}"
    );
    let mut rows = stdout.lines().filter(|line| line.starts_with("SESSION_"));
    let first = rows
        .next()
        .and_then(|line| line.strip_prefix("SESSION_FIRST="))
        .unwrap();
    let second = rows
        .next()
        .and_then(|line| line.strip_prefix("SESSION_SECOND="))
        .unwrap();
    let pid = rows
        .next()
        .and_then(|line| line.strip_prefix("SESSION_PID="))
        .unwrap();
    assert!(
        rows.next().is_none(),
        "unexpected additional session report"
    );
    assert_eq!(pid.parse::<u32>().unwrap(), startup.pid);
    assert_eq!(
        first, second,
        "genuine double-source changed the live session"
    );
    assert_ne!(
        first, PARENT_SESSION,
        "fresh source reused the inherited session"
    );
    assert!(first.len() <= 128 && first.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'));
    assert!(
        first.starts_with(&format!("{:x}-", startup.pid)),
        "ID was not generated by this shell"
    );
    first.to_owned()
}

fn check(family: &str, file: &str) {
    let Some(binary) = shell(family) else {
        eprintln!("skipping session initialization: {family} unavailable");
        return;
    };
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = crate_root.join("../../shell/lib").join(file);
    let embedded = crate_root.join("assets/shell/lib").join(file);
    assert_eq!(fs::read(&source).unwrap(), fs::read(&embedded).unwrap());
    // Eight concurrently live children receive one multiplexer-style ID.
    // Both installed-byte copies and inherited load-marker cases participate.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut starts = Vec::new();
    for hook in [&source, &embedded] {
        for inherited_guard in [false, true] {
            for _ in 0..2 {
                starts.push(start(&binary, family, hook, inherited_guard));
            }
        }
    }
    let identities: HashSet<_> = starts
        .into_iter()
        .map(|child| finish(child, deadline))
        .collect();
    assert_eq!(identities.len(), 8, "concurrent shells shared a session ID");
}

#[cfg(unix)]
#[test]
fn bash_fresh_hook_session_is_independent_and_double_source_is_stable() {
    check("bash", "bash-hook.bash");
}

#[cfg(unix)]
#[test]
fn zsh_fresh_hook_session_is_independent_and_double_source_is_stable() {
    check("zsh", "zsh-hook.zsh");
}

#[cfg(unix)]
#[test]
fn fish_fresh_hook_session_is_independent_and_double_source_is_stable() {
    check("fish", "fish-hook.fish");
}

#[test]
fn powershell_fresh_hook_session_is_independent_and_double_source_is_stable() {
    check("pwsh", "powershell-hook.ps1");
}
