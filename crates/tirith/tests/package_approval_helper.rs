//! The shipped `tirith-package-approval-authority` helper stays in the release
//! packages (installers and self-update install it at fixed paths), but
//! `tirith pkg approve` refuses with `private_input_execution_unqualified` and
//! nothing redeems an approval. The helper therefore must not create an
//! authority key or sign an approval on any platform or for any operation.

use std::io::Write as _;
use std::process::{Command, Stdio};

const HELPER: &str = env!("CARGO_BIN_EXE_tirith-package-approval-authority");

#[test]
fn helper_refuses_every_operation_and_issues_no_approval() {
    let operations: [&[&str]; 5] = [
        &[],
        &["issue"],
        &["auth-probe"],
        &["--help"],
        &["issue", "extra"],
    ];
    for args in operations {
        let mut child = Command::new(HELPER)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the package approval helper");
        // The helper may exit before reading; a broken pipe here is expected.
        let _ = child
            .stdin
            .take()
            .expect("helper stdin")
            .write_all(br#"{"digest":{}}"#);
        let output = child.wait_with_output().expect("wait for the helper");
        let stderr = String::from_utf8(output.stderr).expect("utf-8 stderr");
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?} printed to stdout");
        assert!(
            stderr.starts_with("tirith-package-approval-authority: blocked_native: "),
            "{args:?}: {stderr}"
        );
        assert!(
            stderr.contains("private_input_execution_unqualified"),
            "{args:?}: {stderr}"
        );
        assert!(stderr.contains("issues no approvals"), "{args:?}: {stderr}");
        assert_eq!(stderr.lines().count(), 1, "{args:?}: {stderr}");
    }
}

/// Installer and distribution post-install messages must not recommend a
/// privileged helper install "if you need package approval": approve refuses in
/// every state, so the helper and sudo enable nothing.
#[test]
fn installer_messages_do_not_promise_package_approval() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for relative in [
        "scripts/install.sh",
        "packaging/aur/tirith.install",
        "packaging/rpm/tirith.spec",
    ] {
        let text = std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|error| panic!("read {relative}: {error}"));
        for stale in [
            "Only if you need package approval",
            "issuing approvals needs sudo",
            "needs trusted sudo and fresh administrator confirmation",
            "Missing sudo affects that approval flow",
        ] {
            assert!(!text.contains(stale), "{relative} still says {stale:?}");
        }
        assert!(
            text.contains("tirith pkg approve") && text.contains("issues no approvals"),
            "{relative} must say that tirith pkg approve issues no approvals"
        );
    }
}
