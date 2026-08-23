//! C18 integration tests for the top-level `tirith attest` namespace.
//!
//! In its own file rather than appended to `cli_integration.rs`: every test
//! assembles a source and output tree on disk, and the exit-code contract, the
//! self-exclusion of the receipt destination, and the "this is not `pkg attest`"
//! boundary are the point of the slice, so they should be findable.
//!
//! # Sandbox layout
//!
//! ```text
//! <CARGO_TARGET_TMPDIR>/attest-c18/<pid>-<n>/
//!   .git/                a real containing repository with an empty commit
//!   project/src/...      the source tree
//!   project/dist/...     the output tree
//! ```
//!
//! The fixture owns its containing repository rather than assuming
//! `CARGO_TARGET_TMPDIR` lives under tirith's checkout. Git therefore resolves a
//! real HEAD from `project/`, and the receipt records it honestly through
//! `source_is_repository_root: false`, which the build test pins.
//!
//! Nothing is written outside `CARGO_TARGET_TMPDIR`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn tirith() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tirith"))
}

struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("attest-c18")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        // A previous run of the same pid slot must not leak into this one.
        let _ = fs::remove_dir_all(&root);
        for relative in ["project/src", "project/dist"] {
            fs::create_dir_all(root.join(relative)).expect("create sandbox directory");
        }
        fs::create_dir_all(root.join("config")).expect("create the isolated config directory");
        let sandbox = Self { root };
        sandbox.write("src/main.rs", "fn main() {}\n");
        sandbox.write("src/lib.rs", "pub fn hello() {}\n");
        sandbox.write("dist/index.html", "<html>built</html>\n");
        sandbox.write("dist/app.js", "console.log(1)\n");
        sandbox.initialize_containing_repository();
        sandbox
    }

    fn initialize_containing_repository(&self) {
        let initialized = Command::new("git")
            .args(["init", "--quiet"])
            .arg(&self.root)
            .status()
            .expect("run git init for the fixture");
        assert!(initialized.success(), "initialize fixture repository");

        let committed = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args([
                "-c",
                "user.name=Tirith Test",
                "-c",
                "user.email=tirith@example.invalid",
                "commit",
                "--allow-empty",
                "--quiet",
                "-m",
                "fixture root",
            ])
            .status()
            .expect("create fixture commit");
        assert!(committed.success(), "create fixture repository commit");
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    /// Where `Policy::config_dir()` resolves for a subprocess of this sandbox.
    ///
    /// Pinned so the signature rules are decided by what THIS sandbox contains
    /// rather than by whether the developer or the CI runner happens to have an
    /// audit key installed. `XDG_CONFIG_HOME` covers unix; `APPDATA` and
    /// `LOCALAPPDATA` cover Windows, where etcetera ignores the XDG variables.
    fn config(&self) -> PathBuf {
        self.root.join("config")
    }

    /// Put a real ed25519 keypair in the sandbox's config directory, so the
    /// subprocess is an installation that SIGNS its receipts and can check them.
    fn install_audit_key(&self) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
        let directory = self.config().join("tirith");
        fs::create_dir_all(&directory).expect("create the config directory");
        let private = directory.join("audit-signing.key");
        fs::write(&private, key.to_bytes()).expect("write the signing key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // The key reader refuses a group or other readable private key.
            fs::set_permissions(&private, fs::Permissions::from_mode(0o600))
                .expect("chmod the signing key");
        }
        fs::write(
            directory.join("audit-signing.pub"),
            key.verifying_key().to_bytes(),
        )
        .expect("write the verifying key");
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.project().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write fixture");
    }

    /// Run `tirith attest ...` with the project as the working directory.
    fn attest(&self, args: &[&str]) -> std::process::Output {
        tirith()
            .arg("attest")
            .args(args)
            .current_dir(self.project())
            .env("TIRITH_LOG", "0")
            .env("XDG_CONFIG_HOME", self.config())
            .env("APPDATA", self.config())
            .env("LOCALAPPDATA", self.config())
            .output()
            .expect("run tirith attest")
    }

    fn read_receipt(&self, name: &str) -> serde_json::Value {
        self.receipt_json(name)
    }

    fn write_receipt(&self, name: &str, receipt: &serde_json::Value) {
        fs::write(
            self.project().join(name),
            serde_json::to_string_pretty(receipt).expect("serialize"),
        )
        .expect("write the edited receipt");
    }

    fn receipt_json(&self, name: &str) -> serde_json::Value {
        let text = fs::read_to_string(self.project().join(name)).expect("read receipt");
        serde_json::from_str(&text).expect("the receipt is valid JSON")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn code(output: &std::process::Output) -> i32 {
    output.status.code().expect("the process exited normally")
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

// ---------------------------------------------------------------------------
// build
// ---------------------------------------------------------------------------

#[test]
fn attest_build_binds_both_trees_and_exits_clean() {
    let sandbox = Sandbox::new();
    let output = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    let receipt = sandbox.receipt_json("build.receipt.json");
    assert_eq!(receipt["receipt_type"], "attest_build");
    assert_eq!(receipt["status"], "clean");
    assert_eq!(receipt["subject"]["source_tree"]["file_count"], 2);
    assert_eq!(receipt["subject"]["output_tree"]["file_count"], 2);
    assert_eq!(
        receipt["subject"]["output_files"].as_array().unwrap().len(),
        2
    );
    assert_eq!(receipt["coverage"]["audit_chain_anchored"], false);
    assert_eq!(receipt["evidence"]["execution"]["verdict"], "observed");
    // The sandbox sits inside this repository, so when trusted git is
    // available it answers with tirith's own HEAD. That commit must be
    // labelled as describing a containing repository, not the digested tree.
    if !receipt["subject"]["git"]["commit"].is_null() {
        assert_eq!(
            receipt["subject"]["git"]["source_is_repository_root"], false,
            "a commit taken from a containing repository must be labelled as such"
        );
    }
    // The honesty caveats are part of the document, not only of the rendering.
    let caveats = receipt["caveats"].as_array().expect("caveats");
    assert!(caveats.iter().any(|caveat| caveat
        .as_str()
        .unwrap_or_default()
        .contains("not a reproducible-build claim")));
}

#[test]
fn the_receipt_destination_is_excluded_from_its_own_source_digest() {
    let sandbox = Sandbox::new();
    let first = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&first), 0, "{}", stderr(&first));
    let before = sandbox.receipt_json("build.receipt.json")["subject"]["source_tree"]["digest"]
        .as_str()
        .expect("digest")
        .to_string();

    // The receipt now exists in the source tree. A second run must produce the
    // same source digest, which is only true if the destination is excluded.
    let second = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&second), 0, "{}", stderr(&second));
    let after = sandbox.receipt_json("build.receipt.json")["subject"]["source_tree"]["digest"]
        .as_str()
        .expect("digest")
        .to_string();
    assert_eq!(
        before, after,
        "a receipt written under the source tree must not hash itself into existence"
    );
}

#[cfg(unix)]
#[test]
fn the_receipt_is_written_atomically_at_mode_0600() {
    use std::os::unix::fs::PermissionsExt as _;

    let sandbox = Sandbox::new();
    let output = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    let mode = fs::metadata(sandbox.project().join("build.receipt.json"))
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "a receipt is owner-only");
}

#[cfg(unix)]
#[test]
fn a_symlinked_receipt_destination_is_replaced_and_never_followed() {
    let sandbox = Sandbox::new();
    let victim = sandbox.project().join("victim.txt");
    fs::write(&victim, "do not overwrite me\n").expect("write victim");
    let destination = sandbox.project().join("planted.receipt.json");
    std::os::unix::fs::symlink(&victim, &destination).expect("symlink");

    let output = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "planted.receipt.json",
    ]);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert_eq!(
        fs::read_to_string(&victim).expect("read victim"),
        "do not overwrite me\n",
        "the write must never follow a planted symlink onto another file"
    );
    assert!(
        !fs::symlink_metadata(&destination)
            .expect("stat")
            .file_type()
            .is_symlink(),
        "the atomic rename replaces the link itself"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_in_the_source_tree_makes_the_receipt_partial_not_clean() {
    let sandbox = Sandbox::new();
    std::os::unix::fs::symlink(
        sandbox.project().join("src/main.rs"),
        sandbox.project().join("src/alias.rs"),
    )
    .expect("symlink");

    let output = sandbox.attest(&[
        "build", "--source", ".", "--output", "dist", "--format", "json",
    ]);
    assert_eq!(
        code(&output),
        3,
        "a tree that could not be bound is partial: {}",
        stderr(&output)
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the JSON envelope parses");
    assert_eq!(receipt["status"], "partial");
    assert_eq!(receipt["coverage"]["source_scanned"], false);
    assert!(receipt["coverage"]["scan_refusal"]
        .as_str()
        .expect("a refusal names itself")
        .contains("symlink"));
}

#[test]
fn a_source_that_is_not_a_directory_is_a_usage_error() {
    let sandbox = Sandbox::new();
    let output = sandbox.attest(&["build", "--source", "src/main.rs", "--output", "dist"]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("is not a directory"));

    let missing = sandbox.attest(&["build", "--source", ".", "--output", "nope"]);
    assert_eq!(code(&missing), 2);
}

#[test]
fn an_unreadable_execution_receipt_path_is_a_usage_error() {
    let sandbox = Sandbox::new();
    let output = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--execution-receipt",
        "no-such-receipt.json",
    ]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("--execution-receipt"));
}

// ---------------------------------------------------------------------------
// verify-build
// ---------------------------------------------------------------------------

#[test]
fn verify_build_walks_the_clean_mismatch_partial_exit_codes() {
    let sandbox = Sandbox::new();
    let built = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&built), 0, "{}", stderr(&built));

    let clean = sandbox.attest(&[
        "verify-build",
        "build.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));

    // A --output that does not exist is an INPUT error, not a finding about a
    // tree: there is nothing to compare and nothing to report about.
    let partial = sandbox.attest(&[
        "verify-build",
        "build.receipt.json",
        "--source",
        ".",
        "--output",
        "dist2",
    ]);
    assert_eq!(code(&partial), 2, "a missing --output is a usage error");

    fs::remove_file(sandbox.project().join("dist/app.js")).expect("remove");
    let mismatch = sandbox.attest(&[
        "verify-build",
        "build.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(code(&mismatch), 1, "{}", stderr(&mismatch));
    assert!(stderr(&mismatch).contains("output tree no longer matches"));
}

#[test]
fn verify_build_refuses_a_file_that_is_not_a_build_receipt() {
    let sandbox = Sandbox::new();
    sandbox.write("not-a-receipt.json", "{\"hello\": true}\n");
    let output = sandbox.attest(&[
        "verify-build",
        "not-a-receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("is not a build receipt"));
}

#[test]
fn verify_build_reports_a_tampered_receipt_as_a_mismatch() {
    let sandbox = Sandbox::new();
    let built = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&built), 0, "{}", stderr(&built));

    // Edit one field without re-stamping the content address, which is what an
    // operator hand-editing a receipt would produce.
    let path = sandbox.project().join("build.receipt.json");
    let mut receipt: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("parse");
    receipt["subject"]["argv_len"] = serde_json::json!(99);
    fs::write(
        &path,
        serde_json::to_string_pretty(&receipt).expect("serialize"),
    )
    .expect("write");

    let output = sandbox.attest(&[
        "verify-build",
        "build.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("receipt_id does not match"));
}

#[test]
fn verify_build_refuses_a_receipt_carrying_a_fabricated_signature() {
    let sandbox = Sandbox::new();
    sandbox.install_audit_key();
    let built = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&built), 0, "{}", stderr(&built));
    let honest = sandbox.read_receipt("build.receipt.json");
    assert_eq!(
        honest["signature_present"], true,
        "the sandbox installs a signing key, so the receipt must be signed"
    );

    let clean = sandbox.attest(&[
        "verify-build",
        "build.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(code(&clean), 0, "{}", stderr(&clean));
    assert!(stderr(&clean).contains("verified against the installed audit key"));

    // Swap the signature for a junk string and recompute the content address the
    // way anyone with write access to the file can. The forgery must not read as
    // the more trustworthy document.
    let mut forged = honest.clone();
    forged["signature"] = serde_json::json!("AAAA-not-a-real-ed25519-signature");
    sandbox.write_receipt("forged.receipt.json", &forged);
    let restamp = sandbox.attest(&[
        "verify-build",
        "forged.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(
        code(&restamp),
        1,
        "a forged signature is a mismatch: {}",
        stderr(&restamp)
    );
    assert!(
        stderr(&restamp).contains("REJECTED"),
        "the answer must say the signature was rejected: {}",
        stderr(&restamp)
    );

    // Stripping the signature entirely is the cheapest forgery of all, and on a
    // signing installation it is refused rather than reported as unsigned.
    let mut stripped = honest;
    stripped["signature"] = serde_json::Value::Null;
    sandbox.write_receipt("stripped.receipt.json", &stripped);
    let output = sandbox.attest(&[
        "verify-build",
        "stripped.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
}

#[test]
fn a_receipt_id_that_is_not_ascii_reports_a_verdict_instead_of_panicking() {
    let sandbox = Sandbox::new();
    let built = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&built), 0, "{}", stderr(&built));

    // Fifteen ASCII bytes then a two-byte scalar spanning bytes 15..17, so a
    // naive 16-byte slice lands inside it. verify-build loads the receipt
    // WITHOUT validating on purpose, so this value reaches the renderer.
    let mut receipt = sandbox.read_receipt("build.receipt.json");
    receipt["receipt_id"] = serde_json::json!(format!("0123456789abcde{}ffff", '\u{00e9}'));
    sandbox.write_receipt("panic.receipt.json", &receipt);

    let output = sandbox.attest(&[
        "verify-build",
        "panic.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(
        code(&output),
        1,
        "a receipt that fails its own rules is a documented mismatch, not exit 101: {}",
        stderr(&output)
    );
    assert!(
        !stderr(&output).contains("panicked"),
        "no panic may reach an operator: {}",
        stderr(&output)
    );
}

#[test]
fn a_receipt_written_inside_the_output_tree_still_verifies() {
    let sandbox = Sandbox::new();
    let built = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "dist/build.receipt.json",
    ]);
    assert_eq!(code(&built), 0, "{}", stderr(&built));

    // Nothing about the trees changed between the two commands. Excluding the
    // destination from the source alone left this reporting a tree that nobody
    // touched as changed, forever, because the receipt is written AFTER the
    // output tree is measured.
    let output = sandbox.attest(&[
        "verify-build",
        "dist/build.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(
        code(&output),
        0,
        "a receipt inside its own output tree must not accuse the tree: {}",
        stderr(&output)
    );

    // And the exclusion is on the record rather than implicit.
    let receipt = sandbox.read_receipt("dist/build.receipt.json");
    assert_eq!(
        receipt["subject"]["output_exclusions"],
        serde_json::json!(["build.receipt.json"])
    );
}

#[test]
fn content_under_a_directory_named_git_in_the_output_tree_is_bound() {
    let sandbox = Sandbox::new();
    sandbox.write("dist/assets/.git/app.js", "benign\n");
    let built = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&built), 0, "{}", stderr(&built));
    let receipt = sandbox.read_receipt("build.receipt.json");
    assert_eq!(
        receipt["subject"]["output_tree"]["file_count"], 3,
        "output content under a .git directory is shipped content and must be bound"
    );

    sandbox.write("dist/assets/.git/app.js", "MALICIOUS\n");
    let output = sandbox.attest(&[
        "verify-build",
        "build.receipt.json",
        "--source",
        ".",
        "--output",
        "dist",
    ]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("output tree no longer matches"));
}

// ---------------------------------------------------------------------------
// deployment
// ---------------------------------------------------------------------------

fn build_receipt_for(sandbox: &Sandbox) {
    let built = sandbox.attest(&[
        "build",
        "--source",
        ".",
        "--output",
        "dist",
        "--out",
        "build.receipt.json",
    ]);
    assert_eq!(code(&built), 0, "{}", stderr(&built));
}

#[test]
fn a_loopback_base_url_is_a_mismatch_and_reaches_no_network() {
    let sandbox = Sandbox::new();
    build_receipt_for(&sandbox);
    let output = sandbox.attest(&[
        "deployment",
        "--build-receipt",
        "build.receipt.json",
        "--base-url",
        "https://127.0.0.1/",
        "--out",
        "deployment.receipt.json",
    ]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));

    let receipt = sandbox.receipt_json("deployment.receipt.json");
    assert_eq!(receipt["receipt_type"], "attest_deployment");
    assert_eq!(receipt["status"], "mismatch");
    assert_eq!(receipt["coverage"]["routes_mismatched"], 2);
    assert_eq!(receipt["coverage"]["routes_matched"], 0);
    let caveats = receipt["caveats"].as_array().expect("caveats");
    assert!(caveats.iter().any(|caveat| caveat
        .as_str()
        .unwrap_or_default()
        .contains("not continuous monitoring")));
}

#[test]
fn a_route_map_naming_an_unbuilt_file_is_a_usage_error() {
    let sandbox = Sandbox::new();
    build_receipt_for(&sandbox);
    sandbox.write(
        "routes.json",
        "{\"routes\": {\"vendor.js\": \"/vendor.js\"}}\n",
    );
    let output = sandbox.attest(&[
        "deployment",
        "--build-receipt",
        "build.receipt.json",
        "--base-url",
        "https://app.example/",
        "--route-map",
        "routes.json",
    ]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("output manifest"));
}

#[test]
fn a_route_map_pointing_off_the_origin_is_a_usage_error() {
    let sandbox = Sandbox::new();
    build_receipt_for(&sandbox);
    sandbox.write(
        "routes.json",
        "{\"routes\": {\"app.js\": \"https://elsewhere.example/app.js\"}}\n",
    );
    let output = sandbox.attest(&[
        "deployment",
        "--build-receipt",
        "build.receipt.json",
        "--base-url",
        "https://app.example/",
        "--route-map",
        "routes.json",
    ]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("same-origin"));
}

#[test]
fn deployment_refuses_a_file_that_is_not_a_build_receipt() {
    let sandbox = Sandbox::new();
    sandbox.write("not-a-receipt.json", "[]\n");
    let output = sandbox.attest(&[
        "deployment",
        "--build-receipt",
        "not-a-receipt.json",
        "--base-url",
        "https://app.example/",
    ]);
    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("is not a build receipt"));
}

// ---------------------------------------------------------------------------
// verify-deployment
// ---------------------------------------------------------------------------

#[test]
fn verify_deployment_re_checks_a_saved_receipt_without_a_network_request() {
    let sandbox = Sandbox::new();
    build_receipt_for(&sandbox);
    let produced = sandbox.attest(&[
        "deployment",
        "--build-receipt",
        "build.receipt.json",
        "--base-url",
        "https://127.0.0.1/",
        "--out",
        "deployment.receipt.json",
    ]);
    assert_eq!(code(&produced), 1, "{}", stderr(&produced));

    let output = sandbox.attest(&["verify-deployment", "deployment.receipt.json"]);
    assert_eq!(code(&output), 1, "{}", stderr(&output));
    assert!(stderr(&output).contains("did not bind"));
    assert!(
        stderr(&output).contains("not continuous monitoring"),
        "the honesty caveat is printed on every rendering: {}",
        stderr(&output)
    );
}

#[test]
fn verify_deployment_refuses_a_file_that_is_not_a_deployment_receipt() {
    let sandbox = Sandbox::new();
    build_receipt_for(&sandbox);
    let output = sandbox.attest(&["verify-deployment", "build.receipt.json"]);
    assert_eq!(code(&output), 2, "{}", stderr(&output));
    assert!(stderr(&output).contains("is not a deployment receipt"));
}

// ---------------------------------------------------------------------------
// The namespace boundary
// ---------------------------------------------------------------------------

fn help(args: &[&str]) -> String {
    let out = tirith().args(args).output().expect("run tirith");
    assert!(out.status.success(), "{args:?} --help must exit 0");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn attest_help_lists_all_four_subcommands_and_the_exit_codes() {
    let text = help(&["attest", "--help"]);
    for subcommand in ["build", "verify-build", "deployment", "verify-deployment"] {
        assert!(
            text.contains(subcommand),
            "attest --help must list {subcommand}:\n{text}"
        );
    }
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for row in ["0 clean", "1 mismatch", "2 usage", "3 partial"] {
        assert!(
            collapsed.contains(row),
            "attest --help must document `{row}`:\n{text}"
        );
    }
}

#[test]
fn attest_help_makes_no_reproducibility_or_monitoring_claim() {
    for args in [
        &["attest", "--help"][..],
        &["attest", "build", "--help"][..],
        &["attest", "deployment", "--help"][..],
        &["attest", "verify-deployment", "--help"][..],
    ] {
        let collapsed: String = help(args)
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let claims_reproducibility = collapsed.contains("reproducible build")
            && !collapsed.contains("not a reproducible-build claim");
        assert!(
            !claims_reproducibility,
            "{args:?} --help must never imply a reproducible build"
        );
        assert!(
            !collapsed.contains("continuously monitor"),
            "{args:?} --help must never imply continuous monitoring"
        );
    }
    let collapsed: String = help(&["attest", "deployment", "--help"])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(collapsed.contains("not continuous monitoring"));
}

#[test]
fn the_nested_pkg_attest_command_is_unchanged_and_still_binds_a_wheel() {
    let text = help(&["pkg", "attest", "--help"]);
    assert!(
        text.contains("WHEEL"),
        "`pkg attest` still takes a wheel:\n{text}"
    );
    assert!(
        text.contains("tirith pkg attest requests-2.31.0-py3-none-any.whl"),
        "`pkg attest` help examples are untouched:\n{text}"
    );
    // And the top-level namespace is a different command with different args.
    assert!(!help(&["attest", "build", "--help"]).contains("WHEEL"));
}

#[test]
fn attest_appears_in_the_categorized_command_overview() {
    let text = help(&["--help"]);
    assert!(
        text.contains("Supply-chain:") && text.contains("attest"),
        "the categorized overview must list attest:\n{text}"
    );
}

/// The temporary sandbox lives under `CARGO_TARGET_TMPDIR`, and nothing in this
/// file may write outside it. A regression here would mean a test scattering
/// receipts across a developer's home directory.
#[test]
fn the_sandbox_stays_inside_the_cargo_target_directory() {
    let sandbox = Sandbox::new();
    assert!(sandbox
        .root
        .starts_with(Path::new(env!("CARGO_TARGET_TMPDIR"))));
}
