use super::*;

use crate::capsule_receipt::{
    CapsuleRunCoverage, CapsuleRunDecision, CapsuleRunEvidence, CapsuleRunFacts, CapsuleRunReceipt,
    CapsuleRunStatus, CapsuleRunSubject, CapsuleTreeDigest,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn write(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, contents).expect("write fixture file");
}

/// A small tree with two directories and three files.
fn sample_tree(root: &Path) {
    write(root, "README.md", "readme\n");
    write(root, "src/main.rs", "fn main() {}\n");
    write(root, "assets/logo.svg", "<svg/>\n");
}

fn digest_of(root: &Path) -> String {
    source_scan(root).digest
}

fn source_scan(root: &Path) -> TreeScan {
    scan_tree(root, &[], PrunedNames::GitMetadata, TreeLimits::default())
        .expect("the sample tree binds")
}

fn output_scan(root: &Path) -> TreeScan {
    scan_tree(root, &[], PrunedNames::None, TreeLimits::default()).expect("the output tree binds")
}

/// A deterministic signing key, and the anchor that trusts exactly it. Both are
/// explicit inputs so the tests never depend on whether the machine running them
/// happens to have an audit key installed.
fn test_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}

fn anchor_for(key: &ed25519_dalek::SigningKey) -> SignatureAnchor {
    SignatureAnchor {
        verifying_key: Some(key.verifying_key().to_bytes()),
        signing_expected: true,
    }
}

/// An installation that neither signs nor can check a signature.
fn unsigned_anchor() -> SignatureAnchor {
    SignatureAnchor::default()
}

fn detached(payload: &str, key: &ed25519_dalek::SigningKey) -> String {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;
    base64::engine::general_purpose::STANDARD.encode(key.sign(payload.as_bytes()).to_bytes())
}

/// Sign a build receipt the way a machine with an audit key would: the presence
/// flag is INSIDE the content address, so it is set before the address is
/// stamped and the signature then covers the stamped address.
fn sign_build_receipt(receipt: &mut BuildReceipt, key: &ed25519_dalek::SigningKey) {
    receipt.signature_present = true;
    receipt.receipt_id = receipt.compute_content_hash();
    receipt.signature = Some(detached(&receipt.signing_payload(), key));
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn the_digest_is_independent_of_the_order_the_tree_was_created_in() {
    let first = tempfile::tempdir().expect("tempdir");
    write(first.path(), "assets/logo.svg", "<svg/>\n");
    write(first.path(), "README.md", "readme\n");
    write(first.path(), "src/main.rs", "fn main() {}\n");

    let second = tempfile::tempdir().expect("tempdir");
    write(second.path(), "src/main.rs", "fn main() {}\n");
    write(second.path(), "README.md", "readme\n");
    write(second.path(), "assets/logo.svg", "<svg/>\n");

    assert_eq!(digest_of(first.path()), digest_of(second.path()));
}

#[test]
fn every_kind_of_change_moves_the_digest() {
    let base = tempfile::tempdir().expect("tempdir");
    sample_tree(base.path());
    let baseline = digest_of(base.path());

    let mutated = tempfile::tempdir().expect("tempdir");
    sample_tree(mutated.path());
    write(mutated.path(), "README.md", "readme!\n");
    assert_ne!(
        baseline,
        digest_of(mutated.path()),
        "a one-byte content change must move the digest"
    );

    let renamed = tempfile::tempdir().expect("tempdir");
    sample_tree(renamed.path());
    std::fs::rename(
        renamed.path().join("README.md"),
        renamed.path().join("README.markdown"),
    )
    .expect("rename");
    assert_ne!(
        baseline,
        digest_of(renamed.path()),
        "a rename must move the digest"
    );

    let extra = tempfile::tempdir().expect("tempdir");
    sample_tree(extra.path());
    write(extra.path(), "src/extra.rs", "");
    assert_ne!(
        baseline,
        digest_of(extra.path()),
        "an extra file must move the digest"
    );

    let missing = tempfile::tempdir().expect("tempdir");
    sample_tree(missing.path());
    std::fs::remove_file(missing.path().join("src/main.rs")).expect("remove");
    assert_ne!(
        baseline,
        digest_of(missing.path()),
        "a missing file must move the digest"
    );
}

#[cfg(unix)]
#[test]
fn a_mode_change_moves_the_digest() {
    use std::os::unix::fs::PermissionsExt as _;

    let base = tempfile::tempdir().expect("tempdir");
    sample_tree(base.path());
    let baseline = digest_of(base.path());

    std::fs::set_permissions(
        base.path().join("src/main.rs"),
        std::fs::Permissions::from_mode(0o755),
    )
    .expect("chmod");
    assert_ne!(
        baseline,
        digest_of(base.path()),
        "a permission change must move the digest"
    );
}

#[test]
fn an_empty_directory_is_bound_and_not_silently_dropped() {
    let with_directory = tempfile::tempdir().expect("tempdir");
    sample_tree(with_directory.path());
    std::fs::create_dir(with_directory.path().join("empty")).expect("mkdir");

    let without = tempfile::tempdir().expect("tempdir");
    sample_tree(without.path());

    assert_ne!(digest_of(with_directory.path()), digest_of(without.path()));
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_symlink_at_a_leaf_or_at_a_directory_is_refused_and_never_followed() {
    let secret = tempfile::tempdir().expect("tempdir");
    write(secret.path(), "id_rsa", "PRIVATE KEY BYTES\n");

    let leaf = tempfile::tempdir().expect("tempdir");
    sample_tree(leaf.path());
    std::os::unix::fs::symlink(secret.path().join("id_rsa"), leaf.path().join("link"))
        .expect("symlink");
    let error = scan_tree(
        leaf.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect_err("a symlinked leaf must be refused");
    assert!(matches!(error, TreeScanError::Symlink(path) if path == "link"));

    let directory = tempfile::tempdir().expect("tempdir");
    sample_tree(directory.path());
    std::os::unix::fs::symlink(secret.path(), directory.path().join("nested")).expect("symlink");
    let error = scan_tree(
        directory.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect_err("a symlinked directory must be refused");
    assert!(matches!(error, TreeScanError::Symlink(path) if path == "nested"));
}

#[cfg(unix)]
#[test]
fn a_symlinked_root_is_refused_before_anything_is_read() {
    let real = tempfile::tempdir().expect("tempdir");
    sample_tree(real.path());
    let holder = tempfile::tempdir().expect("tempdir");
    let link = holder.path().join("alias");
    std::os::unix::fs::symlink(real.path(), &link).expect("symlink");

    let error = scan_tree(&link, &[], PrunedNames::GitMetadata, TreeLimits::default())
        .expect_err("a symlinked root must be refused");
    assert!(matches!(error, TreeScanError::Symlink(_)));
}

#[cfg(unix)]
#[test]
fn a_fifo_is_refused_rather_than_read() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let fifo = root.path().join("pipe");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("cstring");
    // SAFETY: `name` is a NUL-terminated path inside a temporary directory this
    // test owns; mkfifo only creates a filesystem entry.
    let created = unsafe { libc::mkfifo(name.as_ptr(), 0o600) };
    assert_eq!(
        created, 0,
        "mkfifo must succeed for this test to mean anything"
    );

    let error = scan_tree(
        root.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect_err("a fifo must be refused, never opened for reading");
    assert!(matches!(error, TreeScanError::UnsupportedEntry(path) if path == "pipe"));
}

#[test]
fn a_case_folded_collision_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "README", "one\n");
    // A case-insensitive filesystem merges these two names, so the second write
    // silently overwrites the first and the collision cannot be staged there.
    std::fs::write(root.path().join("readme"), "two\n").expect("write");
    if std::fs::read_dir(root.path())
        .expect("read_dir")
        .filter_map(Result::ok)
        .count()
        < 2
    {
        // A case-insensitive host cannot hold both names at once; the collision
        // rule is exercised by the normalization test below on every platform.
        return;
    }
    let error = scan_tree(
        root.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect_err("two case-folded names must be refused");
    assert!(matches!(error, TreeScanError::Collision { .. }));
}

#[test]
fn a_unicode_normalization_collision_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    // The same word twice: once composed (U+00E9) and once decomposed
    // (e + U+0301). Both are assembled from escapes so the source file itself
    // stays plain ASCII and the two spellings cannot be confused by an editor.
    let composed = format!("caf{}.txt", '\u{00e9}');
    let decomposed = format!("cafe{}.txt", '\u{0301}');
    if std::fs::write(root.path().join(&composed), "one\n").is_err()
        || std::fs::write(root.path().join(&decomposed), "two\n").is_err()
    {
        return;
    }
    if std::fs::read_dir(root.path())
        .expect("read_dir")
        .filter_map(Result::ok)
        .count()
        < 2
    {
        // A normalizing filesystem (Darwin's HFS+ lineage) folds the two names
        // into one on the way in, so the collision cannot be staged here.
        return;
    }
    let error = scan_tree(
        root.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect_err("an NFC/NFD collision must be refused");
    assert!(matches!(error, TreeScanError::Collision { .. }));
}

#[test]
fn caps_refuse_rather_than_binding_a_prefix() {
    let root = tempfile::tempdir().expect("tempdir");
    for index in 0..8 {
        write(root.path(), &format!("f{index}.txt"), "x");
    }

    let files = TreeLimits {
        max_files: 4,
        ..TreeLimits::default()
    };
    assert!(matches!(
        scan_tree(root.path(), &[], PrunedNames::GitMetadata, files),
        Err(TreeScanError::CapExceeded(_))
    ));

    let bytes = TreeLimits {
        max_bytes: 3,
        ..TreeLimits::default()
    };
    assert!(matches!(
        scan_tree(root.path(), &[], PrunedNames::GitMetadata, bytes),
        Err(TreeScanError::CapExceeded(_))
    ));

    let deep = tempfile::tempdir().expect("tempdir");
    write(deep.path(), "a/b/c/d/leaf.txt", "x");
    let depth = TreeLimits {
        max_depth: 2,
        ..TreeLimits::default()
    };
    assert!(matches!(
        scan_tree(deep.path(), &[], PrunedNames::GitMetadata, depth),
        Err(TreeScanError::CapExceeded(_))
    ));

    let long = TreeLimits {
        max_path_bytes: 4,
        ..TreeLimits::default()
    };
    assert!(matches!(
        scan_tree(root.path(), &[], PrunedNames::GitMetadata, long),
        Err(TreeScanError::PathTooLong(_))
    ));
}

#[test]
fn the_caps_are_folded_into_the_digest() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let wide = scan_tree(
        root.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect("bind");
    let narrow = scan_tree(
        root.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits {
            max_files: 1_000,
            ..TreeLimits::default()
        },
    )
    .expect("bind");
    assert_ne!(
        wide.digest, narrow.digest,
        "a digest taken under looser caps must never compare equal to one taken under tighter caps"
    );
}

// ---------------------------------------------------------------------------
// The three races, exercised through the bound-file hasher directly
// ---------------------------------------------------------------------------

fn walk_entry(root: &Path, relative: &str, size: u64, mode: u32) -> WalkEntry {
    let path = root.join(relative);
    let identity = std::fs::symlink_metadata(&path)
        .ok()
        .and_then(|metadata| identity_of(&metadata));
    WalkEntry {
        relative: relative.to_string(),
        path,
        directory: false,
        mode,
        size,
        identity,
    }
}

fn fresh_hasher() -> DigestBuilder {
    DigestBuilder::new(
        ModeModel::host(),
        TreeLimits::default(),
        &[],
        PrunedNames::None,
        &[],
    )
}

#[test]
fn a_file_larger_than_the_measured_size_is_refused_as_grown() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "a.txt", "0123456789");
    let real_mode = mode_of(&std::fs::metadata(root.path().join("a.txt")).expect("stat"));
    let mut hasher = fresh_hasher();
    // The walk measured 4 bytes and the file holds 10: exactly what an append
    // between the entry scan and the hash looks like.
    let error = hash_bound_file(&walk_entry(root.path(), "a.txt", 4, real_mode), &mut hasher)
        .expect_err("a grown file must be refused");
    assert!(matches!(error, TreeScanError::Changed(path) if path == "a.txt"));
}

#[test]
fn a_file_smaller_than_the_measured_size_is_refused_as_truncated() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "a.txt", "0123");
    let real_mode = mode_of(&std::fs::metadata(root.path().join("a.txt")).expect("stat"));
    let mut hasher = fresh_hasher();
    let error = hash_bound_file(
        &walk_entry(root.path(), "a.txt", 10, real_mode),
        &mut hasher,
    )
    .expect_err("a truncated file must be refused");
    assert!(matches!(error, TreeScanError::Changed(path) if path == "a.txt"));
}

#[cfg(unix)]
#[test]
fn a_file_whose_mode_no_longer_matches_is_refused_as_rebound() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "a.txt", "0123");
    let mut hasher = fresh_hasher();
    let error = hash_bound_file(&walk_entry(root.path(), "a.txt", 4, 0o777), &mut hasher)
        .expect_err("a rebound file must be refused");
    assert!(matches!(error, TreeScanError::Changed(path) if path == "a.txt"));
}

#[test]
fn a_file_rebound_to_another_inode_of_the_same_size_and_mode_is_refused() {
    let root = tempfile::tempdir().expect("tempdir");
    // The decoy the attacker renames INTO place, and the file the walk measured.
    // Same length, same mode: length and mode compares alone accept the swap, so
    // only the recorded filesystem identity can tell them apart.
    write(root.path(), "measured.txt", "AAAA");
    write(root.path(), "decoy.txt", "CCCC");
    let measured = walk_entry(root.path(), "measured.txt", 4, 0o644);
    let decoy = walk_entry(root.path(), "decoy.txt", 4, 0o644);
    assert_eq!(
        std::fs::metadata(root.path().join("measured.txt"))
            .expect("stat")
            .len(),
        std::fs::metadata(root.path().join("decoy.txt"))
            .expect("stat")
            .len(),
        "the two inodes must be the same length for this test to mean anything"
    );
    let real_mode = mode_of(&std::fs::metadata(root.path().join("measured.txt")).expect("stat"));
    assert_eq!(
        real_mode,
        mode_of(&std::fs::metadata(root.path().join("decoy.txt")).expect("stat")),
        "the two inodes must carry the same mode for this test to mean anything"
    );
    if measured.identity.is_none() || decoy.identity.is_none() {
        // A platform that cannot report an identity from a walk stat is outside
        // what this test can prove; the length and mode compares still apply.
        return;
    }
    assert_ne!(measured.identity, decoy.identity);

    // The rename lands between the walk stat and the open, which is exactly the
    // window this compare exists to close.
    std::fs::rename(
        root.path().join("decoy.txt"),
        root.path().join("measured.txt"),
    )
    .expect("rename the decoy over the measured name");

    let mut hasher = fresh_hasher();
    let entry = WalkEntry {
        relative: "measured.txt".to_string(),
        path: root.path().join("measured.txt"),
        directory: false,
        mode: real_mode,
        size: 4,
        identity: measured.identity,
    };
    let error = hash_bound_file(&entry, &mut hasher)
        .expect_err("a name rebound to another inode must be refused");
    assert!(matches!(error, TreeScanError::Changed(path) if path == "measured.txt"));
}

#[test]
fn a_vanished_file_is_refused_rather_than_skipped() {
    let root = tempfile::tempdir().expect("tempdir");
    let mut hasher = fresh_hasher();
    let error = hash_bound_file(&walk_entry(root.path(), "gone.txt", 0, 0o644), &mut hasher)
        .expect_err("a vanished file must be refused");
    assert!(matches!(error, TreeScanError::Changed(path) if path == "gone.txt"));
}

// ---------------------------------------------------------------------------
// Exclusions
// ---------------------------------------------------------------------------

#[test]
fn git_the_output_root_and_the_receipt_destination_are_all_excluded() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    write(root.path(), "dist/index.html", "<html/>\n");
    write(root.path(), ".git/HEAD", "ref: refs/heads/main\n");
    let exclusions = vec!["dist".to_string(), "build.receipt.json".to_string()];
    let baseline = scan_tree(
        root.path(),
        &exclusions,
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect("bind")
    .digest;

    // One new file under each removed path. None of them may move the digest.
    write(root.path(), ".git/ORIG_HEAD", "0000\n");
    write(root.path(), "dist/app.js", "console.log(1)\n");
    write(root.path(), "build.receipt.json", "{}\n");
    let after = scan_tree(
        root.path(),
        &exclusions,
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect("bind")
    .digest;
    assert_eq!(
        baseline, after,
        "an excluded path must not reach the source digest"
    );

    // And an UNEXCLUDED sibling must still move it, so the test above is not
    // passing because nothing is being hashed at all.
    write(root.path(), "src/extra.rs", "");
    assert_ne!(
        baseline,
        scan_tree(
            root.path(),
            &exclusions,
            PrunedNames::GitMetadata,
            TreeLimits::default()
        )
        .expect("bind")
        .digest
    );
}

#[test]
fn a_pruned_git_subtree_keeps_its_content_out_but_never_its_existence() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    write(root.path(), "vendor/dep/lib.rs", "");
    let bare = source_scan(root.path());
    assert!(bare.pruned.is_empty());

    // A submodule records `.git` as a FILE, not a directory, and it can sit at
    // any depth. Its CONTENT is the object-store pointer and stays out ...
    write(
        root.path(),
        "vendor/dep/.git",
        "gitdir: ../../.git/modules/dep\n",
    );
    let pruned = source_scan(root.path());
    assert_eq!(pruned.pruned, vec!["vendor/dep/.git".to_string()]);
    write(
        root.path(),
        "vendor/dep/.git",
        "gitdir: ../../.git/modules/other\n",
    );
    assert_eq!(
        pruned.digest,
        source_scan(root.path()).digest,
        "the content behind the prune rule is deliberately not bound"
    );

    // ... but the fact that a subtree was removed at all is folded into the
    // digest. Without that, an attacker who can create a directory named `.git`
    // anywhere in the tree ships bytes under a digest that never moves.
    assert_ne!(
        bare.digest, pruned.digest,
        "a pruned path appearing must move the digest"
    );
}

#[test]
fn the_output_tree_binds_content_under_a_directory_named_git() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "keep", "keep\n");
    write(root.path(), "assets/.git/app.js", "benign\n");
    let before = output_scan(root.path());
    assert!(
        before.pruned.is_empty(),
        "the output scan prunes nothing by name"
    );
    assert!(before
        .files
        .iter()
        .any(|file| file.path == "assets/.git/app.js"));

    // Build output has no object store to protect a digest from, so a directory
    // named `.git` under it is shipped content: changing it must be visible, and
    // adding a sibling under it must be visible too.
    write(root.path(), "assets/.git/app.js", "MALICIOUS\n");
    let edited = output_scan(root.path());
    assert_ne!(before.digest, edited.digest);
    write(root.path(), "assets/.git/backdoor.js", "steal()\n");
    assert_ne!(edited.digest, output_scan(root.path()).digest);
}

#[test]
fn the_prune_rule_itself_is_folded_into_the_digest() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    assert_ne!(
        source_scan(root.path()).digest,
        output_scan(root.path()).digest,
        "two scans that would remove different subtrees must not agree, even over a tree that \
         contains none of them"
    );
}

#[test]
fn the_exclusion_set_is_folded_into_the_digest() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let bare = scan_tree(
        root.path(),
        &[],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect("bind");
    let declared = scan_tree(
        root.path(),
        &["dist".to_string()],
        PrunedNames::GitMetadata,
        TreeLimits::default(),
    )
    .expect("bind");
    assert_eq!(
        bare.file_count, declared.file_count,
        "no dist tree exists yet"
    );
    assert_ne!(
        bare.digest, declared.digest,
        "two scans that excluded different sets must not produce the same digest"
    );
}

// ---------------------------------------------------------------------------
// Surrounding facts
// ---------------------------------------------------------------------------

#[test]
fn a_tree_that_is_not_a_repository_records_no_commit() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let binding = capture_git_binding(root.path());
    assert_eq!(
        binding.commit, None,
        "a commit must never be fabricated for a non-repository"
    );
}

#[test]
fn lockfiles_are_digested_from_the_root_only() {
    let root = tempfile::tempdir().expect("tempdir");
    write(root.path(), "Cargo.lock", "# lock\n");
    write(root.path(), "nested/package-lock.json", "{}\n");
    let found = scan_lockfiles(root.path());
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name, "Cargo.lock");
    assert_eq!(found[0].size, 7);
}

#[test]
fn the_argv_digest_is_taken_after_redaction_not_before() {
    // Two synthetic AWS-shaped keys, assembled at runtime so no credential-shaped
    // literal exists in this file. They differ, but both redact to the same
    // marker, so an argv digest taken AFTER redaction must be identical. A digest
    // taken before redaction would differ, and would also let an attacker confirm
    // a guessed secret by hashing it.
    let first = format!("AKIA{}", "A".repeat(16));
    let second = format!("AKIA{}", "B".repeat(16));
    assert_ne!(first, second);
    let (left, _) = redacted_argv_digest(&["tirith".to_string(), first]);
    let (right, _) = redacted_argv_digest(&["tirith".to_string(), second]);
    assert_eq!(
        left, right,
        "the argv digest must be taken after redaction, not before"
    );

    // A non-secret difference must still move the digest, so the equality above
    // is redaction and not a constant.
    let (other, len) = redacted_argv_digest(&["tirith".to_string(), "--source".to_string()]);
    assert_ne!(left, other);
    assert_eq!(len, 2);
}

#[test]
fn the_argv_digest_length_prefixes_every_element() {
    let (joined, _) = redacted_argv_digest(&["ab".to_string(), "c".to_string()]);
    let (split, _) = redacted_argv_digest(&["a".to_string(), "bc".to_string()]);
    assert_ne!(
        joined, split,
        "two argvs that concatenate to the same bytes must not collide"
    );
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

fn assembled(root: &Path, output: &Path) -> BuildReceipt {
    build_receipt(
        &BuildRequest {
            source: root.to_path_buf(),
            output: output.to_path_buf(),
            extra_exclusions: Vec::new(),
            extra_output_exclusions: Vec::new(),
            execution_receipt: None,
            argv: vec!["tirith".to_string(), "attest".to_string()],
            limits: TreeLimits::default(),
        },
        "a".repeat(64),
    )
}

fn clean_receipt() -> (tempfile::TempDir, BuildReceipt) {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    write(root.path(), ".git/HEAD", "ref: refs/heads/main\n");
    write(root.path(), "dist/index.html", "<html/>\n");
    let output = root.path().join("dist");
    let receipt = assembled(root.path(), &output);
    (root, receipt)
}

#[test]
fn a_fresh_receipt_is_content_addressed_clean_and_valid() {
    let (_root, receipt) = clean_receipt();
    assert_eq!(receipt.status, AttestStatus::Clean);
    assert_eq!(receipt.receipt_id.len(), 64);
    assert!(receipt.content_hash_matches());
    receipt.validate().expect("a coherent receipt validates");
    assert!(receipt.subject.source_tree.is_some());
    assert!(receipt.subject.output_tree.is_some());
    assert!(!receipt.coverage.audit_chain_anchored);
}

#[test]
fn the_output_root_is_excluded_from_the_source_digest_by_assembly() {
    let (root, receipt) = clean_receipt();
    let source = receipt.subject.source_tree.expect("source tree");
    // README.md, src/main.rs, assets/logo.svg and nothing from dist or .git.
    assert_eq!(source.file_count, 3);
    assert!(receipt
        .subject
        .source_exclusions
        .iter()
        .any(|value| value == "dist"));
    assert_eq!(
        receipt.subject.source_pruned,
        vec![".git".to_string()],
        "the receipt must name the subtree the prune rule removed"
    );
    drop(root);
}

#[test]
fn the_receipt_round_trips_and_every_field_is_bound_by_the_content_address() {
    let (_root, receipt) = clean_receipt();
    let json = receipt.to_json();
    let parsed = BuildReceipt::parse(&json).expect("a receipt round-trips");
    assert_eq!(parsed.receipt_id, receipt.receipt_id);

    for mutate in [
        (|r: &mut BuildReceipt| r.status = AttestStatus::Partial) as fn(&mut _),
        |r: &mut BuildReceipt| r.subject.argv_digest = "b".repeat(64),
        |r: &mut BuildReceipt| r.subject.output_files_truncated = true,
        |r: &mut BuildReceipt| r.coverage.source_scanned = false,
        |r: &mut BuildReceipt| r.policy_projection_hash = "c".repeat(64),
        |r: &mut BuildReceipt| r.evidence.limits.max_files = 7,
        |r: &mut BuildReceipt| r.caveats.push("extra".to_string()),
    ] {
        let mut tampered = receipt.clone();
        mutate(&mut tampered);
        assert!(
            !tampered.content_hash_matches(),
            "an edited receipt must not still match its content address"
        );
        assert!(tampered.validate().is_err());
    }
}

#[test]
fn stripping_the_signature_fails_verification_instead_of_reading_as_unsigned() {
    let (_root, mut receipt) = clean_receipt();
    // Sign the way the audit chain would, then re-stamp the content address so
    // the receipt is internally the same as one produced on a machine with a
    // signing key configured.
    receipt.signature_present = true;
    receipt.receipt_id = receipt.compute_content_hash();
    receipt.signature = Some("not-verified-here".to_string());
    receipt
        .validate()
        .expect("a signed receipt validates before tampering");

    let mut stripped = receipt.clone();
    stripped.signature = None;
    assert!(
        stripped.content_hash_matches(),
        "the content address deliberately blanks the signature field"
    );
    let error = stripped
        .validate()
        .expect_err("a stripped signature must fail verification");
    assert!(error.to_string().contains("signature"));
}

#[test]
fn a_deployment_receipt_does_not_deserialize_as_a_build_receipt() {
    let deployment = crate::deployment_receipt::DeploymentReceipt::new(
        crate::deployment_receipt::DeploymentReceiptFacts {
            policy_projection_hash: "a".repeat(64),
            status: AttestStatus::Partial,
            subject: crate::deployment_receipt::DeploymentSubject {
                build_receipt_id: "b".repeat(64),
                build_receipt_status: AttestStatus::Clean,
                output_tree_digest: None,
                base_url: "https://app.example".to_string(),
                origin: "https://app.example".to_string(),
                route_map_source: "default".to_string(),
                route_count: 0,
            },
            routes: Vec::new(),
            coverage: crate::deployment_receipt::DeploymentCoverage {
                build_receipt_verified: true,
                build_signature: SignatureTrust::Unsigned,
                route_map_refusal: None,
                output_files_total: 0,
                routes_requested: 0,
                routes_matched: 0,
                routes_mismatched: 0,
                routes_partial: 0,
                audit_chain_anchored: false,
            },
        },
    );
    let error = BuildReceipt::parse(&deployment.to_json())
        .expect_err("a deployment receipt is not a build receipt");
    assert!(matches!(error, BuildReceiptError::Malformed(_)));
}

#[test]
fn the_serialized_receipt_carries_no_argv_and_no_host_path() {
    let (root, receipt) = clean_receipt();
    let json = serde_json::to_string(&receipt).expect("serialize");
    assert!(json.contains("argv_digest"));
    assert!(!json.contains("\"argv\""));
    // The temporary directory's absolute path is the operator's machine layout.
    let host_path = root.path().display().to_string();
    assert!(
        !json.contains(&host_path),
        "no absolute host path may reach a durable receipt"
    );
    assert!(!json.contains("/Users/"));
    assert!(!json.contains("/home/"));
}

#[test]
fn a_clean_status_requires_both_trees_an_untruncated_manifest_and_no_refusal() {
    let (_root, receipt) = clean_receipt();
    for mutate in [
        (|r: &mut BuildReceipt| r.coverage.source_scanned = false) as fn(&mut _),
        |r: &mut BuildReceipt| r.coverage.output_scanned = false,
        |r: &mut BuildReceipt| r.coverage.scan_refusal = Some("a cap".to_string()),
        |r: &mut BuildReceipt| r.subject.output_files_truncated = true,
        |r: &mut BuildReceipt| r.subject.source_tree = None,
    ] {
        let mut broken = receipt.clone();
        mutate(&mut broken);
        // Re-stamp so the ONLY thing wrong is the honesty rule, not the address.
        broken.receipt_id = broken.compute_content_hash();
        assert!(
            broken.validate().is_err(),
            "a clean receipt must not survive losing its coverage"
        );
    }
}

#[test]
fn an_unreadable_output_tree_produces_a_partial_receipt_not_a_clean_one() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let receipt = assembled(root.path(), &root.path().join("does-not-exist"));
    assert_eq!(receipt.status, AttestStatus::Partial);
    assert!(receipt.coverage.scan_refusal.is_some());
    assert!(!receipt.coverage.output_scanned);
    receipt
        .validate()
        .expect("a partial receipt is still valid");
}

#[test]
fn a_receipt_that_drops_its_caveats_is_refused() {
    let (_root, mut receipt) = clean_receipt();
    receipt.caveats.clear();
    receipt.receipt_id = receipt.compute_content_hash();
    assert!(receipt.validate().is_err());
}

// ---------------------------------------------------------------------------
// Execution link
// ---------------------------------------------------------------------------

fn full_coverage(all: bool) -> crate::capsule::CapsuleCoverage {
    crate::capsule::CapsuleCoverage {
        fs_read_enforced: all,
        fs_write_enforced: all,
        exec_limited: all,
        network_raw_denied: all,
        domain_proxy_enforced: false,
        resource_limits_enforced: all,
        env_isolated: all,
        handles_isolated: all,
    }
}

/// A capsule receipt shaped exactly the way `cli::capsule_run` emits one: the
/// input inventory is the project copy BEFORE the build (equal to the source
/// tree, since the copy is faithful) and the output inventory is the whole copy
/// AFTER it, which is a different tree from any dist directory and is deleted
/// before the run ends.
fn capsule_for(source: &Path, output: &Path) -> CapsuleRunReceipt {
    let tree = |digest: Option<String>| {
        digest.map(|digest| CapsuleTreeDigest {
            digest,
            file_count: 1,
            total_bytes: 1,
            complete: true,
        })
    };
    // The ephemeral copy after the build: the project plus whatever the build
    // wrote into it. Deliberately NOT an inventory of `output`.
    let post_build = {
        let copy = tempfile::tempdir().expect("tempdir");
        write(copy.path(), "src/main.rs", "fn main() {}\n");
        write(copy.path(), "dist/index.html", "<html/>\n");
        capsule_source_inventory(copy.path())
    };
    let _ = output;
    let mut receipt = CapsuleRunReceipt::new(CapsuleRunFacts {
        status: CapsuleRunStatus::Contained,
        policy_projection_hash: "a".repeat(64),
        task_gate_binding: "task_gate:v1:mode=off;denied=".to_string(),
        subject: CapsuleRunSubject {
            preset: "untrusted-project".to_string(),
            argv_digest: "b".repeat(64),
            argv_len: 2,
            project_input: tree(capsule_source_inventory(source)),
            project_output: tree(post_build),
        },
        evidence: CapsuleRunEvidence {
            backend_id: "landlock-seccomp".to_string(),
            platform: "linux/x86_64".to_string(),
            limits: crate::capsule::ResourceLimits::conservative(),
            child_exit_code: Some(0),
            decision: CapsuleRunDecision::TargetCompleted,
            termination_kind: None,
            reason: None,
            project_copy_materialized: true,
            cleanup_confirmed: true,
            diff: crate::capsule_project::ProjectDiff::default(),
        },
        coverage: CapsuleRunCoverage {
            requested: full_coverage(true),
            achieved: full_coverage(true),
            parent_enforced_dimensions: vec!["wall_clock_seconds".to_string()],
        },
    });
    // The signing key is not configured in a test process, so the receipt comes
    // back unsigned. A capsule receipt's content address blanks the signature,
    // so a REAL detached signature attached afterwards leaves the document valid
    // and is what the link's signature requirement is exercised against.
    let key = test_signing_key();
    receipt.signature = Some(detached(&receipt.signing_payload(), &key));
    receipt
}

/// The fixture a real `capsule run` over this source tree would produce, and the
/// inventory the link compares it against.
fn capsule_fixture() -> (tempfile::TempDir, CapsuleRunReceipt, Option<String>) {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let output = root.path().join("dist");
    std::fs::create_dir(&output).expect("mkdir");
    write(&output, "index.html", "<html/>\n");
    let capsule = capsule_for(root.path(), &output);
    let inventory = capsule_source_inventory(root.path());
    (root, capsule, inventory)
}

#[test]
fn a_capsule_receipt_whose_signature_verifies_and_binds_this_source_tree_is_verified() {
    let (_root, capsule, inventory) = capsule_fixture();
    let link = evaluate_execution_link(
        &capsule,
        inventory.as_deref(),
        anchor_for(&test_signing_key()),
    );
    assert_eq!(
        link.reasons,
        Vec::<String>::new(),
        "a fully coherent link must name no reason"
    );
    assert_eq!(link.verdict, ExecutionVerdict::Verified);
    assert!(link.linked);
    assert_eq!(link.input_digest_matches, Some(true));
    assert_eq!(link.capsule_signature, Some(SignatureTrust::Verified));
    // Recorded verbatim, never compared: it inventories a directory that no
    // longer exists.
    assert!(link.capsule_output_digest.is_some());
}

#[test]
fn a_capsule_signature_that_does_not_verify_is_never_accepted_on_presence_alone() {
    let (_root, capsule, inventory) = capsule_fixture();
    let anchor = anchor_for(&test_signing_key());

    // Exactly the forgery the reviewer built: a hand-written receipt whose every
    // recomputable field is coherent, carrying a string in the signature slot.
    let mut forged = capsule.clone();
    forged.signature = Some("this-is-not-a-signature".to_string());
    let link = evaluate_execution_link(&forged, inventory.as_deref(), anchor);
    assert_eq!(
        link.verdict,
        ExecutionVerdict::Observed,
        "a signature is a signature only when it verifies"
    );
    assert_eq!(link.capsule_signature, Some(SignatureTrust::Rejected));
    assert!(link
        .reasons
        .iter()
        .any(|reason| reason.contains("does not verify")));

    // A genuine signature checked against a DIFFERENT key is equally rejected.
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let link = evaluate_execution_link(&capsule, inventory.as_deref(), anchor_for(&other));
    assert_eq!(link.verdict, ExecutionVerdict::Observed);

    // And an installation with no key at all cannot check it, which is an
    // absence of evidence rather than a pass.
    let link = evaluate_execution_link(&capsule, inventory.as_deref(), unsigned_anchor());
    assert_eq!(link.verdict, ExecutionVerdict::Observed);
    assert_eq!(link.capsule_signature, Some(SignatureTrust::Uncheckable));
}

#[test]
fn every_missing_execution_requirement_downgrades_the_link_and_names_itself() {
    let (root, _capsule, inventory) = capsule_fixture();
    let output = root.path().join("dist");
    let anchor = anchor_for(&test_signing_key());

    /// One way a capsule receipt can fail to prove a contained build, applied to
    /// an otherwise fully coherent receipt.
    type Defect = fn(&mut CapsuleRunReceipt);

    let cases: Vec<(&str, Defect)> = vec![
        ("unsigned", |receipt| receipt.signature = None),
        ("not contained", |receipt| {
            receipt.status = CapsuleRunStatus::Partial
        }),
        ("degraded", |receipt| {
            receipt.coverage.achieved.network_raw_denied = false
        }),
        ("terminated", |receipt| {
            receipt.evidence.decision = CapsuleRunDecision::TerminatedByTirith
        }),
        ("failed child", |receipt| {
            receipt.evidence.child_exit_code = Some(1)
        }),
        ("no input digest", |receipt| {
            receipt.subject.project_input = None
        }),
        ("incomplete input digest", |receipt| {
            if let Some(tree) = receipt.subject.project_input.as_mut() {
                tree.complete = false;
            }
        }),
        ("wrong input digest", |receipt| {
            if let Some(tree) = receipt.subject.project_input.as_mut() {
                tree.digest = "f".repeat(64);
            }
        }),
        ("no output digest", |receipt| {
            receipt.subject.project_output = None
        }),
    ];

    for (label, mutate) in cases {
        let mut capsule = capsule_for(root.path(), &output);
        mutate(&mut capsule);
        let link = evaluate_execution_link(&capsule, inventory.as_deref(), anchor);
        assert_eq!(
            link.verdict,
            ExecutionVerdict::Observed,
            "{label} must not be recorded as verified"
        );
        assert!(
            !link.reasons.is_empty(),
            "{label} must name why it is not verified"
        );
    }
}

#[test]
fn an_absent_execution_receipt_is_observed_and_says_so() {
    let link = ExecutionLink::default();
    assert_eq!(link.verdict, ExecutionVerdict::Observed);
    assert_eq!(link.reasons.len(), 1);
    assert!(link.reasons[0].contains("no capsule execution receipt"));
}

#[test]
fn an_execution_receipt_that_does_not_prove_containment_makes_the_receipt_partial() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let output = root.path().join("dist");
    std::fs::create_dir(&output).expect("mkdir");
    write(&output, "index.html", "<html/>\n");
    let bogus = root.path().join("not-a-receipt.json");
    std::fs::write(&bogus, "{}").expect("write");

    let receipt = build_receipt(
        &BuildRequest {
            source: root.path().to_path_buf(),
            output: output.clone(),
            extra_exclusions: Vec::new(),
            extra_output_exclusions: Vec::new(),
            execution_receipt: Some(bogus),
            argv: vec!["tirith".to_string()],
            limits: TreeLimits::default(),
        },
        "a".repeat(64),
    );
    assert_eq!(
        receipt.evidence.execution.verdict,
        ExecutionVerdict::Observed
    );
    assert!(receipt.evidence.execution.linked);
    assert!(!receipt.evidence.execution.reasons.is_empty());
    // An operator who asked for a containment link and did not get one must not
    // be handed exit 0, which is what `--execution-receipt` promises in help.
    assert_eq!(
        receipt.status,
        AttestStatus::Partial,
        "a link that was asked for and did not stand up is a partial receipt"
    );
    assert_eq!(receipt.status.exit_code(), 3);
    receipt.validate().expect("the receipt is still valid");

    // And the honesty rule holds at the document level too: re-stamping a clean
    // status over an unverified link must not validate.
    let mut relabelled = receipt.clone();
    relabelled.status = AttestStatus::Clean;
    relabelled.coverage.scan_refusal = None;
    relabelled.receipt_id = relabelled.compute_content_hash();
    assert!(relabelled.validate().is_err());
}

#[test]
fn an_unlinked_build_stays_clean_even_though_the_default_link_is_observed() {
    let (_root, receipt) = clean_receipt();
    assert!(!receipt.evidence.execution.linked);
    assert_eq!(
        receipt.evidence.execution.verdict,
        ExecutionVerdict::Observed
    );
    assert_eq!(
        receipt.status,
        AttestStatus::Clean,
        "not asking for a containment link is not a finding"
    );
}

// ---------------------------------------------------------------------------
// verify-build
// ---------------------------------------------------------------------------

#[test]
fn verify_build_is_clean_on_an_unchanged_tree_and_mismatch_on_a_changed_one() {
    let (root, receipt) = clean_receipt();
    let output = root.path().join("dist");

    let clean = verify_build(&receipt, root.path(), &output, unsigned_anchor());
    assert_eq!(clean.status, AttestStatus::Clean);
    assert!(clean.findings.is_empty());
    assert_eq!(clean.status.exit_code(), 0);

    write(root.path(), "src/main.rs", "fn main() { println!(); }\n");
    let changed = verify_build(&receipt, root.path(), &output, unsigned_anchor());
    assert_eq!(changed.status, AttestStatus::Mismatch);
    assert_eq!(changed.status.exit_code(), 1);
    assert!(changed
        .findings
        .iter()
        .any(|finding| finding.contains("source tree no longer matches")));
}

#[test]
fn verify_build_is_partial_when_a_tree_cannot_be_re_read() {
    let (root, receipt) = clean_receipt();
    let verification = verify_build(
        &receipt,
        root.path(),
        &root.path().join("gone"),
        unsigned_anchor(),
    );
    assert_eq!(verification.status, AttestStatus::Partial);
    assert_eq!(verification.status.exit_code(), 3);
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.starts_with("output:")));
}

#[test]
fn verify_build_refuses_a_receipt_that_failed_its_own_integrity_rules() {
    let (root, mut receipt) = clean_receipt();
    let output = root.path().join("dist");
    receipt.subject.argv_digest = "d".repeat(64);
    let verification = verify_build(&receipt, root.path(), &output, unsigned_anchor());
    assert_eq!(verification.status, AttestStatus::Mismatch);
    assert_eq!(verification.findings.len(), 1);
}

#[test]
fn verify_build_cannot_be_clean_over_a_receipt_that_was_itself_partial() {
    let root = tempfile::tempdir().expect("tempdir");
    sample_tree(root.path());
    let output = root.path().join("dist");
    std::fs::create_dir(&output).expect("mkdir");
    write(&output, "index.html", "<html/>\n");

    let mut receipt = assembled(root.path(), &output);
    receipt.status = AttestStatus::Partial;
    receipt.receipt_id = receipt.compute_content_hash();

    let verification = verify_build(&receipt, root.path(), &output, unsigned_anchor());
    assert_eq!(verification.status, AttestStatus::Partial);
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.contains("the receipt itself is partial")));
}

#[test]
fn a_receipt_bound_under_another_permission_model_is_partial_not_mismatch() {
    let (root, mut receipt) = clean_receipt();
    let output = root.path().join("dist");
    let other = if ModeModel::host() == ModeModel::UnixPermissions {
        ModeModel::WindowsReadonly
    } else {
        ModeModel::UnixPermissions
    };
    if let Some(tree) = receipt.subject.source_tree.as_mut() {
        tree.mode_model = other;
    }
    if let Some(tree) = receipt.subject.output_tree.as_mut() {
        tree.mode_model = other;
    }
    receipt.receipt_id = receipt.compute_content_hash();

    let verification = verify_build(&receipt, root.path(), &output, unsigned_anchor());
    assert_eq!(
        verification.status,
        AttestStatus::Partial,
        "a tree that cannot be compared here must not be reported as changed"
    );
}

#[test]
fn verify_build_refuses_a_receipt_whose_signature_does_not_verify() {
    let key = test_signing_key();
    let (root, mut receipt) = clean_receipt();
    let output = root.path().join("dist");
    let anchor = anchor_for(&key);

    // The honest signed receipt verifies.
    sign_build_receipt(&mut receipt, &key);
    let honest = verify_build(&receipt, root.path(), &output, anchor);
    assert_eq!(honest.status, AttestStatus::Clean);
    assert_eq!(honest.signature, SignatureTrust::Verified);

    // Attaching a fabricated signature and re-stamping the content address is
    // the whole forgery: `receipt_id` is a keyless sha256 anyone who can write
    // the file can recompute. It must not read as the MORE trustworthy document.
    let mut forged = receipt.clone();
    forged.signature = Some("AAAA-not-a-real-ed25519-signature".to_string());
    forged.receipt_id = forged.compute_content_hash();
    let verification = verify_build(&forged, root.path(), &output, anchor);
    assert_eq!(verification.status, AttestStatus::Mismatch);
    assert_eq!(verification.status.exit_code(), 1);
    assert_eq!(verification.signature, SignatureTrust::Rejected);
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.contains("does not verify")));

    // A genuine signature over DIFFERENT content is equally rejected: this is
    // the spliced-subject forgery, where a stale signature is retained over a
    // receipt whose subject was swapped and whose id was recomputed.
    let mut spliced = receipt.clone();
    spliced.subject.source_exclusions = vec!["src".to_string(), "assets".to_string()];
    spliced.receipt_id = spliced.compute_content_hash();
    let verification = verify_build(&spliced, root.path(), &output, anchor);
    assert_eq!(verification.status, AttestStatus::Mismatch);
    assert_eq!(verification.signature, SignatureTrust::Rejected);
}

#[test]
fn verify_build_refuses_an_unsigned_receipt_on_an_installation_that_signs() {
    let (root, receipt) = clean_receipt();
    let output = root.path().join("dist");
    assert!(receipt.signature.is_none());

    // Deleting the signature is the cheapest forgery there is, so on a signing
    // installation an unsigned document is a stripped one.
    let signing = SignatureAnchor {
        verifying_key: Some(test_signing_key().verifying_key().to_bytes()),
        signing_expected: true,
    };
    let verification = verify_build(&receipt, root.path(), &output, signing);
    assert_eq!(verification.status, AttestStatus::Mismatch);
    assert_eq!(verification.signature, SignatureTrust::Rejected);

    // The same document on an installation that signs nothing is honestly
    // unsigned, and still clean.
    let verification = verify_build(&receipt, root.path(), &output, unsigned_anchor());
    assert_eq!(verification.status, AttestStatus::Clean);
    assert_eq!(verification.signature, SignatureTrust::Unsigned);
}

#[test]
fn verify_build_is_partial_when_a_signature_cannot_be_checked() {
    let key = test_signing_key();
    let (root, mut receipt) = clean_receipt();
    let output = root.path().join("dist");
    sign_build_receipt(&mut receipt, &key);

    let no_key = SignatureAnchor {
        verifying_key: None,
        signing_expected: true,
    };
    let verification = verify_build(&receipt, root.path(), &output, no_key);
    assert_eq!(verification.status, AttestStatus::Partial);
    assert_eq!(verification.signature, SignatureTrust::Uncheckable);
    assert!(verification
        .findings
        .iter()
        .any(|finding| finding.contains("could not be checked")));
}

#[test]
fn verify_build_reports_the_exclusion_sets_and_the_covered_counts() {
    let (root, receipt) = clean_receipt();
    let output = root.path().join("dist");
    let verification = verify_build(&receipt, root.path(), &output, unsigned_anchor());
    // A forged exclusion set wide enough to swallow every top-level entry makes
    // one receipt verify against two unrelated trees. The answer has to carry
    // the set and the count, or "clean" is unreadable.
    assert!(verification
        .source_exclusions
        .iter()
        .any(|value| value == "dist"));
    assert_eq!(verification.source_files, Some(3));
    assert_eq!(verification.output_files, Some(1));
}

#[test]
fn an_output_manifest_over_the_cap_is_refused_as_a_document() {
    let (_root, mut receipt) = clean_receipt();
    // A hand-edited receipt carrying more manifest entries than the schema can
    // produce is a request amplifier for `attest deployment`, so the document
    // itself refuses it.
    let file = receipt.subject.output_files[0].clone();
    receipt.subject.output_files = (0..=MAX_RECORDED_OUTPUT_FILES)
        .map(|index| TreeFile {
            path: format!("f{index}.js"),
            ..file.clone()
        })
        .collect();
    receipt.status = AttestStatus::Partial;
    receipt.receipt_id = receipt.compute_content_hash();
    let error = receipt
        .validate()
        .expect_err("an oversized manifest must be refused");
    assert!(error.to_string().contains("over the"));
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[test]
fn the_status_exit_codes_are_the_documented_ones() {
    assert_eq!(AttestStatus::Clean.exit_code(), 0);
    assert_eq!(AttestStatus::Mismatch.exit_code(), 1);
    assert_eq!(AttestStatus::Partial.exit_code(), 3);
    assert_eq!(
        AttestStatus::Partial.worst(AttestStatus::Mismatch),
        AttestStatus::Mismatch
    );
    assert_eq!(
        AttestStatus::Clean.worst(AttestStatus::Partial),
        AttestStatus::Partial
    );
}
