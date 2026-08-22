# Release Checklist

## Feature-specific rollout playbooks

Some releases carry their own staged-enablement and back-out procedure. Work
through the playbook BEFORE the generic steps below, because a stage-0 item can
block the merge window itself.

- [Web3 and untrusted-task boundary](web3-task-rollout.md): pause and verify the
  scheduled ThreatDB workflow, run the shadow build and the `@solana/web3.js`
  boundary regression, confirm the frozen MCP tool list and the inert policy
  defaults, then re-enable the workflow and monitor one deliberate run.
- [ThreatDB v2 rollout](threatdb-v2-rollout.md): the separate database-format
  playbook.

## crates.io publish order

Publish `tirith-core` to crates.io **first**, then `tirith`. Run
`cargo package -p tirith-core --allow-dirty` and
`cargo package -p tirith --allow-dirty` locally before publishing.

Don't try to publish `tirith` while `tirith-core` on crates.io is
older than the workspace version: `cargo package -p tirith` resolves
the `tirith-core` dep from the registry (not the in-tree path) and
will fail with unresolved imports for any symbol added in the
current cycle (`agent_origin`, `ecosystem_scan`, `package_risk`, …).

The local `cargo build --workspace` succeeds anyway because the
workspace path takes precedence over the registry version for
in-tree builds. The cross-crate failure only shows up at `cargo
package` / `cargo publish` time, which is exactly the point where
publishing tirith-core first becomes a hard prerequisite.

## Quick local check before tagging a release

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo package -p tirith-core --allow-dirty
cargo package -p tirith --allow-dirty   # may fail until tirith-core is published
```

## Linux release compatibility contract

The two GNU tarballs are cross-linked with Zig against a GLIBC 2.28 ceiling.
Both shipped executables (`tirith` and
`tirith-package-approval-authority`) are scanned before packaging, and the
release workflow executes the packaged bytes on AlmaLinux 8, Amazon Linux
2023, and Rocky Linux 9. The x86_64 test runs natively; the aarch64 test runs
under a pinned QEMU/binfmt environment. A release is not compatible merely
because `tirith --version` starts: the runtime smoke also requires an exact
allow exit code, an exact block exit code, and the helper's fail-closed exit
code. GLIBC 2.28 is deliberate: Tirith and Rust's standard library reference
`memfd_create` and `statx`, so a 2.17 sysroot cannot link without an additional
raw-syscall shim. EL8 already ships GLIBC 2.28, and adding that shim would
increase release risk without expanding the supported target set.

The aarch64 release does not overclaim x86_64-only seccomp support: extrasafe is
compiled only for linux-x86_64. On aarch64, Landlock and the remaining Linux
containment layers stay available, but `network_raw_denied` is reported false;
a locked-down capsule that requires it is degraded and fails closed. The
aarch64 release build is itself a required CI gate, preventing an x86_64-only
dependency from silently breaking the shipped artifact again. Each aarch64
runtime smoke also invokes the locked-down capsule and requires an exit-1
pre-launch refusal naming `network_raw_denied`; any child output fails the gate.
The static musl build retains the cleanup walk's exact mount-ID proof through a
size- and offset-asserted Linux `statx` UAPI buffer because libc hides those
bindings for its default musl ABI. There is no `st_dev` fallback: an unavailable
syscall or missing mount-ID result remains a fail-closed cleanup error.

The `.deb` and `.rpm` packages must contain byte-identical copies of the
canonical x86_64 GNU tarball executables. Do not restore a distro-native RPM
rebuild: it raises the GLIBC floor and would invalidate `tirith verify-self`
for DNF installs. CI extracts both packages, compares both executables, scans
every packaged ELF, installs the packages, and repeats the runtime smoke.

Pull requests that affect release inputs and manual `workflow_dispatch` runs
execute these build/package/runtime gates without publishing. Only a pushed
`v*` tag may run signing, attestations, release upload, registry publication,
or package-manager update jobs.

## Release pipeline (full sequence)

Push a `v*` tag → GitHub Actions workflow builds, compatibility-tests, then publishes to:

- GitHub Releases (signed checksums, install.sh, platform tarballs)
- crates.io (`cargo publish tirith-core` then `cargo publish tirith`)
- Homebrew (sheeki03/homebrew-tap — template sed'd from `packaging/homebrew/tirith.rb`)
- npm (6 packages — root + 5 platform, version from tag)
- Scoop (sheeki03/scoop-tirith — template sed'd from `packaging/scoop/tirith.json`)
