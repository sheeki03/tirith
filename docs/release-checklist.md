# Release Checklist

## Release sequence

Substitute the release version for `<VERSION>` throughout (for example `0.4.2`,
tagged `v0.4.2`). The changelog and release notes describe the final tree. The
workspace version stays on the previous release until the integration tree is
known, then the release commit performs the version and documentation
transition below:

1. Rebase or merge the complete integration stack onto the final default-branch
   tip and review the resulting tree, not only each stacked diff.
2. Resolve or explicitly defer every item under `[Unreleased]` → `Known issues`.
3. Run the required Linux, macOS, and Windows matrices on that exact tree,
   including native x86_64-Linux containment and host-shaped hook tests.
4. Complete the Web3/task and ThreatDB v2 rollout playbooks below.
5. Change the workspace version to `<VERSION>` in BOTH root `Cargo.toml`
   lines (`[workspace.package] version` and the `[workspace.dependencies]
   tirith-core` version), regenerate `Cargo.lock` AND `fuzz/Cargo.lock` (a
   separate cargo workspace; `.github/workflows/fuzz.yml` runs
   `cargo +nightly fetch --manifest-path fuzz/Cargo.toml --locked` followed by
   `git diff --exit-code`, and fuzz-gate blocks the release job), regenerate
   generated documentation/fixtures through their owning commands, and confirm
   every package template is materialized from the tag as designed. Do not
   hand-edit generated capability or evidence files.
6. Move the changelog content from `[Unreleased]` to
   `[<VERSION>] - YYYY-MM-DD`, write `docs/release-notes-<VERSION>.md` (the
   release job publishes the GitHub Release body from that exact path and
   silently falls back to auto-generated commit titles when it is missing),
   retarget the release-notes links in `README.md`, `TIRITH.md`, and
   `docs/compatibility.md`, and ensure README installation text does not claim
   a registry has `<VERSION>` before that registry actually does.
7. Run package assembly and the full release-validation workflow before pushing
   the protected `v<VERSION>` tag.

### Do not touch as part of a version bump

- `npm/*/package.json` and every `packaging/` template (Homebrew, Scoop, AUR,
  Chocolatey, RPM). The release workflow rewrites all of them from the tag, and
  their checked-in versions are deliberately stale placeholders.
- `V2_MIN_VERSION` in `.github/workflows/threatdb.yml`. It must equal the tag of
  the release that FIRST shipped the DB-B reader, which is 0.4.0. Bumping it on
  a patch release would strand every earlier 0.4.x client on the v1 asset.
- Version literals inside Rust sources and tests. Everything runtime-facing
  reads `env!("CARGO_PKG_VERSION")`; the rest are semver fixtures or
  `#[deprecated(since = ...)]` records of past events.
- The `NOTICE` pinned revisions are NOT part of the version bump, but they are
  hand-maintained and nothing in CI checks them. Whenever a ThreatDB source pin
  moves in `.github/threatdb-source-pins.json`, update `NOTICE` to match in the
  same cycle.

### Tag timing

`release-authority` requires the tag to point at the CURRENT default-branch
commit. `.github/workflows/threatdb.yml` pushes manifest commits straight to
`main` on its own schedule, and observed pushes span a wide range of hours, so
do not rely on a quiet window. Either disable the Threat DB Build workflow for
the release window, or confirm `git rev-parse origin/main` still equals the
release commit immediately before pushing the tag and re-tag if it moved.

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

## Release authority prerequisites

Repository settings are part of the release security boundary. Before a tag
can publish, GitHub must have an environment named `release` with required
reviewers and a deployment-branch/tag rule that admits only protected `v*`
tags. The repository must also have a ruleset that restricts creation, update,
and deletion of `v*` tags to release maintainers. Workflow YAML cannot protect
its own tag trigger from an account that is allowed to replace that YAML at an
arbitrary tagged commit, so these settings are mandatory rather than optional
hardening.

The workflow independently requires a complete semantic-version tag, requires
that tag to point at the current default-branch commit, and routes every
attestation/publication job through the `release` environment. The installer
and self-updater accept the checksum signature only from the exact
`release.yml@refs/tags/<requested-tag>` OIDC identity; a valid signature from
another repository workflow or another release tag is not interchangeable.

Release versions are single-use. Before publishing, the workflow requires the
GitHub Release, both crates.io versions, all six npm versions, and all
version-specific container tags to be absent. A pre-existing version is a hard
conflict, not a successful rerun, and GitHub release assets are never replaced.
Recover a partially published release manually after comparing the published
bytes and provenance; do not delete or overwrite public artifacts to make a
workflow rerun green. Release runner labels and the Node toolchain use explicit
versions rather than moving `*-latest` or major-only selectors.

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
protected `v*` tag on the current default-branch commit may run signing,
attestations, release upload, registry publication, or package-manager update
jobs, and each publishing job requires approval through the `release`
environment.

## Release pipeline (full sequence)

Push a `v*` tag → GitHub Actions workflow builds, compatibility-tests, then publishes to:

- GitHub Releases (signed checksums, install.sh, platform tarballs)
- crates.io (`cargo publish tirith-core` then `cargo publish tirith`)
- Homebrew (sheeki03/homebrew-tap — template sed'd from `packaging/homebrew/tirith.rb`)
- npm (6 packages — root + 5 platform, version from tag)
- Scoop (sheeki03/scoop-tirith — template sed'd from `packaging/scoop/tirith.json`)
- GHCR (x86_64 and arm64 images plus immutable version manifest; moving
  selectors advance only after version publication succeeds)
- Chocolatey (package push; availability remains pending until community
  moderation approves it)
- AUR (`PKGBUILD` and `.SRCINFO` generated from the release tag)

Homebrew core is separate from the tap publication. After the release exists,
follow [the Homebrew core update guide](homebrew-core.md) and verify the core
formula/bottles independently before describing `brew install tirith` as
serving the new version everywhere.

## Post-publication verification

- Verify the GitHub Release contains all six platform archives, the Debian
  and RPM packages, the installer, and the checksum manifest with its detached
  signature and certificate. Re-run verification against the downloaded public
  bytes, not the runner workspace. The current pipeline does not publish an
  SBOM attachment.
- Verify Debian and RPM build provenance through GitHub's artifact attestation
  service, binding the downloaded package digest to this repository's
  `release.yml`, the exact release tag, and its commit. These attestations are
  stored by GitHub, not attached as release files. npm provenance is published
  with each registry package and must be checked through that registry.
- Verify `tirith` and `tirith-core` at `<VERSION>` on crates.io and all six
  exact `<VERSION>` npm packages (the unscoped root `tirith` plus the five
  scoped `@sheeki03/tirith-*` platform packages; a scoped `@sheeki03/tirith` is
  absent by design). Test one clean and one blocked command through an installed npm
  platform wrapper.
- Verify the Homebrew tap, Scoop bucket, GHCR architecture manifest, and AUR
  package all resolve to the released checksums/digests.
- Record Chocolatey's moderation state honestly. `choco info tirith` is the
  source of truth for the approved community package; do not call the new
  version available there while it is still awaiting moderation.
- Run `tirith version --provenance`, `tirith verify-self`, and `tirith doctor`
  from representative package-manager installs and publish the final release
  notes only after those checks match the tag.
