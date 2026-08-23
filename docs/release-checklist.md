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

## Release pipeline (full sequence)

Push a `v*` tag → GitHub Actions workflow builds, smoke-tests, then publishes to:

- GitHub Releases (signed checksums, install.sh, platform tarballs)
- crates.io (`cargo publish tirith-core` then `cargo publish tirith`)
- Homebrew (sheeki03/homebrew-tap — template sed'd from `packaging/homebrew/tirith.rb`)
- npm (6 packages — root + 5 platform, version from tag)
- Scoop (sheeki03/scoop-tirith — template sed'd from `packaging/scoop/tirith.json`)
