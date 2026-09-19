# LocalLeafNoScriptsV1 installation contract

Status: proposed bounded execution contract for WP26, requiring independent
review and native enforcement evidence before a protected install route is
enabled. The shipped local npm inspection/comparison API does not authorize
installation.

## Supported request

The first execution contract accepts a bounded set of explicitly selected local
npm tarballs, a new dedicated destination, and no package-manager arguments.
Every tarball must pass the supported archive structure and metadata contract.
Every install-affecting dependency field must be captured from those exact
metadata bytes: `dependencies`, `optionalDependencies`, `peerDependencies`,
bundled dependencies and workspaces. This version refuses all non-empty such
graphs and package aliases, links, registry specs and unresolved selections.
Development dependencies are never selected. A missing capture is a refusal,
not proof of an empty graph. This is a zero-transitive-dependency contract; it
does not claim registry resolution or general npm installation support.

The npm and Node versions and their trusted executable/module closure must be
characterized together. The contract table contains only exact tested versions,
argv, metadata/output behavior and platform evidence. Unknown versions refuse
before package-manager execution. Registry signatures and provenance remain
separate evidence and cannot replace inspected artifact identity.

## Inputs and authority

A plan binds the exact compressed SHA-256 of each selected artifact, package
name/version, inspected member inventory, analyzer and limit versions, final
policy identity and private replay guard, threat-data generation, task-boundary
authorization, operator, operation UUID, tool closure, original scope and the
retained identity of the destination's parent. Source artifacts enter private
content-addressed quarantine from retained regular-file handles; arbitrary
browser paths, user-provided argv, pointers and raw filesystem writes are not
plan inputs.

Before launch, the operation revalidates policy and every bound tool/input/
destination generation under its retained authority boundary. Any changed byte,
resolution input, expiry or destination refuses. A successful preview is not an
authorization token independent of these inputs. Retries use the shared durable
operation journal and immutable intent binding; they do not regenerate a
different install under the same UUID.

Suggested pure core interface:

```rust
prepare_local_leaf_install(
    artifacts: &[VerifiedNpmArtifact],
    policy: &EffectivePolicySnapshot,
    tools: &QualifiedNpmToolClosure,
    destination: &NewDestinationIdentity,
    backend: &QualifiedCapsuleCoverage,
) -> Result<NpmInstallPlan, NpmInstallRefusal>
```

`VerifiedNpmArtifact` must be constructible only from the retained/quarantined
bytes and complete dependency-field capture. A deserialized inspection report
is never sufficient to construct it. The launcher consumes a plan together
with the exact bound input handles; it never accepts a generic command string.

## Contained launch

Scripts are always disabled with a characterized `--ignore-scripts` contract,
including npm's implicit `node-gyp` install. Configuration files, HOME, cache,
environment, project root and working directory are isolated; ambient project
`.npmrc`, node injection flags, proxies and credentials cannot redirect npm.
The install uses only staged local artifacts with offline operation and actual
deny-all network enforcement. CLI flags alone are not containment.

The child receives read access to the immutable staged artifacts and qualified
tool closure, and write access only to a fresh transaction tree. It cannot write
the existing project or an existing environment. The launcher requires native
filesystem, raw-network and resource restrictions and fails closed when any
required primitive is missing. It uses the existing bound-input capsule path,
never the uncontained generic install runner.

The exact npm argv remains part of qualification: candidate controls include
offline mode, ignored scripts, no audit/fund/update checks, disabled bin links,
no root lockfile/save mutation, and an explicit transaction target. Their
complete interaction must be observed on the pinned npm version, including
hidden lockfiles and package metadata rewriting, before that argv is admitted
to the closed contract table.

## Verification and recovery

After npm exits, no result is published until a retained-handle tree walk
verifies every expected installed file against the inspected member SHA-256,
rejects new links/special files and unexpected package content, and accounts for
the explicitly characterized manager-generated metadata. A package-manager
success exit is not proof of installation integrity.

Only a verified new tree can be published at the reserved destination through a
retained-parent transaction. No existing environment is overwritten. The shared
journal records staging, launch acceptance, child completion, verification and
publication. Cancellation or crash before publication leaves only owned staging
state; recovery never reruns an accepted install without establishing its prior
outcome. Cleanup requires the original owned directory identity. External edits
or uncertain publication produce a recovery-required state, not blanket
rollback or deletion of user state.

## Required acceptance evidence

- Real supported npm/Node version and complete argv/output characterization.
- Artifact replacement, tool/config/policy drift and changed destination refusal.
- Dependency/peer/optional/bundled/workspace substitution refusal.
- Lifecycle and implicit native-build sentinel scripts never execute.
- Native denial of network access and writes outside the transaction tree.
- Post-install member verification and unexpected-file/link detection.
- Child failure, cancellation, interruption, identical retry, publication race
  and cleanup under replaced directories.

The available Docker server uses an aarch64 Linux 6.12.76 kernel. A separate WP27
native aarch64 Landlock/seccomp qualification is in progress; existing protected
package approvals still require x86_64. An emulated x86_64 process on that ARM
kernel is not evidence of native x86_64 seccomp enforcement. Native x86_64 CI or
a separately qualified aarch64 package-launch path is required before enabling
this execution capability.
