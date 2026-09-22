# LocalLeafNoScriptsV1 installation contract

Status: the bounded WP26 implementation is registered for review and tracking.
Native execution remains disabled on every host until the complete launch,
publication and recovery route passes qualification. Inspection, comparison and
saved review records do not authorize installation. Administrator access and
confirmation flags do not enable the route.

## Command lifecycle

On Linux, `tirith pkg install-npm plan ARCHIVE... --target NEW_DIRECTORY`
reinspects exact local archives and records an immutable review intent. Its
output identifies the operation and the digest to review. `status OPERATION`
reads historical observations. `apply OPERATION --reviewed DIGEST` requires that
exact review and recaptures current inputs, policy and task authority; it
currently refuses at the native qualification gate before recording a start.

The review digest commits to the entire intent, including private policy inputs,
working directory and retained archive generations. A private random nonce
prevents that public digest from exposing a guessable policy commitment. Editing
private state requires a different review digest even when the public display
looks unchanged. Display redaction never rewrites the canonical intent.

`undo OPERATION --reviewed DIGEST` can withdraw an unstarted intent. A started
operation cannot be replayed or treated as unstarted merely because its final
response is missing. `recover OPERATION --reviewed DIGEST` can reconfirm an
already published tree using exact signed completion milestones, linked receipts
and fresh archive, policy, threat-data and task checks. It never replays npm or
modifies the target. Missing, private-only, changed or ambiguous state is
preserved. All routes accept `--json`. Other platforms refuse before creating
installation intent state.

This uses separate private `npm-install-intents` and `npm-install-recovery`
stores. Update and rollback compatibility require explicit readers for both
schemas. The local
`pkg materialize` command retains its separate data-only contract.

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

Preparation now captures the actual signed offline threat source and evaluates
the retained artifact bytes under the current effective policy. It refuses
missing or stale threat data, incomplete analysis and any decision other than
Allow. A caller-supplied threat generation or inspection report cannot substitute
for that decision. The plan retains the source handles and private decision
commitment and revalidates them before staging or other effects. This closes the
preparation authority gap; it does not enable the contained install launcher.

The source must be a current, production-signed ThreatDB v2 with artifact-hash
coverage. A valid v1 signature alone cannot provide that coverage. The published
v1 feed is insufficient for this route; a qualified v2 feed is a prerequisite,
not something administrator privileges can replace.

Before launch, the operation revalidates policy and every bound tool/input/
destination generation under its retained authority boundary. Any changed byte,
resolution input, expiry or destination refuses. A successful preview is not an
authorization token independent of these inputs. Retries use the shared durable
operation journal and immutable intent binding; they do not regenerate a
different install under the same UUID.

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

The registered ARM64 launch path passes sealed descriptors for the pinned Node
executable, bootstrap, npm runtime pack, archives and empty configuration. The
protected child copies Node into its own execute-only sealed inode so a peer
cannot change its permissions through the parent's copy. Only nine exact
runtime files receive filesystem read grants; only the pinned ELF interpreter
receives an execution grant. Writable grants cover the new private target and
temporary cache. The existing generic private-input execution path stays
disabled.

The launcher requires native filesystem, raw-network and resource restrictions
and refuses when any required primitive is missing. Its ARM64 seccomp filter
restricts `execveat` to the initial numeric Node descriptor and denies pathname
execution. That numeric check is not a stateful one-execution guarantee:
descriptor reuse remains possible, and the pinned interpreter has an execution
grant. Qualification must test this boundary; the source implementation alone
does not establish containment.

The exact npm argv remains part of qualification. Fixed controls include
offline mode, ignored scripts, no audit/fund/update checks, disabled bin links,
no root lockfile/save mutation, and an explicit transaction target. Their
complete interaction is bound to Node 26.7.0 and npm 11.19.0, including the entire
hidden lockfile and physical target path used in its package keys. Native stock
npm characterization has passed for the sealed bootstrap, but the full Tirith
launch and output-verification transaction still needs native acceptance.

## Verification and recovery

After npm exits, no result is published until a retained-handle tree walk
verifies every expected installed file against the inspected member SHA-256,
rejects new links/special files and unexpected package content, and accounts for
the explicitly characterized manager-generated metadata. A package-manager
success exit is not proof of installation integrity.

Only a verified new tree can be published at the reserved destination through a
retained-parent transaction. No existing environment is overwritten. The shared
journal records staging, launch acceptance, child completion, verification and
publication. Cancellation or crash may leave private staging and an uncertain
execution outcome. Unknown child cleanup preserves the checkpoint. Recovery
must never rerun an accepted installation. Cleanup requires retained current
directory authority and verified state; a saved inode number alone does not
prove ownership across a crash. External edits or uncertain publication require
preservation. Published environments are never recursively deleted by this
transaction.

Only the native supervisor can produce the in-process completion witness used
to sign a private completion milestone. It requires a successful authenticated
launch, zero exit, complete containment and observed child/cache cleanup. A
second signed milestone binds the linked committed receipt and the whole
published tree. Recovery verifies both signatures using the trusted audit key,
rechecks exact receipt contents and freshly observes every tree entry, file
digest and metadata generation. A key supplied inside a milestone is never
trusted. A signing challenge checks the configured private/public key pair
before launch; mandatory milestone verification checks it again afterward.
This establishes agreement with a recorded completed installation; it does not
establish uninterrupted inode ownership or ongoing immutability. Private cleanup
after a restart remains unavailable when retained ownership or quiescence cannot
be established.

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
native aarch64 Landlock/seccomp backend has passed its separate primitive and
launcher checks, but that does not qualify this npm transaction. Existing
package execution remains disabled. An emulated x86_64 process on an ARM kernel
is not evidence of native x86_64 seccomp enforcement. The complete native npm
contract must pass before this execution capability is enabled.
