# Installation and lifecycle evidence

`tirith version --provenance --json` and the local lifecycle API report separate
facts for the running binary, release discovery, the owning package channel,
and an inherited shell integration. Reading these facts does not execute other
Tirith binaries, query package managers, request elevation, or establish that a
hook actually blocks commands.

## Version and channel facts

The installed version comes from the running binary's build metadata. Release
and channel-available versions remain null until their own source is queried;
GitHub release discovery does not establish availability in a package-manager
repository. A loaded integration's `TIRITH_INTEGRATION_VERSION` and
`TIRITH_INTEGRATION_SHELL` are inherited, unverified evidence. Equal versions do
not establish active protection. A mismatched version requires a fresh shell or
host reload and another behavioral verification. An absent marker means unknown.

Generated shell activation stamps a version only when the sourced hook bytes
match the binary's embedded hook. An older external hook bundle reports
`unknown`. PATH scanning counts distinct resolved binaries with a bounded scan;
unresolved wrappers and an incomplete scan remain explicit.

| Owning channel | Detection and upgrade behavior |
| --- | --- |
| Shell installer / standalone | Only a resolved installation in a recognized user-local location can self-update. Existing protected helper state remains a paired transaction. |
| Hermes | Requires the existing exact ownership/provenance proof; an expired proof refuses replacement. |
| Debian / RPM | Distro refinement is limited to recognized system binary directories. Use the owning package manager. |
| Homebrew / npm / Cargo / Scoop / AUR | Existing channel-specific paths and package-manager guidance apply; the CLI does not replace managed binaries. |
| Chocolatey | Recognize the package's `chocolatey/lib/tirith` path. Use `choco upgrade tirith` with the permissions required by that Chocolatey installation. |
| Nix | Recognize the immutable `/nix/store` path. Update the owning profile, flake, or Home Manager configuration. A source-built binary is honestly unverified against generic release bytes. |
| mise | Recognize Tirith's GitHub/Cargo backend install paths. Use `mise upgrade tirith --no-prune` to retain the previous installed version. The Cargo carveout requires Tirith's own valid local Cargo install record. |
| asdf | Recognize `.asdf/installs/tirith` and custom `asdf/installs/tirith` paths. Install with `asdf install tirith latest`, then select the intended project/user scope explicitly with `asdf set`. |
| Unknown / custom / unresolved shim | Remain non-self-modifying. Host OS alone cannot turn an arbitrary path into a package-manager installation. |

The [mise upgrade reference](https://mise.jdx.dev/cli/upgrade.html),
[asdf version-management reference](https://asdf-vm.com/manage/versions.html),
and [Chocolatey upgrade reference](https://docs.chocolatey.org/en-us/choco/commands/upgrade/)
describe those manager commands and their scope. Retaining an older binary does
not automatically make newer policy, grant, lock, or journal formats compatible
with it.

## Signed compatibility artifact

Release publication creates `release-compatibility.json` before generating
`checksums.txt`; the existing exact-tag Sigstore signature covers its checksum
alongside every other payload. The document binds the release version, each
canonical target archive SHA-256, the exact root CLI executable SHA-256, readable
format versions, lock formats that can authorize execution, and service/journal
contracts. Generation reads archive members without executing candidates. It
rejects missing targets, duplicate or escaping members, links, special files,
and oversized archives. Changed format constants require review of the contract
before another publication.

| Stored surface | Current reader | Compatibility consequence |
| --- | --- | --- |
| Policy | Schemas 1 and 2; forward migration occurs in memory | Future or malformed versions fail closed. Updates preserve existing file bytes. |
| MCP lock | Formats 4–8 readable; only 8 authorizes a live gateway | Older formats are migration inputs and require explicit reapproval. |
| Legacy trust | Version 1 | Existing expiry and authority rules continue to apply. |
| Scoped trust grants | Store schema 1 | 0.4.2 ignores the separate grant store; downgrade loses these exceptions rather than making them global. Unknown newer schemas are inactive. |
| Operation journal | Schema 1 with the exact originating client version | Another client version cannot silently replay or undo an old mutation. |
| Local control service | Protocol 1, exact binary version and SHA-256 | Reuse requires the full identity; an update must quiesce writes and reconcile pending jobs. |
| Team connection, enrollment, report and rollout records | Each schema 1; team policy semantics 1 | Candidates must retain team Runtime enforcement and explicit report/rollout recovery. A missing reader or capability refuses update and rollback, even if the old binary has the same package version. |
| Shell execution receipts | Schema 3 active/unacknowledged records; schema 4 acknowledged terminal records | A hook acknowledges only an observed terminal result. Schema 4 is non-authorizing and eligible for the next locked cleanup; schema 3 recovery windows are preserved. Schema 1/2 are authenticated retirement inputs only. Older readers reject schema 4; missing reader declarations refuse update/rollback. Hook capability schema 3 is unchanged. Explicit ACK may end only its own exact clean shell-boundary record's retention at the actual acknowledgment time, advancing the ledger generation without upgrading its unresolved evidence. The observation remains available to normal reads until existing pressure or stale-session cleanup reclaims it; warnings, escalation, typed events and later transitions keep their existing retention. |
| Local materialization intent/events, target checkpoints and recovery inventory | Each schema 1 | Linux recovery continues to require fresh policy, task authorization and exact current ownership. Format compatibility never authorizes a replay or removes retained records. |

The closed `persisted_formats` contract names these readers separately. A missing
contract in older signed metadata or rollback evidence means unsupported; it is
not filled from the running client's capabilities. Publication checks the actual
writer/reader constants and refuses an unreviewed format change.

Inventory reads only fixed private team files, the bounded team rollout directory,
the bounded materialization intent/event directory, and shell receipt declarations
in the private session receipt directory. Known receipt locks and hook capability
filenames are skipped; this inventory does not authenticate or declare compatibility
for their payloads. The same captured bytes
also expose document schemas and policy semantics inside enrollment caches and
both rollout policy documents; future or malformed nested declarations refuse.
It uses the existing
guarded native readers, caps directory entries and total bytes, and reports
unknown names, partial scans, changed inventories and unreadable records as
incompatible. These observations expose no credentials, stored contents or paths.
Target-local materialization checkpoints are **not discovered** by this inventory;
the required recovery contract preserves the reader capability, and an explicit
recovery must recapture its exact target and journals. This is not a claim that
all pending operations have been discovered, reconciled, or successfully recovered.

Local format observations report only the surface, declared version, and
readability. They omit policy contents, grant patterns, service credentials,
and paths. A declared version is unverified local metadata, not a successful
candidate compatibility check. Unknown, malformed, and future versions remain
visible rather than being treated as empty legacy state.

`tirith update --dry-run --json` fetches the compatibility document and checksum
verification material without downloading or executing the candidate binary.
Its preview binds the selected release, target archive and executable hashes to
the readable local formats. Replacement repeats the format and preimage checks
before publication. Missing compatibility metadata, unreadable local formats,
unsupported feature contracts, or an invalid signature refuse the update.
An explicit `--allow-unsigned` can accept missing signature tooling or material;
the evidence then says checksum-only and does not claim signature verification.
It never permits an invalid available signature.

Before replacing a running binary, the updater preserves its current format
contract in an adjacent receipt bound to that binary's exact SHA-256. Rollback
checks this receipt against the saved executable and current local formats,
preserves configuration bytes, and refuses modified evidence. These receipts
record the previously running binary's contract; they are not release signatures.
Older backups without a receipt require a compatible release through the owning
installation channel. Retention is bounded to 64 receipt generations; reaching
that bound requires reviewing obsolete receipts while keeping those for the live
and saved previous executable. Updates do not erase manually edited evidence.

Update and rollback quiesce the current operator's local control service and
retain its launch and lifetime locks through replacement and verification. Active
jobs must drain within the bounded wait; the updater does not force-kill them or
claim to quiesce another user's service. A fresh shell or host reload and another
behavioral verification are required after replacement.

## Owned configuration and removal

Configuration changes use the shared operation journals and ownership-aware
change plans. Undo restores only unchanged owned fields, blocks, or files; newer
manual edits are conflicts. An update must not copy old configuration wholesale
over current user edits. Disablement, removing an integration, uninstalling the
owning package, and deleting retained data are separate operations. Package
installation or removal follows the administrator policy for that destination;
personal setup does not implicitly select another user's home or invoke sudo.

The optional native package-approval capability is separate from ordinary
command checks and shell protection. Package metadata does not install or
suggest sudo. Explicit approval issuance requires a supported host, protected
helper, trusted sudo, and fresh interactive administrator confirmation.
