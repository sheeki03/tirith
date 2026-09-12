# Browser lifecycle operations

The Settings view reads local lifecycle and ThreatDB facts without network
requests. Checking releases, preparing a refresh, and applying a stored operation
are separate explicit actions. A browser request supplies a typed action or a
canonical operation UUID; it never supplies an executable, write path, URL,
command line, package-manager command, credential, or sudo flag.

## Shared service contract

`read` returns offline installation/channel/version facts and current database
health. `prepare(operation_id, action)` first reserves the caller-generated canonical
UUID with the exact action, operator, working directory and client. It then
resolves and verifies the candidate and records the immutable preview under that
same ID. A retry returns the existing result before any network request; an
interrupted reservation cannot select another candidate and requires a fresh
explicit request. `apply(id)`
accepts only the immutable recorded plan; `status(id)` reports its persisted
phase and result. The CLI and browser consume typed results from the same
verification/publication primitives. They do not parse each other's terminal
output or rerun a mutable `latest` selector at apply time.

An update plan binds the current executable and rollback preimages, selected
release tag/target, signed compatibility document, archive and executable hashes,
signature-verifier identity, current policy replay guard, local format
observations, operator, canonical working directory and private state-directory
identity. A rollback plan additionally binds the saved binary's compatibility
receipt. A ThreatDB refresh plan binds a validated signed index/manifest and the
selected asset identity and sequence. Browser refresh has no forced rollback or
unsigned mode. Optional supplemental failures are reported as partial success
while preserving the previous valid overlay.

User-owned, resolved standalone installations and proven Hermes installations
may be eligible for browser binary updates. Package-managed, unknown, privileged,
root-owned, protected-helper-dependent and unsupported replacement paths return
precise owning-channel or CLI instructions. Browser actions never invoke sudo,
request administrator credentials, change helper ownership, or silently switch
channels. Helper state is checked again at mutation time.

## Handoff, retries and recovery

The control service cannot wait for its own update job to drain. Binary changes
therefore use a separate trusted worker launched from the retained current
binary identity. The service returns an accepted operation ID. The worker
revalidates the immutable plan, original binary, policy/tool context and retained
operation-directory identity, then acquires the existing service update guard.
Acquiring that guard stops new service mutations and drains existing work before
publication; it keeps launch and service-lifetime locks through replacement and
post-publication verification.

The operation journal is independent of the browser session and contains no
browser bearer token. It records publication intent before the atomic swap and
the verified result afterwards. On restart, status checks the worker lock. An interrupted accepted or verifying
operation becomes refresh-required; a publication-intent or published operation
without a worker becomes recovery-required. No resumed worker receives authority
from serialized inode numbers after the original handles are lost. A committed
swap is never repeated; ambiguous publication requires explicit inspection. Retrying cannot
choose another release, reinterpret edited evidence, or discard a partial
result. Journal edits, expired plans and changed policy require a fresh preview.

After a verified result, only the fixed verified resulting executable may start
its own control service. That executable creates its own fresh authenticated
browser URL. The previous service's token is neither copied nor stored as an
operation result. A failed restart does not erase a successful binary change:
the operation reports the verified installed version plus explicit dashboard
reopen and shell/host reload instructions. A failed update can relaunch the
retained old binary only after its identity is revalidated.

Private operation files and worker locks use the existing scoped, no-follow,
owner-checked filesystem transactions. Retained directory handles prevent path
rebinding between phases. Operation counts, bytes, age and worker concurrency
are bounded; unfinished or manually edited recovery evidence is not silently
deleted to admit another operation. Preparation can be cancelled before apply;
after publication begins, recovery follows observed identities rather than a
blind compensating overwrite.

## Acceptance evidence required

Test offline Settings, explicit network actions, signed metadata substitution,
exact-tag retry, changed old binary/backup/policy/verifier, package-manager and
helper refusal, duplicated apply, concurrent workers, quiesce with pending jobs,
service death before and after publication, directory replacement, failed service
restart, and status recovery from a newly opened dashboard. ThreatDB fixtures
also cover partial supplemental refresh and preservation of signed last-known-good
data. Native Windows replacement remains unavailable until its process/image
replacement path is separately exercised; a file-copy model cannot establish it.

Private request reservations survive lost responses and process restarts. Failed
preparation cannot reuse its ID to rerun a mutable selector. Plans expire after
15 minutes, at most 16 binary previews and 16 ThreatDB previews retain live
handles, and the durable store retains at most 64 requests. Bounded private
failure diagnostics are separate from public views; publication evidence is
never silently deleted to admit another request. Cosign and archive extraction
use trusted executable checks, bounded output and explicit deadlines.

If the process stops between writing an immutable plan and its initial result,
status returns a non-applicable refresh-required view with no candidate. It does
not reconstruct a result or application authority from the orphaned file.
Incomplete publication evidence must be retained and inspected before preparing
another request.

Support export can read an explicitly selected lifecycle UUID from an existing
private store without creating files, taking mutation locks or reconciling its
phase. The exported view includes a bounded fixed failure summary when available.
Private payloads, local paths, verifier identities, policy replay proofs and raw
failure diagnostics stay out of that export.
