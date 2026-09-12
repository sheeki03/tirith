# Reviewed local profile rollouts

`tirith policy rollout prepare balanced --command 'curl https://example.com/x' --json`
captures a bounded command-impact report and saves a personal profile operation.
It does not run the commands or activate the profile. Use `--command` repeatedly
for up to 32 workflows, with at most 4096 bytes per command and 64 KiB total.
`--shell` selects the grammar and `--interactive` models an interactive boundary;
these preview facts do not authorize execution. Session evidence remains
explicitly unavailable.

The response contains the operation UUID. Inspect it with
`tirith policy rollout show UUID --json`, activate it explicitly with
`tirith policy rollout activate UUID --json`, and undo its owned changes with
`tirith policy rollout undo UUID --json`. The same commands are available through
the local control service's typed rollout interface. Personal operation does not
require a cloud service. Managed restrictions continue to apply.

The report and profile change are published atomically in the shared private
operation journal. Supply `--operation-id UUID` to retry preparation after a
lost response. The immutable intent binds the complete command corpus, profile,
shell/interaction choices, operator, client version and original working scope.
An identical retry returns the original report, including a no-change outcome;
a different intent at the same UUID is refused. Changing policy inputs before
activation requires a new review. A review at least 24 hours old, or with a
future timestamp, cannot be activated. Undo uses the existing retained-target
transaction and preserves unrelated edits where the ownership contract allows.

Each workflow reports its captured decision, proposed decision, rule identifiers
and unavailable evidence. The model reevaluates the same FrozenEvaluation under
both policies without another command execution, network request or observation
write. Detector-policy changes and unresolved managed/repository/incident
composition produce unavailable impact, rather than a fabricated tightening or
relaxation. Session, runtime enrichment and other existing preview gaps remain
visible even when the supported post-detection comparison is available.

The exception inventory identifies operator-owned stable grants by UUID and
shows their scope, owner evidence, expiry and eligibility. Eligibility is not
permission to execute a command. Legacy, invalid or over-limit inventory is
explicitly incomplete. Expired grants stay expired; repeated warnings or a
positive impact report never renew or approve an exception.

Local activation status, observed profile selection and client adoption are
separate facts. A local Runtime snapshot can show equivalent effective policy
at its observation time; a supplied client report cannot prove adoption. Stored
client observations are historical and their timestamps remain visible. Remote
publication and verified fleet adoption are unavailable in this local workflow;
the interface never claims that saving or activating one local profile updated
other clients. No remote write falls back to local authority.

The existing remote contract fetches YAML with authenticated HTTPS from
`GET /api/policy/fetch`. The remote policy replaces the local baseline; its cache
remains bound to the selected endpoint and credential. Fetch time, ETag and
Last-Modified are observations. They are neither a signed policy revision nor a
conditional publication receipt. The repository currently defines no remote
policy write or client-adoption acknowledgement protocol.

Remote activation needs a server-supported atomic revision precondition and a
defined conflict outcome, with the exact proposed policy bound to the reviewed
operation. Verified fleet adoption additionally needs authenticated client
identity, applied revision and observation time, with offline, stale and partial
responses represented separately. A successful fetch or audit upload cannot
substitute for those facts. Until that contract exists, remote-authorized
mutation is refused; a managed local policy also requires its own operator
scope rather than a personal-profile write.

Canonical impact attachments contain typed fields, UUIDs, counts and timestamps.
Raw commands, labels, grant patterns, owner names and reasons are not copied into
them. Operation destinations and current diagnostics are redacted with freshly
captured DLP patterns on every read. Core limits are 128 workflows, 512 exceptions,
1024 client observations, 32 rule IDs per workflow and a 256 KiB attachment.

Tests cover repeated frozen evaluation, changed detectors, stale/future evidence,
expired/unverified-owner grants, partial and unverified adoption, invalid stored
claims, same-ID retries, explicit activation and undo with unrelated edits.
