# Effective policy snapshot v1

`EffectivePolicySnapshot::resolve(cwd, Runtime)` executes the same resolver as
enforcement: trusted local baseline, repository tightening, configured remote
replacement/fallback, incident restrictions, operator and repository lists,
operator trust, and context/SSH labels. `LocalOnly` remains an explicitly limited
diagnostic. It omits remote resolution and separate list/trust/label files.

The observer records input bytes when the runtime reads them and records field
contributions at the actual composition boundaries. It does not discover or read
policy a second time to manufacture provenance. Missing discovery candidates
are revision inputs: creating a policy after preview invalidates a defaults-only
snapshot. A source can constrain a field even when the existing value is already
equally restrictive. Repository neutralization includes its reason and source.

`policy effective --runtime --json` exposes the snapshot identity, primary/all
input revisions, field sources, constraints, operator target scopes, trust
generation and nearest accepted grant expiry, requested profile and effective
customizations, and remote availability/fallback/freshness. The legacy policy
object remains a redacted display projection. It must never be reapplied as YAML.
Paths and dynamic field keys are projected; opaque identities and protocol
status values are preserved even with broad custom DLP expressions.

Revision IDs are random identifiers of this particular observation. No public
revision is a hash of secret-bearing policy bytes or environment credentials.
The snapshot and its private witnesses are not serializable and their Debug
projection omits policy values. The protected operation journal may persist a
`PrivatePolicyReplayGuard`, which binds canonical effective policy and actual
captured inputs; that guard is private comparison material and must never be
included in public output. It is neither a bearer token nor permission to write.

`revalidate_inputs()` compares the captured inputs using the original scoped
readers and rejects changed bytes, new/missing files, changed roots/environment,
incident changes, or expired grants. Trusted managed policy symlinks continue
using the bounded symlink-following reader; repository reads retain their
no-follow containment. Revalidation reads fresh incident semantics. It does not
re-fetch remote policy or create a second policy snapshot.

`revalidate_for_mutation()` additionally requires full Runtime resolution and
rejects configured remote authority. The current remote fetch protocol has no
atomic server revision precondition; re-reading a local cache cannot prove that
the server still authorizes a write. Mutation services must still authorize the
operator and scope, lock and compare target preimages, apply once, and verify
effective readback. A local snapshot revalidation is not a filesystem transaction.

Successful validated fetches retain client receipt/validation times and bounded
Date/ETag/Last-Modified evidence. Cache metadata is stored in a separate receipt
bound to the exact origin/credential-bound v1 cache envelope bytes, preserving
compatibility with old binaries that reject unknown cache fields. An older cache,
missing/malformed receipt, mismatched generation, or future timestamp reports
unknown freshness without changing established cached-fallback enforcement.
Server headers are evidence, not authority. A cache write/receipt interruption
can lose freshness evidence but cannot certify a mismatched policy generation.
