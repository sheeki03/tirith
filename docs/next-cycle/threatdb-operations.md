# ThreatDB freshness and recovery

`tirith threat-db status --json` and `tirith threat-db health --json` include a
`freshness` object. These reads work offline. They never contact upstream or infer
fresh source content merely because a database was rebuilt recently.

The report separates:

| Field | Meaning |
|---|---|
| `publication_age_seconds` | Time since the signed database build timestamp. Actual upload completion is unknown; `publication_time_basis` states this limit. |
| `revision_age_seconds` | Age of the exact source commit used in this database. A months-old unchanged upstream is not automatically lagged. |
| `observation_age_seconds` | Age of the last upstream comparison included in this generation. It does not claim that upstream is still unchanged today. |
| `known_upstream_lag_seconds` | Difference between the observed candidate commit time and the published source commit time. Unknown when no matching observation is available. |
| `upstream_commits_ahead` | Verified upstream comparison's commit count, independent of commit timestamp differences. |
| `reviewed_pin_adoption_required` | The observed upstream candidate differs from the published pin and needs review before adoption. It does not claim that a review PR has already been opened or approved. |
| `lag_exceeds_reviewed_budget` | Observed lag exceeds the per-source budget in the reviewed pin manifest. |
| `accepted`, `rejected`, `accepted_fraction` | Compiler parser outcomes. Counts measure coverage; they do not independently prove completeness or indicator effectiveness. |

Future timestamps produce unknown ages and `clock_skew: true`, rather than zero
age. Missing legacy evidence and observations remain unknown. Status retains the
existing `age_hours` field for compatibility.

## Trust and acquisition

An update downloads the immutable generation's source-integrity sidecar and
merged provenance. The pinned Ed25519 key must verify the sidecar; its sequence,
format and database SHA-256 must match the installed blob. Canonical source and
compiler digests must both match. Reads revalidate these bindings, so a stale or
modified local evidence file cannot make another database appear current.

Source evidence is cached separately for v1 and v2 as one atomic record per
format. A source-evidence outage does not replace or invalidate a verified
database; freshness is reported unavailable if the retained evidence does not
match. Generations published without a signed source-integrity sidecar cannot
provide authenticated source ages. Run `tirith threat-db update` to retry
evidence acquisition for the installed generation.

The read-only upstream observer compares each reviewed pin with a completed
upstream revision. Its observations enter compiler metadata and therefore the
signed source-integrity contract. Neither observing nor publishing adopts a pin.
The existing watcher still proposes updates for review. A failed observation
prevents the publication run from claiming a complete fresh observation.

## Failure and retry behavior

Manifest, index, database and registry request recovery is bounded by the original
source deadline and at most three attempts. HTTP 408, 429, 500, 502, 503 and 504
are retryable. Valid numeric and HTTP-date `Retry-After` values are honored; a
delay exceeding the remaining budget refuses the retry. Unclassified TLS or
connection-identity failures, permanent HTTP statuses, invalid HTTP 200 bodies,
schema, identity, completeness and integrity failures are not retried as data.
Mutable feed curl requests likewise use selected transient retries, a transfer
cap and the existing source/transaction timeout wrapper. Git operations remain
bounded and fail once because their errors do not reliably distinguish identity
failures from transient transport failures.

The source transaction still exposes inputs only after all required sources
validate. The compiler retains its signed baseline, unique-record minimums,
per-source and per-section drop gates, and atomic signed generation commit point.
No validation failure republishes a partial source set. A partial supplemental
feed outage preserves the entire prior supplemental database.

`health --json` also includes `last_update`: a bounded record containing the last
attempt, failing phase/category, retained verified sequence, stable incident key,
consecutive failure count and recovery timestamp. It contains no raw request URLs
or credentials. `partial` means primary processing succeeded but supplemental
reconciliation failed. The category is diagnostic; it does not authorize retries.

## Publication operations

Before pruning, the publisher independently verifies primary and fallback
discovery, every referenced immutable database's size/hash/signature/sequence,
and source provenance. It then runs the actual CLI with empty data/state caches
and verifies its installed generation and authenticated freshness. A failure
prevents pruning and is retained as an operational artifact.

Each run has one structured `threatdb-run-report.json` and one summary. Stable
incident keys group repeats by failed phase. The prior completed workflow outcome
distinguishes recovery from ordinary success. Failure before publication reports
the retained generation; failure after upload reports partial/unverified
publication and instructs the operator to check both discovery surfaces. These
reports do not post new issues or adopt pins automatically.

## Count calibration and verification

The existing fail-closed gate rejects a source or section loss greater than 50%
against a signature-verified baseline. Required-source floors remain source
specific: OpenSSF, DataDog, CISA and typosquats require at least 100 records;
Feodo requires a nonempty feed because its reviewed live baseline contains five
addresses. Parse acceptance fractions are now reported but do not introduce a
new universal gate. Review historical per-feed fractions and count changes before
tightening thresholds; otherwise legitimate feed cleanup could block publication.

Deterministic tests cover old unchanged upstream, reviewed-pin lag, timezone
equivalence, future clocks, missing observations, wrong signatures/generations,
provenance tampering, transient retry/backoff limits, invalid successful responses,
partial upload, replayed pointers, stable incident keys and recovery. Existing
tests cover missing/empty required sources, transactional cleanup, signed baseline
loss, generation commit failures, rollback and same-second cache replacement.
