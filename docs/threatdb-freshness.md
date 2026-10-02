# ThreatDB freshness

The threat database is a signed file that Tirith downloads and verifies. Its
freshness report tells you how old the database and its source data really
are, without contacting the network.

## Check freshness

```sh
tirith threat-db status --json
tirith threat-db health --json
```

Both include a `freshness` object:

| Field | Meaning |
|---|---|
| `publication_age_seconds` | Time since the signed database build timestamp. `publication_time_basis` says that the actual upload time is unknown. |
| `revision_age_seconds` | Age of the exact source commit used in this database. A months-old unchanged upstream is not automatically lagging. |
| `observation_age_seconds` | Age of the last upstream comparison included in this generation. It does not claim that upstream is still unchanged today. |
| `known_upstream_lag_seconds` | Difference between the observed upstream commit time and the published source commit time. Unknown when no matching observation exists. |
| `upstream_commits_ahead` | How many commits the verified upstream comparison is ahead. |
| `reviewed_pin_adoption_required` | The observed upstream differs from the published pin and needs review before adoption. It does not say that a review was opened or approved. |
| `lag_exceeds_reviewed_budget` | The observed lag exceeds the per-source budget in the reviewed pin manifest. |
| `accepted`, `rejected`, `accepted_fraction` | Parser outcomes when the database was compiled. They measure coverage, not completeness or effectiveness. |

`health --json` also has `last_update`: the last attempt, the failing phase and
category, the verified sequence still in use, a stable incident key, the count
of consecutive failures and the recovery time. `partial` means the primary
database updated but supplemental feeds did not. It contains no request URLs or
credentials.

## Update now

```sh
tirith threat-db update
```

Or use **Refresh threat DB now** on the [dashboard](dashboard.md)'s Settings
page; it runs the same signed update. Unless `auto_update_hours` is 0, Tirith
also refreshes the database in the background about every
`auto_update_hours` hours.

An update downloads the database, its signed source-integrity sidecar and its
merged provenance. The pinned Ed25519 key must verify the sidecar, and its
sequence, format and database SHA-256 must match the installed database. Reads
check these bindings again, so a stale or edited local evidence file cannot make
another database look current.

Downloads retry transient failures (HTTP 408, 429, 500, 502, 503 and 504, and a
stalled server) at most three times within the original time budget. Each
attempt waits for response headers for an equal share of the remaining budget;
the last attempt gets all of it. A valid `Retry-After` is honored when it fits
the budget.

## Limits

- Freshness reads work offline and never infer fresh source content from a
  recent rebuild. A future timestamp gives an unknown age and
  `clock_skew: true`, never a zero age. Missing evidence stays unknown.
- A database published without a signed source-integrity sidecar cannot report
  authenticated source ages. Run `tirith threat-db update` to retry fetching
  the evidence for the installed generation.
- A source-evidence outage never replaces or invalidates a verified database;
  freshness is then reported unavailable.
- TLS or connection-identity failures, permanent HTTP statuses, invalid
  responses, and schema, identity, completeness or integrity failures are not
  retried.
- The dashboard refresh refuses a redirected database path, an
  administrator-owned data directory, the root account, and a remote policy that
  forbids local changes.
- `age_hours` in `status` stays for compatibility; prefer the `freshness`
  fields.
