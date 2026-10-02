# Operator trust grants

New grants live in the operator configuration directory's `trust-grants.json`.
Its version-one envelope has `schema_version` and `grants`; it deliberately has
no `entries` member. A 0.4.2 client ignores this store. Even if someone copies
this envelope over a legacy `trust.json`, that client's entry reader finds no
grants. A new project grant never enters a legacy globally interpreted entry.

Each new record has a random UUID, target pattern, optional rule, scope,
creation timestamp, optional expiry, optional reason and optional revocation
timestamp. UUIDs are public identities, not hashes of sensitive target content.
The operator store and the mutation journal are private files. CLI projections
redact targets, rules, reasons and project paths while preserving validated
identities and lifecycle states.

`tirith trust add URL --rule RULE` creates an expiring grant with a 30-day
default. A domain or wildcard requires `--broad`. Omitting a rule requires the
separate explicit `--all-rules` opt-in; existing scripts receive a migration
message rather than silently gaining all-rule permission. Suggestions retain
the exact target/rule evidence where available. Applying a last-trigger
suggestion refuses missing-rule or domain-only evidence; the operator must
choose broadness explicitly.

`--scope project` stores an operator-owned grant bound to a checkout's canonical
root, filesystem object identity and creation timestamp, captured through a
retained directory handle. The operator home identity is bound as well, so
copying configuration to another user does not reuse a grant. Creation timestamps
prevent a recycled inode from reviving a deleted checkout's grant. It covers
that checkout's ordinary subdirectories. Symlink aliases to
the same checkout agree; sibling repositories, nested repositories with their
own `.git`, and linked worktrees have different roots. Moving or replacing a
checkout requires re-enrolment. A copied configuration does not match a different
checkout identity. Platforms without usable filesystem identity and creation timestamps refuse
project enrolment. A repository-owned `.tirith/trust.json` remains recorded and
inactive; it cannot authorize its own contents.

The shared validator produces `recorded`, `effective`, `overridden`, `expired`,
`revoked` and `invalid` states. An effective grant is an eligible exception;
independent blocklists and other security decisions may still block an
operation. An expiry at or before the current instant is expired. Malformed
dates and non-string expiry values are invalid, never permanent. Display and
runtime use the same validator.

`tirith trust expiry ID --ttl 1h` changes the identified record, preserving its
scope and identity. Repeating `add` for one matching active grant also replaces
that grant's expiry instead of appending beside a permanent copy. Ambiguous
duplicates require an explicit ID. `tirith trust revoke ID` retains a revoked
record and reports remaining broader grants. Pattern-based `remove` preserves
its legacy selection behavior while revoking selected new records and showing
remaining matching permission. `list --expired` includes expired and revoked
records; malformed and inactive repository records remain visible.

`explain ID` resolves the private target and selected rule from the stable grant
identity; browser clients never reuse redacted target text as an identifier.
Its matching effective grants include broader user and policy permissions even
when the selected record is project-scoped or revoked. This reports trust
eligibility only: it does not evaluate a command or clear independent blockers.

Legacy user entries keep their existing scope until an explicit
`tirith trust migrate --scope user`. Migration assigns UUIDs, preserves expiry
and rule scope, retains malformed raw records for repair, and removes migrated
entries from the legacy envelope. Older clients then lose those migrated
exceptions. Repository entries cannot be globally migrated; create individual
operator-owned project grants after review. A matching legacy entry must be
migrated before adding or shortening its new counterpart, so a permanent
legacy copy cannot silently defeat the shorter expiry.

Mutations use the shared typed, revision-bound operation service and
configuration-write authorization. The journal binds exact preimages, owned
postimages, operator and policy authority. Refresh and retry are explicit when
authority changes. Multi-file migration removes legacy applicability before
activating the new envelope, so interruption can temporarily narrow trust but
cannot widen it. Runtime resolves both stores for every request, including
daemon requests, and snapshots retain the earliest accepted expiry plus input
revisions. Removing a grant or reaching its deadline needs no cache-file
rewrite to affect the next request.

Regression coverage resides in `trust_grants` core tests and the
`trust_lifecycle` CLI tests: old envelope compatibility, invalid expiry,
stable-ID edits, remaining broader grants, checkout identity boundaries,
project-store removal, migration, explicit broadness and redacted projections.
