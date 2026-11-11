# Threat-DB v2 staged rollout runbook

The threat database is a signed binary blob. Bumping its on-disk format is not a
single switch: an old binary handed a newer-format file rejects it, and
`ThreatDb::cached()` returns `None` on a load failure, which is fail-OPEN (every
DB-backed detection silently stops). So the v2 migration is staged so that no
client is ever served data it cannot read, and the v1 path is never removed until
adoption is high enough.

The mutable rolling channel is `threatdb-current`. The former
`threatdb-latest` release is sealed and retained as a last-known-good fallback;
it must not be deleted or reused.

This runbook covers the rollout sequence, the safety properties that make it
safe, and how the cutover is gated without any client telemetry.

## Phases

| Phase | PR | What changes | Feed serves | Client reads |
| --- | --- | --- | --- | --- |
| 1 | DB-A | Richer OpenSSF indicator parser, confidence fix. No format change. | v1 | v1 |
| 2 | DB-B | v1+v2 reader, dual-format writer, dual-manifest updater, per-format cache filenames. | v1 | v1 (v2-capable) |
| 3 | DB-C | Ship the v1+v2 client broadly. Feed still serves v1 only. Wait for adoption. | v1 | v1 (v2-capable, broadly deployed) |
| 4 | DB-D | Publish the v2 asset and the v2 index alongside v1. Keep serving v1 through a migration window. | v1 + v2 | v2 if capable, else v1 |

The order is deliberate: the v2-capable reader (Phase 2) and a broadly-deployed
client (Phase 3) must precede publishing any v2 data (Phase 4), so that by the
time v2 exists on the feed, the clients that select it can already read it, and
the clients that cannot still have v1.

Tirith 0.5.0 is in Phase 3. Clients since 0.4.0 carry the v1+v2 reader, the
feed serves v1 only, and v2 publication is not enabled. One visible effect is
that [source ages](threatdb-freshness.md) stay unavailable until Phase 4.

## Safety properties

These are implemented in DB-B and are what make the staged rollout safe:

- **Range-accepting reader.** `from_bytes` accepts `MIN_SUPPORTED_FORMAT_VERSION (1)` through `FORMAT_VERSION (2)`. A v1 file loads with every v2 lookup returning `None` (behaves exactly like today); a v2 file loads on the new binary; an old (v1-only) binary rejects a v2 file with `InvalidVersion`. The per-format cache filenames (next point) mean an old binary never loads a v2 file in the first place, and the staged publish order keeps v2 off the wire until v2-capable clients are widely deployed. If an old binary ever did read a v2 file, that rejection is fail-OPEN for that file's detections (per the fail-open note in the intro), not fail-safe, which is exactly why the per-format split below exists.
- **Per-format local cache filenames.** v1 keeps the canonical `tirith-threatdb.dat`; the new updater writes v2 to a distinct `tirith-threatdb-v2.dat` and never clobbers the v1 path. The loader prefers `tirith-threatdb-v2.dat` when present, parseable, and signature-valid (the primary resolver requires a valid signature, see the unsigned-v2 point below), else falls back to `tirith-threatdb.dat`. So a co-located old binary still reads its own v1 file and is never fail-opened by a shared cache. The same split applies to the supplemental DB.
- **One dual-format generation pointer.** Old clients keep verifying the legacy single-asset `threatdb-manifest.json` (`{sha256,size,url,version}` + detached signature), which keeps pointing at v1. New clients treat `threatdb-index-v2.json` as the authoritative immutable-generation commit point: signed schema v2 requires exactly one v1 and one v2 asset with distinct immutable filenames and URLs, and signs `manifest_version`, sequence, names, hashes, sizes, URLs, formats, and compatibility floors together. The client authenticates both raw-main and release candidates, chooses the greatest signed sequence, and rejects equal-sequence equivocation before selecting the highest compatible format. The compiler stages both databases, publishes their immutable filenames, and advances the index only after both are durable; a partial publication leaves only unreferenced assets. External legacy readers that bypass the index retain direct-path compatibility but do not receive pair-atomic semantics.
- **Signature and rollback preserved.** All v2 bytes (sections + descriptor trailer + the fixed EOF footer) live after `HEADER_SIZE`, so the existing Ed25519 signature and the rollback `build_sequence` cover them with no change to the signed range. A malformed v2 footer or trailer is rejected (`InvalidTrailer`), fail-closed for v2 data.
- **Unsigned v2 cannot shadow a good v1.** The primary resolver requires a valid signature; the unsigned supplemental overlay does not. So a structurally-valid but unsigned or wrong-key v2 planted beside a good v1 cannot shadow the v1 and fail open.
- **Rollback preserves the v2 anti-drop baseline.** `threatdb-baseline-v2.json` is a signed copy of the newest complete generation index under a filename clients never fetch. The workflow retains that record and its referenced immutable assets after deleting both discovery indexes, so a later reactivation still passes `--baseline-v2` and cannot silently republish a catastrophically truncated v2-only dataset.

## Gating the cutover without telemetry

tirith ships no analytics, crash reporting, or phone-home behavior
(`README.md`). Adoption is therefore never measured from clients. The Phase 4
cutover (publishing v2) is gated on a deliberate release window plus
non-telemetry signals only:

- GitHub release download counts for the version that first carries the v1+v2 reader.
- Issue and support reports.
- Manual confirmation that enough of the fleet is on a v2-capable build.

There is no fixed adoption percentage baked into code; the cutover is a human
decision made against the signals above.

The workflow is fail-closed by default. Phase 4 starts only when the repository
variable `ENABLE_THREATDB_V2` is exactly lowercase `true`; an unset variable,
`false`, or any other spelling normalizes to disabled. The existence of the
client release tag alone never activates publication.

Before publishing, the release operator confirms the v2 floor matches a real
release: the `min_tirith_version` set on the v2 index (the workflow's
`V2_MIN_VERSION`) must equal the tag of the release that first carried the v1+v2
reader, so the index never gates v2 behind a version no client can satisfy. DB-D
enforces this in the workflow with a preflight check
(`git tag -l "v${V2_MIN_VERSION}" | grep -q .`); the operator confirms that tag
exists before flipping the publish gate.

## Phase 4 publish and rollback

The v2 publish steps already exist in `.github/workflows/threatdb.yml` and are
skipped while the gate is off. When the gate is on, the
compiler builds both immutable assets, signs the generation index over their
canonical metadata, and stages the index as the final local commit point. The
workflow uploads the v2 asset first and overwrites `threatdb-index-v2.json` only
after both assets exist, alongside the unchanged legacy manifest for old clients.

Rollback does not require a client release, but deleting data first is unsafe:
both the raw-main index and the rolling-release index are live discovery
pointers. The workflow runs daily and would also re-publish them while enabled.
To roll back, FIRST disable v2 publishing, then retire both pointers, and only
then remove unreferenced data:

1. Set the repository variable `ENABLE_THREATDB_V2` to `false` or delete it
   (Settings, then Secrets and variables, then Actions, then Variables). Only an
   exact lowercase `true` enables the v2 generate, publish, and commit steps.
2. Cancel any release/cron run that has not yet COMPLETED (queued, in-progress,
   waiting for deployment approval, pending, or requested). GitHub Actions reads
   repository variables at job-dispatch time, so a run already dispatched (or
   queued, or held `waiting` for an environment reviewer) before step 1 still
   completes with `ENABLE_THREATDB_V2=true` and would re-publish v2, silently
   undoing the rollback — a `waiting` run re-publishes the moment a reviewer
   approves it. Filter on "not completed" rather than an allowlist of states, so
   no non-terminal status is missed. List and cancel them first:
   `gh run list --workflow threatdb.yml --limit 100 --json databaseId,status --jq '.[] | select(.status != "completed") | .databaseId'`, then `gh run cancel <id>` for each.
3. Dispatch `threatdb.yml` after the variable change and wait for it to complete.
   A disabled run publishes the next signed v1 generation, preserves the newest
   authenticated generation as the non-discovery `threatdb-baseline-v2.json`,
   deletes the fallback `threatdb-index-v2.json` asset from `threatdb-current`, and
   commits deletion of the primary `threatdb-index-v2.json` on main, in that order.
   Confirm the release index is absent and the raw-main URL returns 404 before
   proceeding. If an emergency manual retirement is necessary, preserve the
   signed baseline first, then delete the exact release index asset and remove
   the main index in a commit; do not delete either referenced `.dat` asset until
   both pointer removals are visible.
4. After both indexes are absent, delete the now-unreferenced rolling-release v2
   data assets, but retain the exact v2 asset referenced by
   `threatdb-baseline-v2.json`. The shell does NOT expand `*.dat` against a remote
   release (no local file matches the glob), and `gh release delete-asset` takes
   an exact asset name, so resolve the protected name and candidate names first:

   ```sh
   set -euo pipefail
   state=$(mktemp -d)
   trap 'rm -rf -- "$state"' EXIT
   gh release download threatdb-current --repo <owner>/<repo> \
     --pattern threatdb-baseline-v2.json --dir "$state"
   protected=$(jq -er '.assets[] | select(.format == 2) | .filename' \
     "$state/threatdb-baseline-v2.json")
   if [[ ! "$protected" =~ ^tirith-threatdb-v2-[0-9]+-[0-9]+\.dat$ ]]; then
     echo "invalid protected v2 baseline asset: $protected" >&2
     exit 1
   fi
   gh release view threatdb-current --repo <owner>/<repo> --json assets \
     > "$state/assets.json"
   jq -e --arg protected "$protected" \
     '.assets | any(.name == $protected)' "$state/assets.json" >/dev/null
   jq -r \
     '.assets[].name | select(test("^tirith-threatdb-v2-[0-9]+-[0-9]+\\.dat$"))' \
     "$state/assets.json" > "$state/candidates.txt"
   while IFS= read -r asset; do
     if [ "$asset" != "$protected" ]; then
       gh release delete-asset threatdb-current "$asset" --repo <owner>/<repo> --yes
     fi
   done < "$state/candidates.txt"
   ```

   Do not run this deletion step unless step 3 completed successfully: that run
   authenticates the retained baseline and reads the uploaded bytes back before
   either discovery index is retired. The commands above also fail closed unless
   the protected immutable filename is well-formed and present in the captured
   release asset list.

New clients then exhaust both absent v2-index candidates and fall back to the
legacy manifest. A successful legacy update installs and syncs the authenticated
v1 file first, then removes `tirith-threatdb-v2.dat` and syncs its containing
directory. Equal-sequence v2-to-v1 transitions are treated as a required format
switch rather than "already current". If local v2 retirement fails, the update
fails loudly and does not claim rollback success. Offline clients necessarily
keep their cached v2 until they next update; the signed v1 channel remains
available throughout.

Schema migration is fail-safe in both directions. Schema-v2 indexes sign
`manifest_version`. Older v2-capable clients reject version 2 and use the legacy
v1 manifest; current clients reject the earlier schema-v1 signature shape and
also use v1. The workflow allocator can read a valid legacy schema-v1 pointer as
one-time migration input for monotonic sequence and signed baselines, but every
new pointer it publishes is signed schema v2.

On reactivation, the workflow authenticates the retained record, verifies and
downloads its referenced v2 bytes, and supplies them as `--baseline-v2`. If the
record exists but that baseline cannot be materialized, publication fails rather
than treating reactivation as a baseline-free first launch. The compiler's
section-aware floor rejects a greater-than-50-percent loss, including complete
loss hidden behind stable v1 package totals.

## Exact-hash blocking behavior

Exact artifact/member-hash correlation is already wired into the default CLI
feature graph; it is not an off-by-default post-merge step. A known-malicious
artifact hash produces `ArtifactKnownMalicious` and a blocking verdict when a v2
database containing that record is active. A v1 database has no exact-hash
sections, so those lookups return no match while the legacy detection behavior
continues unchanged. The release workflow runs the focused release-profile
regression test before packaging so this security boundary cannot silently
disappear behind a feature change.
