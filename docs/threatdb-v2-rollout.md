# Threat-DB v2 staged rollout runbook

The threat database is a signed binary blob. Bumping its on-disk format is not a
single switch: an old binary handed a newer-format file rejects it, and
`ThreatDb::cached()` returns `None` on a load failure, which is fail-OPEN (every
DB-backed detection silently stops). So the v2 migration is staged so that no
client is ever served data it cannot read, and the v1 path is never removed until
adoption is high enough.

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

## Safety properties

These are implemented in DB-B and are what make the staged rollout safe:

- **Range-accepting reader.** `from_bytes` accepts `MIN_SUPPORTED_FORMAT_VERSION (1)` through `FORMAT_VERSION (2)`. A v1 file loads with every v2 lookup returning `None` (behaves exactly like today); a v2 file loads on the new binary; an old (v1-only) binary rejects a v2 file with `InvalidVersion`. The per-format cache filenames (next point) mean an old binary never loads a v2 file in the first place, and the staged publish order keeps v2 off the wire until v2-capable clients are widely deployed. If an old binary ever did read a v2 file, that rejection is fail-OPEN for that file's detections (per the fail-open note in the intro), not fail-safe, which is exactly why the per-format split below exists.
- **Per-format local cache filenames.** v1 keeps the canonical `tirith-threatdb.dat`; the new updater writes v2 to a distinct `tirith-threatdb-v2.dat` and never clobbers the v1 path. The loader prefers `tirith-threatdb-v2.dat` when present, parseable, and signature-valid (the primary resolver requires a valid signature, see the unsigned-v2 point below), else falls back to `tirith-threatdb.dat`. So a co-located old binary still reads its own v1 file and is never fail-opened by a shared cache. The same split applies to the supplemental DB.
- **Dual manifests.** Old clients keep verifying the legacy single-asset `threatdb-manifest.json` (`{sha256,size,url,version}` + detached signature), which keeps pointing at v1. New clients read a separate signed multi-asset `threatdb-index-v2.json` and select the highest `format <= MAX_FORMAT_VERSION` whose `min_tirith_version` is satisfied and whose asset hash verifies, falling back to the legacy manifest on any failure. So an old client only ever sees v1.
- **Signature and rollback preserved.** All v2 bytes (sections + descriptor trailer + the fixed EOF footer) live after `HEADER_SIZE`, so the existing Ed25519 signature and the rollback `build_sequence` cover them with no change to the signed range. A malformed v2 footer or trailer is rejected (`InvalidTrailer`), fail-closed for v2 data.
- **Unsigned v2 cannot shadow a good v1.** The primary resolver requires a valid signature; the unsigned supplemental overlay does not. So a structurally-valid but unsigned or wrong-key v2 planted beside a good v1 cannot shadow the v1 and fail open.

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

Before publishing, the release operator confirms the v2 floor matches a real
release: the `min_tirith_version` set on the v2 index (the workflow's
`V2_MIN_VERSION`) must equal the tag of the release that first carried the v1+v2
reader, so the index never gates v2 behind a version no client can satisfy. DB-D
enforces this in the workflow with a preflight check
(`git tag -l "v${V2_MIN_VERSION}" | grep -q .`); the operator confirms that tag
exists before flipping the publish gate.

## Phase 4 publish and rollback

When the gate is met, DB-D adds the v2 publish step to the release workflow: it
builds v2 via the compiler `--output-v2`, signs the v2 index over its canonical
payload (the same `jq -cS` discipline as the legacy manifest), and publishes both
the v2 asset and `threatdb-index-v2.json` alongside the unchanged v1 asset and
legacy manifest.

Rollback does not require a client release, but reverting the published files is
not enough on its own: the release workflow runs on a daily cron and regenerates
and re-publishes the v2 asset and `threatdb-index-v2.json` (and re-commits the
index to main) on every run, so a manual revert is silently undone within a day.
To roll back, FIRST disable v2 publishing, then remove the published artifacts:

1. Set the repository variable `PUBLISH_V2` to `false` (Settings, then Secrets and
   variables, then Actions, then Variables). DB-D gates the v2 generate, publish,
   and commit steps on this variable, so the next cron run stops re-publishing.
2. Cancel any in-progress or queued release/cron runs. GitHub Actions reads
   repository variables at job-dispatch time, so a run already dispatched (or
   queued) before step 1 still completes with `PUBLISH_V2=true` and would
   re-publish v2, silently undoing steps 3 and 4. List and cancel them first:
   `gh run list --workflow threatdb.yml --json databaseId,status --jq '.[] | select(.status=="in_progress" or .status=="queued") | .databaseId'`, then `gh run cancel <id>` for each.
3. Delete the rolling-release v2 asset(s). The shell does NOT expand `*.dat` against a
   remote release (no local file matches the glob), and `gh release delete-asset` takes
   an EXACT asset name, so resolve the names first, then delete each:

   ```sh
   gh release view threatdb-latest --repo <owner>/<repo> \
     --json assets --jq '.assets[].name | select(startswith("tirith-threatdb-v2-"))' \
   | while IFS= read -r asset; do
       gh release delete-asset threatdb-latest "$asset" --repo <owner>/<repo> --yes
     done
   ```
4. Revert `threatdb-index-v2.json` on main.

New clients then fail to fetch or verify the v2 index and fall back to the legacy
manifest and v1. The v1 asset and the legacy manifest are kept through the entire
migration window, so v1 is always available. Until step 1, the next scheduled cron
re-publishes v2, so the `PUBLISH_V2` gate (not the revert) is what actually holds
the rollback. Clients that already cached `tirith-threatdb-v2.dat` keep reading it
from disk (the loader prefers the local v2 file, independent of the manifest) until
their next successful update overwrites it from the rolled-back feed. Because v1 and
the legacy manifest stay published throughout, that next update cycle rewrites the
cached v2 file from v1-only inputs, so there is no separate client-side purge step.

## After both stacks merge: activate exact-hash blocking

B8 reserved an off-by-default `artifact-hash-lookup` cargo feature with a seam in
`evaluate_artifact` that currently returns `None`. DB-B added the
`check_artifact_sha256` / `check_file_sha256` readers. Because B8 (the detection
stack) and the DB track land on separate branches, wiring the seam to the readers
is a small post-merge step once both are on `main`: connect the seam to the
readers and enable the feature. Only then does `ArtifactKnownMalicious` fire on an
exact known-malicious artifact or member hash, and only against a published v2 DB.
