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

- **Range-accepting reader.** `from_bytes` accepts `MIN_SUPPORTED_FORMAT_VERSION (1)` through `FORMAT_VERSION (2)`. A v1 file loads with every v2 lookup returning `None` (behaves exactly like today); a v2 file loads on the new binary; an old (v1-only) binary rejects a v2 file and fails closed for that file.
- **Per-format local cache filenames.** v1 keeps the canonical `tirith-threatdb.dat`; the new updater writes v2 to a distinct `tirith-threatdb-v2.dat` and never clobbers the v1 path. The loader prefers `tirith-threatdb-v2.dat` when present and parseable, else falls back to `tirith-threatdb.dat`. So a co-located old binary still reads its own v1 file and is never fail-opened by a shared cache. The same split applies to the supplemental DB.
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

## Phase 4 publish and rollback

When the gate is met, DB-D adds the v2 publish step to the release workflow: it
builds v2 via the compiler `--output-v2`, signs the v2 index over its canonical
payload (the same `jq -cS` discipline as the legacy manifest), and publishes both
the v2 asset and `threatdb-index-v2.json` alongside the unchanged v1 asset and
legacy manifest.

Rollback is cheap and does not require a client release: stop publishing (or
revert) `threatdb-index-v2.json`. New clients then fail to fetch or verify the v2
index and fall back to the legacy manifest and v1. The v1 asset and the legacy
manifest are kept through the entire migration window, so v1 is always available.

## After both stacks merge: activate exact-hash blocking

B8 reserved an off-by-default `artifact-hash-lookup` cargo feature with a seam in
`evaluate_artifact` that currently returns `None`. DB-B added the
`check_artifact_sha256` / `check_file_sha256` readers. Because B8 (the detection
stack) and the DB track land on separate branches, wiring the seam to the readers
is a small post-merge step once both are on `main`: connect the seam to the
readers and enable the feature. Only then does `ArtifactKnownMalicious` fire on an
exact known-malicious artifact or member hash, and only against a published v2 DB.
