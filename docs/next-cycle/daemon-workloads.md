# Standalone and daemon characterization

`scripts/measure-daemon-workloads.py` compares the same inert offline analysis
through fresh CLI processes and a retained foreground daemon. It never executes
the analyzed strings. The caller supplies an ordinary executable, a genuine
signed database and their digests, plus a separately reviewed source binding.
No database download, signature override, timestamp change, cache purge or sudo
is used. Personal configuration and existing daemons are untouched.

## Fixed workloads

Two private fixtures contain one or 256 custom rules. The larger fixture has an
eight-level nested working directory and 128 inert repository files. Both use
the same URL-analysis string and a literal custom-rule block marker. Each mode
must agree on action, exit code, findings, policy path, reached tier and bypass
state before its timings can be compared. Any mismatch stops collection.

The fixed sample units are:

- 100 fresh database-status processes in the flat fixture, plus admission and
  postchecks in the larger fixture. The product must admit the supplied signed
  bytes and retain their actual sequence, timestamp and freshness diagnostics.
- 100 fresh standalone checks per command and fixture, measured from before
  spawn through owned-process cleanup and pipe EOF.
- One foreground daemon startup per fixture, followed by first-request,
  100 serial and 100 paired-client request observations per command.
- Daemon requests measured from send through response EOF, after connection
  and peer-PID admission. Two clients are sent before either response is read;
  request-window overlap does not prove simultaneous engine execution.

These are fresh-process and repeated-process measurements, not cold OS caches
or observed database cache-hit counts. Direct socket time excludes the CLI
renderer, audit path, terminal and host adapter. Automatic database updates and
audit logging are disabled in both modes. Disabling updates affects the
product's `stale` boolean; it does not rejuvenate the signed database timestamp.
The larger fixture measures bounded policy loading and discovery, not a full
repository scan or a distribution of arbitrary repositories.

## Ownership and bounds

Every child is retained through the pinned native ownership helper. The daemon
must retain its original private directory, PID-file and socket generations.
Each connection must report the retained child PID through Darwin
`LOCAL_PEERPID` or Linux `SO_PEERCRED`; Linux also checks the peer UID. A direct
response cannot silently be a standalone fallback. Cleanup signals only retained
children and requires group exit, leader reaping and pipe EOF. Uncertain cleanup
retains the fixture and fails the run.

One 900-second work deadline bounds collection. Individual CLI, startup and
socket-batch limits are 15, 10 and 5 seconds, clamped to remaining time. Cleanup
has separate finite bounds. Responses and child streams are limited to 64 KiB,
the raw journal to 16 MiB and the report to 4 MiB. Fixture inspection caps
entries, depth and bytes; free disk must remain above 2 GiB between units.
These checks are observations, not a filesystem quota.

The report keeps wall time, child CPU, cumulative completed-child RSS,
sampled daemon RSS/CPU, logical bytes and allocated disk bytes separate.
Sampled RSS is a lower bound on peak memory; the child high-water mark is not
an individual request or process-tree sum. Every raw sample is retained; there
are no discarded warmups or replacement samples. p50 is the conventional
median and p95 uses nearest rank. Ambient contention is recorded, and intentional
builds or other qualification should finish before measurement.

## Running and interpreting

The source-binding JSON has exactly `binary_sha256`, `product_commit` and
`product_tree`. Its build/artifact evidence must be reviewed separately; labels
in this JSON are not executable attestation.

```sh
python3 -B scripts/test-measure-daemon-workloads.py
python3 -B tools/qualification/daemon_workload_owner.py \
  --native-helper tools/qualification/mixed_audit_native.py \
  --output /absolute/new-owner-evidence
python3 -B scripts/measure-daemon-workloads.py \
  --binary /absolute/tirith --sha256 EXACT_BINARY_SHA256 \
  --database /absolute/signed.dat --database-sha256 EXACT_DATABASE_SHA256 \
  --native-helper tools/qualification/mixed_audit_native.py \
  --source-binding /absolute/reviewed-binding.json \
  --output /absolute/new-measurement-evidence
```

The twelve pure controls and eight Python-responder cases cover admission,
identity replacement, malformed/oversized replies, deadlines, output overflow
and cleanup. They execute no Tirith product. The September 28 ordinary-product
measurement and independent raw-sample review are recorded in
[verification](verification.md#september-28-matched-standalone-and-daemon-workloads).
The integrated producer differs from those measured bytes only in its module
description; the responder's import path is adjusted for its repository location.
Existing Criterion and allocation/RSS budgets remain unchanged. These observations
do not establish a universal latency promise or final release qualification.
