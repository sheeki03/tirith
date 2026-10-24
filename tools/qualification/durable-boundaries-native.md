# Observed native process death and recovery

`durable_boundaries_native.py` exercises the supplied, SHA-256-pinned Tirith
executable in fresh private operator roots. It does not build, instrument, install
or replace the binary, create signing keys, launch a dashboard service, or modify
an existing operator configuration. Run it as an ordinary user on macOS or Linux
with a Python runtime exposing `os.waitid`, `WNOWAIT`, `WEXITED` and `WSTOPPED`
(the reviewed local macOS runtime is Python 3.14):

```sh
python3 tools/qualification/durable_boundaries_native.py \
  --candidate /absolute/path/to/retained/tirith \
  --candidate-sha256 <exact-64-character-sha256> \
  --output /absolute/path/to/new-evidence-directory
```

The output directory must not exist. `--case NAME` selects one route and can be
repeated. The runner imports the adjacent `mixed_audit_native.py` process and
bounded-I/O helpers. Its own hash, that helper's hash, the Python runtime hash,
OS/architecture/effective UID, candidate hash, exact command results, and input
postchecks are recorded. `artifacts.json` pins the generated evidence. Retain the
exact runner files with results before updating the harness.

## What a captured boundary proves

The observer reads a real published operation journal and probes the existing
native flock without holding a substitute product lock. Once the requested stage
is visible, it signals only its own live child with SIGSTOP, waits for the actual
stop notification without reaping the process, and checks that the expected lock
remains contended. The shared process helper retains its waitable leader identity
through group cleanup and never sends a numeric group signal after reaping it. Audit
cases require the actual log lock and the per-operation execution lock. Profile
cases require the per-operation execution lock. The same private roots have no
other concurrent product process at this observation point.

The stopped journal, active bytes, hashes and device/inode identities are saved.
The runner checks two snapshots for stability, kills the native owner with
SIGKILL, reaps it, confirms lock release, and uses ordinary CLI status/apply/undo
commands against the original UUID and working directory. An observation that
advanced between sampling and the acknowledged stop records its actual stage
and is `unobserved`; only the exact requested stage with a running journal and
applying step can pass. Missing observations are also explicitly `unobserved`,
and `all_requested_boundaries_observed` remains false. Every requested case must
pass with its exact observation for aggregate `passed: true` and exit 0; partial
qualification exits 1 while preserving each case's evidence and reason. A process or
cleanup failure is always `failed`, never a skipped platform condition. Completed
operation states require exit 0; recovery, in-progress and typed refusal states
require their defined exit 1. Negative controls require the specific product
refusal diagnostic, so a crash or unrelated error cannot stand in for a refusal.

The six audit routes target:

- Applying journal and locked original log before archive publication.
- Complete archive manifest, with original active bytes and head.
- Published invalid-head barrier before truncation.
- Empty active log behind that barrier.
- Complete genesis bytes while the barrier is still the head.
- New genesis and final head while the result journal is still in progress.

Recovery must preserve the active audit inode, reconstruct an archive identical
to the original log and head, pass the native verifier, and restore the exact
original active bytes on undo. Repeated apply and undo must preserve both bytes
and inode of the resulting generation. The small unsigned fixture deliberately
keeps this check independent of operator signing material.

Profile routes kill the typed operation before and after policy publication,
then verify exact retry and undo behavior. The closed strict-profile-v1 fixture
requires both the exact planned owned fields and the exact published YAML bytes;
a successful status without that intended change cannot pass. Recovery after
publication must preserve the already-published byte/inode generation. A separate
ordinary editor changes an
owned setting while the original worker is stopped; retry and undo must refuse
without overwriting that new generation. The fixture starts with canonical empty
YAML parent maps, because owned-field compensation preserves those parents.

The live audit cancellation route first requires the shared setup writer lock to
be free. A competing undo must explicitly refuse the existing execution-lock
owner. A cancellation request is then durably recorded while the owner remains
stopped; after SIGCONT the native worker must stop before changing the original
log/head. A conservative `partially-applied` status is accepted only with the
recorded unchanged-byte proof, followed by safe compensation. Profile cancellation
occurs after process death if the stopped owner holds the shared setup lock; that
case does not claim concurrent cancellation before death.

## Storage failures and limits

The runner establishes actual EACCES with an ordinary-UID OS open/create probe
before testing a read-only log or a non-writable head-publication directory. It
also executes the unchanged candidate with RLIMIT_FSIZE and inherited ignored
SIGXFSZ, requiring the native EFBIG diagnostic. It never fills the host filesystem.

For each failure, native allow and block controls retain their verdict and exit
status, and an audit-write failure must be visible. Failed log writes must leave
the existing log/head bytes and inode unchanged and recover after the constraint
is removed. If an append succeeds but the head cannot be published, the existing
records must remain as an exact prefix and the old head must remain unchanged.
After permissions are restored, native verification and rotation must explicitly
refuse that mismatch without discarding the preserved records.

This is process-death and syscall-failure evidence. It does **not** qualify power
loss, actual ENOSPC or a full filesystem, every fsync/write boundary, signed audit
recovery, partial genesis/archive-restore writes, native Windows locking/ACLs, or
signed binary update/rollback publication. Those checks need separate suitable
native environments and fixtures. Successful source-level recovery tests do not
replace them.

Run the runner's fixture tests separately:

```sh
cd tools/qualification
python3 -m unittest -v test_durable_boundaries_native
```

These validate stop/exit races, actual owned fixture process cleanup, lock
observation, refusal/cleanup accounting, exact-generation checks, output ownership,
input pinning, and the OS file-size-limit mechanism. They are not evidence that a
Tirith release passed the native routes.
