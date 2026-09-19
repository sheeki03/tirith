# Native mixed-version audit qualification

This standard-library Python runner executes two existing, distinct SHA-256-pinned Tirith binaries in fresh operator roots. It never builds, installs, edits the source tree, executes inspected commands, or uses the caller's policy, audit records, keys, proxy settings or shell initialization. Native Windows is explicitly outside its scope. macOS needs its built-in `/usr/sbin/lsof`; Linux uses `/proc` for descriptor observation.

The six native cases are signed and unsigned variants of:

1. Both versions append and verify; the candidate rotates without replacing the active inode; both verify the retained exact original bytes/head and the new active chain; both append afterward; compensation refuses after append without changing active bytes. Signed cases additionally remove the fixture private key and require rotation and both appenders to refuse audit writes while retaining the Allow check exit code. The candidate must display its audit failure notice.
2. Six overlapping native writers (three of each version) append before rotation, then another mixed burst appends after rotation. Exact command accounting and both native verifiers check all expected records. This case does not claim forced overlap with truncation.
3. The real candidate prepares a rotation. The harness watches its private journal enter `applying`, observes the native lock is held, then stops the **lock owner** with SIGSTOP. It observes the stopped process and re-probes the lock, checks the original log/head are still intact, starts the real legacy writer, and records the writer's open audit descriptor using native OS observation. After SIGCONT, it requires completed rotation, unchanged inode, exact original archive, the legacy record in the new active segment, and successful active/archive verification by both versions. No binary is instrumented or replaced; all product log bytes are written by the supplied binaries. Missing the bounded observation window fails the case rather than claiming coverage.

The private signing fixture is the publicly known RFC 8032 section 7.1 test-vector-1 seed. It exists only as an owner-only file in fresh signed case roots and is removed at case completion, including handled failures. It is not an operator credential or a production signing identity. Native verifiers establish the fixture signatures; Python's signature check only enforces framing and count.

## Run

Use a Python runtime exposing `os.waitid` with `WNOWAIT`, and a new evidence output directory whose parent already exists. This is feature-checked before spawning a candidate; there is no fallback that reaps a leader before signaling its group. On macOS, Python 3.14 supplies this interface; Apple's `/usr/bin/python3` 3.9 does not. Linux also needs readable native `/proc` process metadata. The mandatory input hashes are checked before creating the output directory and rechecked after all cases. A binary symlink, identical binaries, changed hash, or existing output directory is rejected. Exit 0 means every requested native case passed; exit 1 means a case failed; exit 2 means the runner itself could not start or complete normally. Omitting `--held-writer` runs four cases and explicitly records the missing held-descriptor coverage.

```sh
python3 tools/qualification/mixed_audit_native.py \
  --baseline /absolute/path/baseline/tirith \
  --baseline-sha256 BASELINE_SHA256 \
  --candidate /absolute/path/candidate/tirith \
  --candidate-sha256 CANDIDATE_SHA256 \
  --output /absolute/path/new-evidence-directory \
  --held-writer

python3 tools/qualification/test_mixed_audit_native.py
```

Each invocation records input and runner hashes, host OS/architecture, a precise coverage scope, each argument vector/result/PID, bounded stdout/stderr, native observations, and case/environment records. `artifacts.json` hashes all retained evidence files, including the report; it intentionally excludes itself. No ambient environment dump is collected. Children have a 45-second deadline, at most 16 can be drained together, and each stream is capped at 64 KiB. Each candidate starts in a new session and process group. Cleanup sends signals only while the owned leader remains waitable and unreaped, observes that the group has no executing members, and then reaps the leader exactly once. Group observation and signaling have a three-second deadline, followed by at most one second for leader termination/reaping and two seconds for pipe drainage. Descriptor observation has a separate 3-second child limit. Fixture log reads are capped at 16 MiB. The harness leaves evidence roots for review and refuses to reuse them.

These results apply only to the exact input bytes on the recorded native host. Hash pinning does not authenticate vendor release signatures. Native Windows ACL/locking qualification, crash injection at every durable boundary, corrupt/modified archives, full/read-only storage, other historic clients, and non-fixture policy contexts remain separate evidence requirements.

## Development evidence and limits

`native-attempt-1` retains the first experiment. All four sequential/burst cases passed; the first external-gate held-writer design observed both open descriptors but let the legacy writer win between candidate apply phases. The candidate safely returned `refresh-required`; these were correctly failed crossing cases and are not crossing proof.

`native-attempt-2` passed all six cases using the stopped-lock-owner method. `native-final` is the final source rerun after strengthening exact command accounting. The fixture tests verify isolation, hash/reuse rejection, read/output caps, child/descendant cleanup, stopped-child timeouts, native result requirements, exact command accounting, archive substitution refusal and fixture-key cleanup. Unit test results are runner validation, not substitute release qualification.

The runner and its fixtures are registered under `tools/qualification/`. Development reports retain their own source and executable hashes; the exact final candidate must be qualified separately.

The runner also bounds drainage when an out-of-group process retains an output pipe. Such a case fails with incomplete output cleanup. An arbitrary descendant that creates a new session and closes inherited pipes is outside this process-group observation; this helper does not claim process-tree containment. Group signal permission failures are retried only within a finite deadline, and successful leader reaping or output EOF alone does not establish group cleanup. Fixture private signing-key removal runs even when child cleanup raises an error.

Cleanup reports retain `leader_reaped`, `group_signaled_or_absent`, and `output_eof`, and add the required `group_members_exited` boolean. The last value requires bounded native membership/status observation through Darwin `libproc` or Linux procfs while the leader still pins the numeric group identity. Exited zombies may still await reaping by their actual parent; they cannot execute or retain descriptors. `group_observation` records the method, observed members, and this scope. A group signal merely being delivered is insufficient. Failure to inspect membership, an observation bound being exceeded, or losing the waitable leader produces a cleanup failure. New evidence consumers must require all four facts; historical reports lack the new group proof and must not be relabeled as meeting it.

The shared `Job.process` wrapper deliberately makes `poll()` and `wait(timeout=...)` non-reaping observations. Callers should use `send_signal()` and `observe_stop()` for stop/resume observation, and `Job.kill()`/`finish()` for cleanup. They must not call raw `waitpid()` or `waitid()` without `WNOWAIT` for its child. Premature or external reaping is detected and prohibits further numeric PID/group signals. Repeated cleanup calls are inert after the single bounded attempt.
