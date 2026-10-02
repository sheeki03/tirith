# Native CLI reader compatibility capture

Run a separately authenticated 0.4.2 baseline and a candidate in fresh private
operator roots. Both executable SHA-256 values are mandatory. The runner checks
native version output, preserves raw bounded stdout/stderr and exact fixture
bytes locally, and validates command exits together with relevant policy,
trust, receipt and protection-evidence semantics. It never executes the command
text passed to `tirith check`, starts a service, installs a package, or reads the
operator's configuration. Supplied fixture bytes must remain unchanged.

```sh
python3 tools/qualification/compatibility_capture.py \
  --baseline /absolute/path/baseline/tirith \
  --baseline-sha256 BASELINE_SHA256 \
  --candidate /absolute/path/candidate/tirith \
  --candidate-sha256 CANDIDATE_SHA256 \
  --output /absolute/path/new-capture-directory
python3 tools/qualification/test_compatibility_capture.py
```

The process helper imposes a 45-second child deadline, 64-KiB limit per output
stream and bounded owned-process-group cleanup. It requires a Python runtime with
`os.waitid` and `WNOWAIT`, retaining the leader until native group observation and
cleanup finish. All four cleanup facts are required, including
`group_members_exited`; a delivered signal or output EOF alone cannot pass.
Missing cleanup facts, malformed
or duplicate-key JSON, non-finite numbers, wrong exits and mismatched semantic
values fail qualification. Inputs, runner and helper hashes are rechecked at
completion. Reports retain failures; a partial run cannot pass. Hash pinning
does not authenticate a release signature, so retain the baseline's independent
release-verification evidence alongside the capture.

The sixteen cases are run once against each client. They cover clean/blocked
schema-3 checks, personal policy, repository suppression neutralization,
permanent/expired/malformed-expiry legacy trust, inherited shell mode reporting,
and saved download receipt list/last/verification with exact, changed and absent
cache bytes. These are native reader observations over synthetic inputs, not
proof of installed shell interception, receipt creation/signing, artifact
publication or every historical receipt schema. Other native platforms and
final release bytes need their own evidence.
