# Native service update coordination fixture

This isolated, ignored Unix test exercises the actual local HTTP service,
asynchronous mutation worker and updater drain handshake. It is a mechanism
test: it does not replace a binary, verify an official release, simulate another
released service protocol or establish final package compatibility.

The test prepares a real mutation using the service's actual project context.
An authenticated HTTP request admits the worker and publishes its durable
Running state. A test-only gate then holds that worker for at most 30 seconds;
ordinary unit-test gates retain their existing ten-second limit. No production
deadline, authorization rule or service counter is changed.

The required observations are:

- Stale discovery protocol and binary identity refuse before quiescing or
  changing the mutation target.
- The production updater's ten-second wait refuses while the admitted job is
  still active. Further mutation and required-service reuse are refused.
- Releasing the gate lets the real mutation finish. The service acknowledges
  completion before its retained thread is joined.
- The updater guard retains both launch and service-lifetime locks. A later
  service has a distinct identity; the old required identity cannot launch or
  select a replacement.

Compile the CLI test target with Cargo's JSON output, select the sole `tirith`
test executable for `crates/tirith/Cargo.toml`, and retain its exact digest and
build record. Run as an ordinary user with native Python supporting
`os.waitid`/`WNOWAIT`:

```text
python3 -B tools/qualification/service_coordination_native.py \
  --test-executable /absolute/retained/tirith-test \
  --sha256 <sha256-of-that-test-executable> \
  --output /absolute/new-evidence-directory
```

The runner creates private HOME/XDG/project/organization roots, selects only
this ignored test and bounds the owned process to 90 seconds after spawn.
The pinned native owner retains its waitable leader through original-group
cleanup and reaps last. Each service thread must acknowledge completion before
joining; Rust never deletes the external fixture root. Failure, missing cleanup
evidence or changed input bytes retains the fixture. Success requires the
structured in-process result, all four outer cleanup facts and unchanged inputs.
Arbitrary escaped sessions and an asynchronous pre-spawn watchdog are outside
this runner's scope.

Linux and macOS CI retain the Cargo selection, exact test digest, structured
result and failures. The separate pure controls inject cleanup/reporting errors
without spawning a process; they do not establish native behavior.
