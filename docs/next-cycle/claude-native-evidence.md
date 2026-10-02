# Native Claude Code qualification checkpoints

Observed on macOS 27 arm64 (September 12, 2026) with Claude Code 2.1.268 (`06a96d5423f83770f120859f1c58e60d7252cc4c122aa13043b7e7cd716bc76a`) and Tirith 0.4.2 checkpoint `b2ba2d23c8091eaac111cbaefa3fa877617d2716aca20be808a92db838f360de`. The real host invoked its real setup-installed PreToolUse hook. A deterministic loopback provider issued one inert tool call; no paid model credentials or real user/project configuration were used. This records exercised behavior, not a beginner pilot or qualification of other platforms.

The later unguarded Tirith candidate `11fde156220c6e9bf2cbfd7e26af0b7929b3850bc6c3cdabbdbb37f38bc04172` repeated all three baseline cases successfully with the same native host: allowed once, blocked never, and hook-disabled execution once. That report also verifies unchanged configuration hashes before and after each native host run, and distinguishes the installed settings from the altered disabled configuration. Its harness SHA256 is `59dd8651a5de072597b44550fbda6d364776e3d7057aa395acd1c59701b44e00`. This candidate does not contain the launcher guard.

The integrated guarded candidate `a70b8eba427c8cfbc20287c94102d0da59ce7d44a01e2f0e388f1baddcae156f` subsequently passed all nine cases with the same host and harness. Its source capture is `health-claude-ui-inputs`, based on commit `13e18ca88e6c923c1c2df547741735bb17dda930`. The six configured-hook cases observed harmless execution once and zero execution for a policy block, unavailable interpreter, unavailable checker, crashed hook, and the actual installed hook's checker deadline. The three boundary controls observed execution once with the hook disabled, a manually shortened host deadline, or an unmatched native Write tool. A passing boundary control records that limit; it does not claim protection there. The report verifies unchanged candidate and host hashes and unchanged executed settings/hook hashes before and after every case.

The configured matcher is exactly `PreToolUse/Bash`. It does not intercept Write, other unmatched tools, a host that never launches the configured hook, or a hook disabled by the operator. This scope follows the generated settings and was also exercised with the actual native Write tool.

| Actual host case | Marker executions | Result |
| --- | ---: | --- |
| Harmless Bash call | 1 | allowed exactly once |
| Rule-blocked Bash call | 0 | blocked before execution |
| Same blocked command with hook removed | 1 | negative control confirms hook causality |
| Checker executable unavailable, actual installed Python hook | 0 | hook emits deny |
| Actual installed Python hook with controlled sleeping checker process | 0 | internal ten-second deadline emits deny |
| Configured Python interpreter unavailable, legacy command | 1 | host treats launch failure as nonblocking |
| Hook killed by SIGKILL, legacy command | 1 | host treats abnormal exit as nonblocking |
| Interpreter unavailable, quoted POSIX command followed by `|| exit 2` | 0 | wrapper maps launch failure to host block |
| Hook killed by SIGKILL, same POSIX wrapper | 0 | wrapper maps abnormal exit to host block |
| Host timeout deliberately reduced to one second | 1 | upstream host timeout bypasses the hook; wrapper cannot recover after it is terminated |
| Native Write tool with Bash-only matcher | 1 | outside configured scope |

The generated configuration does not reduce the host timeout. The real Python hook has a shared ten-second check budget and catches `TimeoutExpired` to emit a deny decision. Current Claude documentation specifies a 600-second default for command hooks on PreToolUse, and documents exit 2 as blocking while other nonzero exits are nonblocking. [Claude hook reference](https://code.claude.com/docs/en/hooks), [hook guide](https://code.claude.com/docs/en/hooks-guide).

The Unix setup launcher change preserves the exact quoted interpreter and hook argument, and appends a fixed POSIX `|| exit 2`. It applies to Unix Claude command hooks only; native macOS exercised this behavior. Native Windows launch behavior has not been inferred. Existing unguarded settings require an explicit configuration refresh; updating only Python script bytes does not repair a launch command that the host cannot execute.

The initial retained evidence bundle contains `claude-b2ba-retained-report.json`, `claude-b2ba-failure-controls.json`, `claude-b2ba-wrapper-controls.json`, and `claude-b2ba-checker-deadline.json`. Its manifest pins the product checkpoint (`71070bbb`), both native binary hashes, and the exact harness scripts. All runs confirm their binary hashes remained unchanged. The later baseline is retained separately as `claude-baseline.json` with its exact harness and candidate. The guarded candidate is retained as `claude-nine-controls.json` with a separate manifest that binds the report, source capture, binaries and exact harness. These are development checkpoint observations; subsequent candidates must repeat the installed-command controls before claiming their own qualification.

In the initial three-case report, `settings_sha256` is the configuration produced by setup, captured **before** the hook-disabled control changed it. That field must not be interpreted as the hash of the disabled configuration. The later failure-control reports distinguish `installed.settings_sha256` and `installed.hook_sha256` from `executed_settings_sha256` and `executed_hook_sha256`, captured after the isolated control mutation and host run. These older reports did not independently compare the configuration before and after host execution. The harness revision paired with the launcher fix records both sets for every case, captures the executed hashes immediately before launch, and requires identical configuration hashes after the host returns.

Run the baseline native-host harness against an explicit candidate and installed Claude executable:

```sh
python3 scripts/certify-claude-host.py \
  --tirith /absolute/path/tirith \
  --claude /absolute/path/claude \
  --output /absolute/path/claude-native-report.json
```

Pass `--failure-controls` to additionally exercise missing interpreter/checker, hook crash, checker deadline, deliberately shortened host timeout and unmatched Write cases. A passing boundary control means the observed result matched the documented limitation; it does not mean that surface blocked execution. Each case records its scope separately.

This harness requires the real host. It runs the setup-installed hook through the host's actual tool dispatch; direct Python hook invocation and fabricated hook events do not count as native-host evidence. Provider responses are deliberately scripted over loopback, and the host starts with an environment allowlist and isolated configuration roots. Native Windows, other agent hosts, live-provider behavior and real beginner usability remain separate qualification requirements.

The same harness exposes two additional, separately reported routes. They require
real recommended setup and the host's normal user settings discovery, both within
a fresh temporary HOME. Select one route per new report:

```sh
python3 scripts/certify-claude-host.py \
  --route mcp-only \
  --setup-mode recommended --settings-loading default-user \
  --tirith /absolute/path/tirith \
  --claude /absolute/path/native-claude \
  --claude-invocation /absolute/path/claude \
  --python /absolute/path/python3 \
  --output /absolute/path/claude-mcp-only-report.json
```

Use `--route retained-host-reload` with a different output path for the reload
route. The `claude` PATH invocation must resolve to the selected native host, and
the setup-installed Python runtime must match the independently discovered
runtime. Existing reports are never overwritten. The default `hooks` route and
its nine cases selected by `--failure-controls` remain unchanged.

The MCP-only route removes the hook from the isolated generated settings, connects
the actual selected candidate's `mcp-server`, and requires the host to report that
connection. It then requires the independently policy-denied Bash marker to run
exactly once without hook events. Passing this control demonstrates the boundary
of MCP access; it does not certify automatic Bash interception.

The reload route starts one host before the hook exists, completes a no-tool
initialization turn, and publishes real recommended setup while retaining that
process. It records the next turn immediately after publication, a later turn in
the same process after a policy recheck, and a separate fresh host. Each retained
turn may either observe the hook and block or omit the hook and execute the marker
once; ambiguous or errored results fail the fixture. The fresh host must observe
the hook and block without an additional marker. Elapsed time from setup is
recorded. These are observations of exact host turns, not a universal hot reload
guarantee or a promise of immediate activation.

Reports bind candidate, native host, Python invocation/runtime, PATH alias,
harness, generated settings/hook, policy and captured process output hashes. Policy
before setup is recorded separately because recommended setup can legitimately
change it; the published policy must remain unchanged during the observed turns.
All input executable hashes and resolved identities are checked again after the
route. Output is capped at 4 MiB per process, streaming lines at 1 MiB, input writes
at five seconds and each host turn at 90 seconds. Every child gets a private
process group; termination, reap and pipe drainage have finite deadlines. The
loopback provider has bounded requests, connections and socket deadlines. Fixture
cleanup failures cannot produce a passing report.

Run `python3 scripts/test-certify-claude-host.py` for the harness regressions. These
include bounded real subprocesses and a fake host using the real loopback provider,
with immediate omission, later blocking, fresh-host blocking and absent-MCP
connection controls. They validate the certification harness, not Tirith or Claude
enforcement. Previously retained native reports remain tied to their original
one-off driver hashes; these repeatable routes need fresh native reports for each
candidate they qualify.

## Claude Code 2.1.283 checkpoint, September 28, 2026

The exact-version combined-setup list now retains 2.1.268 and adds 2.1.283. The
native scope remains macOS ARM, personal configuration, and the selected Python
3.9.6 invocation/runtime. This checkpoint used Claude executable SHA256
`d8cb1e5c79684cc12a8bfc813e3a2073406921b6245744b3009be3ab5651d21e`,
fresh private HOME/configuration roots, and the scripted loopback provider.

The earlier PR CI package
`076d6d457a42c76bb6227e7aeadd1a0bdb369020de6c4e6c3b9fa0af308368dc`
passed all nine explicit-setup controls but correctly refused combined setup for
this then-unqualified version. That refusal is retained. A first development
candidate passed the nine behavior controls but failed the outer cleanup
postcheck: an asynchronous `hook-event` writer recreated a removed private
fixture. Its behavior result is not accepted as complete qualification.

The corrected development candidate
`6c17baad668e8d5dfef50040eba9d1fc690cf2bef117cc2c39df781b263ef45d`
(145,953,936 bytes, dev profile) passed each fresh route once:

| Route | Recorded outcome |
| --- | --- |
| Recommended setup, default user settings, nine controls | 9/9 pass; configured-hook and boundary outcomes remain distinct |
| MCP-only | Connection observed; hook absent; policy-denied marker executed once, confirming the interception boundary |
| Retained-host reload | Immediate retained turn omitted the hook and executed once; later retained turn at 1.023 seconds observed the hook and blocked; fresh host blocked |

All corrected routes passed executable/harness hash and fixture cleanup
postchecks. The reload observations do not establish immediate or universal hot
reload. The unchanged native harness SHA256 is
`bf719549ac06764d81030df808c30ad6e09ca15391d6d15f0806cc2ec6aeee91`.
The build's 659-file source closure remained identical before and after
compilation, with content SHA256
`97cf7e2a11a5dfa2b6e086b902ab0b04cade06e21983add0a82f502dbe81265c`.
Reports are retained as `candidate-v2-recommended-nine.json`,
`candidate-v2-mcp-only.json`, and `candidate-v2-retained-host-reload.json` in the
`native-macos-claude-2.1.283` evidence bundle.

The telemetry fix covers the nine related Python, shell, and TypeScript
templates. Python/shell helpers wait briefly, then request termination and a
finite reap attempt; TypeScript helpers use a 250 ms synchronous timeout with SIGKILL.
Telemetry remains optional and cannot change an allow/block decision. Later Pi
review corrected warning telemetry ordering so it cannot shorten the existing
ten-second checker budget. Focused helper/decision regressions cover that change;
they do not qualify other native hosts. That later TypeScript correction is not
part of the retained Claude binary above. Neither these development bytes nor
their reports constitute final PR-package or official signed-release
qualification; the final package must repeat the native routes.

### Actual 6e79b3dd PR package

The [release run 36378009327](https://github.com/sheeki03/tirith/actions/runs/36378009327)
produced the macOS ARM package subsequently tested with that same Claude/Python
tuple. The actual checkout `dfcd8ec5003fd7c09b9a452b3b25014908e3d307` has tree
`a7bb69f2c398cac2941ea575d09947e6e6ac5132`, identical to product head `6e79b3dd`.
GitHub artifact 10952083021 has ZIP SHA-256
`5f86504b2a6e50c01f884c3ece815c6479bc944de468896c0b0aa7a5fa15fb4d`;
the extracted ordinary 0.4.2 executable is 38,409,920 bytes with SHA-256
`4583b1b18043f89a4fd4e642f4f0e5f645e3bd5ecb1a2bff1af7d46e0877167c`.

Each route ran once through the unchanged harness: all nine recommended hook
controls passed, MCP-only demonstrated its interception boundary, and a fresh
host observed the hook and blocked after publication. In this run **both**
retained-host turns omitted the new hook and executed the inert marker once.
The earlier development observation of later blocking is not a reload promise;
users must start a fresh host after setup.

All 35 owned-child cleanup records pass. Input hashes stay unchanged and the
isolated operator/temporary roots are empty after completion. Independent review
rehashed the archive/binary bindings and twelve retained report/log files, and
rechecked every route and cleanup result. Qualification summary SHA-256:
`6fc5a1f5ed9b8adbd116ecc9defdd38c89d0723b0c52bf61614f0360f8bc5821`.
This closes current PR-package hook recertification for the recorded tuple.
Numeric binary replacement, the beginner pilot and official release acceptance
remain separate requirements.

### Numeric replacement with an existing configured host

The ordinary `d0213a22` 0.4.2 product and its exact isolated Cargo-version-only
0.4.3 variant pass actual retained/fresh Claude behavior across update and
rollback. All ten tool turns pass; one host stays alive across both swaps and
fresh hosts verify each resulting installation. Forty-one owned child cleanup
records and 23 loopback-provider requests are retained. The setup-generated
configuration, exact valid enforced policy, three compiler closures and 157
retained evidence files pass postchecks. Result SHA-256:
`3e33d2ee4f4c83bc1d4fd0bf8b02693caef579234c621d62f4b591ff20c12087`.

These public-fixture-key replacements exercise the actual verifier and
publication mechanics. They do not certify official release authority or the
service-to-worker handoff. Existing hooks following the replaced executable
are distinct from hot reload of newly added hook configuration; the latter
continues to require a fresh host. No loaded-Tirith-version field or remote
model latency is inferred from the host observations.
