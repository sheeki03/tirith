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
