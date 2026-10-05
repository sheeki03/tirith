# Caller-shell verification

Use these checks to find out whether the shell you are typing in loads a
current Tirith hook and actually stops commands. Configured startup files and
inherited environment markers cannot tell you that.

## Observe blocking in this shell

Run `tirith doctor --verify-shell` for the exact instructions. The Bash, Zsh and
Fish protocol-v3 hooks support this short sequence, run in the shell being
checked:

1. Run `_tirith_verification_probe start` to obtain a challenge.
2. Run its exact `allowed` command. The inert binary body records execution.
3. Run its exact `blocked` command. The authenticated check returns a diagnostic
   block; the inert binary body must never run.
4. Run its exact `status` command. A later authenticated hook observation and
   the actual status body complete the sequence and return canonical status.
   Its `status` object uses the same schema and strict verified-blocking exit
   contract as `tirith status --json --require-verified-blocking`; the helper's
   existing `observation` and `protection` fields remain, with `status_exit_code`
   recording the canonical result.

The allowed and status commands retain the ordinary policy and execution
receipt path. Policy refusal leaves verification incomplete. The blocked
override recognizes only the exact generated command, with a canonical UUID
and no wrappers, redirections, extra whitespace, or additional shell syntax.
It cannot authorize another command. If a warn-only or disabled interception
path runs the blocked body, the challenge fails.

The helper passes its unexported receipt capability only to the internal
verification process. Core validates the registered shell PID and process start
identity, direct-parent relationship, shell family, session and Tirith binary
identity on every use. A nested shell needs its own challenge. PowerShell and
Nushell do not currently have this strict receipt channel and report unsupported
verification rather than inheriting another shell's result.

Evidence also binds the actual working directory, the resolved policy, bounded
configuration inputs selected by the shell target resolver, and a fingerprint
of loaded hook/helper definitions and native interception state sampled at
start, every matched hook check, and each actual probe/status body. Policy,
configuration, binary, process or sampled runtime-hook changes invalidate the
result. This is an observation of the challenge sequence in the caller shell,
not proof about another terminal, every future command, or changes between
observations that were subsequently restored.

Challenges and results expire five minutes after creation. Repeated status
reads preserve the original observation time; they do not renew evidence.
Private records contain sealed context bindings and never persist the shell
capability or raw hook contents. Public output contains the challenge UUID,
shell family, state, timestamps and the explicit `current_shell_only` scope.
Normal `tirith status` does not acquire an unexported shell capability and cannot
authenticate this evidence by reading a marker alone. Use the authenticated
helper status path when a machine requires observed blocking. This final helper
consumes a core-issued proof in the same Tirith process, after gathering status.
Core rechecks the live shell capability, the sealed record, and its bound context;
projection must complete within five seconds of proof issuance and before the
original challenge expiry. A public report, a copied environment variable, or a
saved result cannot mint that proof. A sourced hook can prove this shell's current
interception while `hook_configured` still reports no configured startup file.

Run each exact command separately in the intended interactive shell. The
sequence does not activate hooks.

## Is this terminal's hook current?

`tirith status` and `tirith doctor` report whether the hook loaded in the
calling terminal is current, and `--json` adds a `hook_freshness` object. At
startup each hook writes a private record that names the shell process and the
Tirith executable which loaded the hook. Bash, Zsh and Fish register their
receipt capability (`evidence: registered_hook_capability`). PowerShell and
Nushell have no receipt capability, so on Linux and macOS their hooks write a
hook load record instead (`evidence: registered_hook_presence`). It carries no
secret and grants nothing:

- `current`: registered by this Tirith executable (loaded, not a blocking proof).
- `stale`: registered by a different or since-replaced executable, for example
  before an upgrade. Open a new terminal to load the upgraded hook.
- `unregistered`: no completed registration for this shell. Open a new terminal
  after setup, or run `tirith init`. A PowerShell or Nushell terminal opened
  before this release also reports `unregistered` until it is reopened.
- `unknown`: the calling shell or its record could not be determined. On
  Windows no shell can be registered (the process identity used here is
  Unix-only), so PowerShell and Nushell there report the inherited, unverified
  `TIRITH_INTEGRATION_VERSION` instead (`evidence:
  inherited_environment_unverified`), as does any other unrecognized shell.

The human output also counts other open terminals that still run an older hook
(`other_live_stale`, with `other_live_current` in JSON). Records of exited
shells are ignored. This readout never reports verified or blocking protection
(`blocking_proof` is always `false`); use the sequence above for that.

## Limits

- Evidence covers only the shell the challenge ran in: not another terminal, a
  nested shell (it needs its own challenge), every future command, or changes
  made and then restored between observations. Commands run in a disposable
  child describe only that child.
- PowerShell and Nushell have no strict receipt channel; they report
  verification as unsupported instead of inheriting another shell's result.
- Challenges and results expire five minutes after creation; reading the status
  again does not renew them. Policy, configuration, binary, process or
  hook-definition changes invalidate the result.
- Plain `tirith status` cannot authenticate this evidence by reading a marker;
  use the helper's status step when a machine must require observed blocking.
- The dashboard is a configuration view. A saved success or a surviving shell
  PID does not let it claim current blocking.
- The hook freshness readout is loaded-hook evidence only (`blocking_proof` is
  always `false`). A PowerShell or Nushell hook load record shows only that the
  hook finished loading in that shell process. It is never a receipt
  capability or verification, and Nushell stays warn-only.
- Hook freshness is not available on Windows: every shell there reports
  `unknown`.
- The core state-machine tests do not qualify a shell adapter. Each adapter must
  show the full sequence in a real interactive shell, including helper
  redefinition, hook disablement, configuration changes and failed
  interception. A child PTY result is evidence for that child shell only.
