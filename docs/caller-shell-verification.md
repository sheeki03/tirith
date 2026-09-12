# Caller-shell verification

Configured startup files and inherited environment markers cannot establish
that the current shell can stop a command. The Bash, Zsh and Fish protocol-v3
hooks instead support a short diagnostic sequence in the shell being checked:

1. Run `_tirith_verification_probe start` to obtain a challenge.
2. Run its exact `allowed` command. The inert binary body records execution.
3. Run its exact `blocked` command. The authenticated check returns a diagnostic
   block; the inert binary body must never run.
4. Run its exact `status` command. A later authenticated hook observation and
   the actual status body complete the sequence.

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
helper status path when a machine requires observed blocking.

The core state-machine tests do not qualify a shell adapter. Each adapter must
also demonstrate the full sequence in a real interactive shell, including
helper redefinition, hook disablement, configuration changes and failed
interception. A child PTY result is evidence for that child shell only.
