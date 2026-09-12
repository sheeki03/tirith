# Recovery at the execution boundary

`tirith check` prints guidance for the exact input's shell and command shape.
Machine callers opt into the versioned `recovery` projection with
`--format json --json-schema 4`. Ordinary JSON remains schema 3 with its existing
fields; `--json-schema 3` selects that contract explicitly. Selecting a JSON
schema without JSON output is refused before analysis. Neither version changes
the decision or exit code. The projection uses the same
inline-bypass parser as runtime. A policy-enabled POSIX/Fish pipeline can receive
a `TIRITH=0 ` prefix hint; compound and background forms that runtime rejects do
not. PowerShell and Cmd environment assignments persist beyond one operation, so
the one-use recovery projection reports that capability as unsupported.

The projection contains no command text or command digest. It lists the current
restriction rule IDs, and never grants execution permission. An exception preview
must be evaluated independently to establish which other restrictions remain.
When policy disables bypass, including incident mode, no bypass is offered.

Acknowledgement and hard Block remain separate. Browser confirmation and
`tirith pending resolve ID approve` cannot authorize a blocked command. The latter
records a review decision only. Existing shell protocol-v3 receipts own permitted
approval and acknowledgement at Tirith's execution prompt, bind the exact
secret-sealed command/CWD/session/hook process/executable/policy/expiry, re-evaluate
at consumption, and refuse changed commands or replay. Receipt consumption after
a crash reconciles its durable ledger before any retry can proceed. Ordinary
operation journals never store those secret-bearing command bytes.

Missing private scratch storage or helper executables can fail before Tirith
runs. Bash/Zsh/Fish capture-failure diagnostics therefore describe opening a
separate terminal without startup hooks, inspecting the pinned helpers and
writable `TMPDIR`, running doctor, and restarting to verify. `TIRITH=0` cannot
repair that failure. A clean diagnostic terminal is not represented as protected.

Init-generated activation snippets report `TIRITH_INTEGRATION_VERSION` and
`TIRITH_INTEGRATION_SHELL` after sourcing. A version is emitted only when the hook
bytes match the running binary's embedded copy; another bundle reports `unknown`.
Status labels these inherited values as unverified. They help identify a loaded
old integration after an update, but do not constitute a fresh blocking probe.
