# Shared shell targets and protection evidence

Setup and doctor now share `cli::shell_target`. An observed ancestor process
selects the shell family; an environment default is explicitly weaker evidence.
Unknown shells have no inferred Bash target. Status can measure the observed
executable's version with bounded, sanitized child execution; polling and prompt
paths do not launch version probes.

| Family | Personal startup targets |
| --- | --- |
| Bash | `.bashrc` for interactive non-login shells, plus the first existing `.bash_profile`, `.bash_login`, or `.profile` for login shells; a new `.bash_profile` when none exists |
| Zsh | `$ZDOTDIR/.zshrc`, otherwise `$HOME/.zshrc` |
| Fish | `$XDG_CONFIG_HOME/fish/config.fish`, otherwise `$HOME/.config/fish/config.fish` |
| Nushell | `$XDG_CONFIG_HOME/nushell/config.nu`; without that override, native Linux `.config`, macOS `Library/Application Support`, or Windows `%APPDATA%` |
| PowerShell 7 on Windows | Native redirected Documents directory, `PowerShell/Microsoft.PowerShell_profile.ps1` |
| Windows PowerShell 5.1 | Native redirected Documents directory, `WindowsPowerShell/Microsoft.PowerShell_profile.ps1` |
| PowerShell on Unix | `$XDG_CONFIG_HOME/powershell/Microsoft.PowerShell_profile.ps1`, otherwise `$HOME/.config/powershell/Microsoft.PowerShell_profile.ps1` |

The implementation follows the [Bash startup contract](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files),
[Nushell configuration contract](https://www.nushell.sh/book/configuration), and
[PowerShell profile contract](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles).
A configured console-host profile does not establish that a custom host loads it.
No-profile and custom startup arguments are observed from the actual ancestor
where available; automatic setup refuses those modes because default profiles
would not activate them. Custom host profiles and unobserved startup modes remain
unknown. Manual workflows remain available.

Under sudo, the resolver uses the account database for the intended operator's
home. Personal mutations refuse a different effective UID. Run personal setup as
the intended user without sudo. Default paths remain contained beneath the home;
explicit external configuration roots retain protected filesystem transactions.

The generic `tirith status` exit contract is preserved: a configured hook whose
live blocking mode is unobservable still exits successfully. Its JSON now exposes
`protection_evidence`, with state, source, observation time, expiry, freshness,
invalidation reason, and a separate `verified_blocking` flag. `protected` is true
only for verified blocking. The legacy `protection_mode` string remains the
reported mode and does not independently establish verification.

`tirith status --require-verified-blocking` exits unsuccessfully when the current
shell has no fresh allow-and-block observation. Exporting `TIRITH_STATUS=blocks`
or inheriting Bash's effective-mode variable cannot satisfy that requirement.
Prompt text shows `blocking-unverified` for this case. A configured hook without
an observable active mode is shown as configured, never as freshly verified
protection. An absent environment variable alone does not prove that activation
is missing.

`tirith doctor --simulate-enter --format json` emits the measured Bash executable,
version, and an actual disposable-shell allow/block observation. That observation
belongs only to `disposable-bash-enter-probe`; it never certifies the calling shell,
a nested shell, another host, or the whole machine. Observations are rejected on
surface/identity mismatch, expiry, clock rollback, incomplete/failed probes, or a
current report of reduced protection. No current-shell verifier is implied by the
existence of the disposable probe.

Unit fixtures cover Bash startup priority, custom config roots, native platform
Nushell paths, separate Windows PowerShell variants and redirected Documents,
unsupported shells, inherited environment, stale/changed identities, expired and
future observations, and cross-surface evidence. Native Windows execution must
still run on Windows CI; Unix fixtures are not Windows certification.

The PowerShell hook checks actual terminal availability and startup options
before installing PSReadLine handlers or starting background snapshots.
Noninteractive invocations remain off, including a command or file payload that
contains the text `-NoExit`. Missing checker or temporary storage leaves Enter
unexecuted and paste uninserted, with degraded status until a successful check.
Unexpected Enter exit codes preserve the existing unprotected fallback and
report it explicitly; unexpected paste exits refuse insertion. Clipboard input
uses one raw string so multiline content is checked and inserted intact.

`scripts/certify-powershell-hook.py` records executable, hook and harness hashes
in disposable environments. Its full mode uses native POSIX terminals; the
Windows CI lane explicitly selects noninteractive-only. Neither lane certifies
an untested platform, version or current user session. See the retained candidate
results and limits in [verification](verification.md).
