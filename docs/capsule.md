# Runtime containment capsule

The capsule is tirith's OS containment layer. It runs a tirith-launched
child process (a downloaded script, a previewed command, an upstream MCP server,
or a package install) inside a real OS sandbox, and it is honest about exactly
what it managed to enforce on the current host.

This is the one narrow exception to tirith's "no runtime sandboxing" non-goal
(see `docs/threat-model.md`). It is per-invocation and applies only to processes
tirith itself launches, never to arbitrary shell commands.

## Where it applies

| Surface | Flag | Network | Fail mode |
| --- | --- | --- | --- |
| `tirith run` (live execution is Linux-only; `--no-exec` is inspection-only on Unix) | default for every live run (`--capsule` remains accepted) | deny-all | fail closed |
| `tirith temp-run` | `--capsule` | deny-all | best-effort (runs uncontained if no backend, and says so) |
| `tirith gateway run` | `--capsule` (or the `secure` gateway profile) | deny-all | fail closed |
| `tirith pkg install` (enforcing execution is x86_64 Linux-only) | always | deny-all | fail closed; every other platform or architecture refuses before pip starts |
| `tirith capsule run` (enforceable on x86_64 Linux only) | `--preset untrusted-project` | deny-all (no domain allow-listing is offered) | fail closed; every other platform or architecture refuses before anything is copied or spawned |

"Fail closed" means: if this host's backend cannot enforce the containment the
surface requires, the command refuses to run rather than running the child
uncontained. The `temp-run` surface is the only best-effort one, because it is
explicitly a filesystem-impact preview rather than a security boundary; with
`--capsule` it hardens the run where it can and reports honestly when it cannot.

The `tirith pkg install` platform limit applies only to the enforcing execution
step. `tirith pkg approve` remains a non-installing approval flow, and
`tirith pkg verify-env` verifies an existing environment without launching pip.

### The untrusted-project preset

`tirith capsule run --preset untrusted-project --project . --receipt <path> --
<argv>` is the recruiter-task surface: you were sent a repository and asked to
run it. The project is copied into a held ephemeral directory and the argv runs
there, with write access to the copy and a private temporary HOME and nothing
else.

The copy is a refusal-based copy, not a best-effort one. A symlink, a hardlink,
an entry on another filesystem mounted inside the tree, a path that escapes the
project root, a case or Unicode name collision, a fifo, a socket, a device, or a
non-UTF-8 name all REFUSE the run. Silently skipping any of them would leave you
believing the whole project was copied, and a hardlink in particular is a second
name for content the project root does not contain, which is how a file is
smuggled out of a denied directory one inode at a time. `.git` is excluded at
every depth, including a submodule `.git` file, and the copy caps at 100,000
files, 200,000 entries of every kind, 256 levels of nesting, and 2 GiB.

The walk is depth-first and holds two open descriptors per level, so it needs
descriptors proportional to the DEPTH of the tree rather than to the width of
its widest directory. A vendored dependency tree with thousands of sibling
packages copies on a stock `RLIMIT_NOFILE`.

The copy is handed to the contained child as the DESCRIPTOR the parent has held
since it created the directory: the launcher enters it with `fchdir` and builds
the Landlock write rule from that same descriptor. Nothing re-resolves the
pathname after the parent proved its identity, so a same-UID rename plus symlink
cannot redirect either the working directory or the write grant.

Resource ceilings are the shared `ResourceLimits::conservative()` values (CPU
120 s, wall 300 s, memory 2 GiB, 256 processes, 256 open files, 16 MiB combined
output), tightened further by any `task_gate` policy through the existing
denied-effect merge. Two of those dimensions, combined output and wall clock,
are enforced by the PARENT supervisor rather than by any OS backend; the receipt
names them so a reader never attributes them to the sandbox.

Domain allow-listing is deliberately not offered. `domain_proxy_enforced` is
`false` in all three OS backends, and a coverage ledger may not claim domain
egress without raw-socket denial, so an allow-list preset would fail closed on
every host while implying a capability the product does not have. Dependencies
must be vendored or installed by a separate trusted transaction; this preset
performs no network dependency installation.

Every invocation writes one signed, content-addressed receipt, including a
refusal. It records the argv DIGEST (never the argv), the project input and
output tree digests, the backend, requested versus achieved coverage, the
effective limits, the child's exit status separately from Tirith's own decision,
the termination reason, a bounded file diff, whether an ephemeral copy of the
project was materialized at all, and cleanup confirmation covering all three
ephemeral artifacts (the project copy, the process tree, and the temporary
HOME). Absolute host paths are redacted out of the recorded reason, because the
receipt is the copy you hand to someone else. A run that was not fully contained
is recorded as `partial` or `refused`, never as a contained result. Exit codes
are 0 (contained, child exited 0), 1 (a Tirith decision: refused before launch,
terminated after it, or a run whose receipt could not be recorded or could not
be anchored in the audit chain), 2 (usage or input error), and 3 (contained, but
the child itself exited non-zero).

The preset is enforceable on x86_64 Linux with a usable Landlock ABI and nowhere
else. Raw-network denial needs seccomp, which is x86_64 Linux only in this
build; macOS cannot enforce a per-process memory ceiling or a process-count
ceiling at all; and the parent-owned wall-clock and combined-output supervisor
is Linux-only. Every other host refuses before anything is copied or spawned,
naming the exact control it could not deliver.

### Linux reviewed-execution proof

Linux live `tirith run` uses a stopped-target authorization protocol in addition
to containment. The guard reports `OBSERVED` only at the kernel
`PTRACE_EVENT_EXEC` stop and keeps the target stopped. The parent then durably
records a stopped-but-unresolved transition under the stable session lock and
sends one exact ACK followed by EOF. Only then may the guard detach/resume the
target and report `RESUMED`; the parent requires that frame followed by status
EOF before durably upgrading the same transition to confirmed kernel-exec
evidence.

A wrong, duplicate, missing, prequeued, or late frame; missing EOF; expired
deadline; state-publication failure; or guard failure aborts, kills, and reaps
the supervised process tree while the execution lock is still owned. Such a
path may retain conservative unresolved history, but it never becomes a
confirmed execution. Native Linux launcher runtime verification belongs to
Linux CI or a native Linux host; portable source/unit coverage and macOS builds
do not satisfy that gate.

For the gateway, containment is part of the hardened posture: when the discovered
core policy sets `gateway_profile: secure` (the `ai-agent-heavy` posture), the
gateway requires a contained upstream even if the operator did not pass
`--capsule`, so a secure deployment never silently fronts an uncontained MCP
server. The upstream is launched deny-network, with the system readable but the
credential subtrees (`~/.aws`, `~/.ssh`, ...) still denied, and the environment
scrubbed down to a minimal allow-list (the `TIRITH_GATEWAY_DEPTH` recursion guard
is preserved). The flag still works on its own, so containment does not depend on
adopting the profile.

## Backends

| Platform | Backend | Mechanism |
| --- | --- | --- |
| Linux | `landlock-seccomp` | Landlock filesystem confinement + a seccomp policy that grants no socket-creation syscalls, applied in a single-threaded re-exec launcher before `execve` |
| macOS | `seatbelt` | a `sandbox-exec` SBPL profile (`deny default` + an allow-list, `deny network*` except the loopback broker), plus an environment scrub and resource limits applied by the launcher |
| Windows | `appcontainer` | an AppContainer profile + package SID, ACL grants on the allowed roots, a suspended `CreateProcessW` inside the container with no inherited handles, and a kill-on-close Job Object with resource caps |
| any other | `noop` | contains nothing and never claims any coverage; enforcing surfaces always fail closed |

## The honesty contract

The capsule never reports a control it did not actually apply. Each backend
produces a per-capability coverage ledger:

| Capability | Meaning |
| --- | --- |
| `fs_read_enforced` | reads are confined to the allow-listed roots |
| `fs_write_enforced` | writes are confined to the allow-listed roots |
| `exec_limited` | process spawn / exec is restricted (e.g. no-new-privs, seccomp) |
| `network_raw_denied` | raw outbound sockets are blocked at the OS layer |
| `domain_proxy_enforced` | domain egress is enforced through the loopback broker |
| `resource_limits_enforced` | at least one resource cap was requested and every requested CPU / memory / process / open-files / output / wall-clock dimension is applied |
| `env_isolated` | the environment was scrubbed of sensitive variables and given an isolated HOME / TMPDIR |
| `handles_isolated` | inherited handles were closed down to stdio plus the explicit allow-list |

A surface compares the coverage a backend can actually achieve against the
coverage its spec requires. Any shortfall is a degraded result. An enforcing
surface fails closed on a degraded result; an analysis surface may run degraded
with a banner.

## The egress broker is a broker, not the boundary

The capsule can optionally allow egress to a small set of domains through a
loopback CONNECT broker. The broker is NOT the security boundary. The boundary is
the OS backend that blocks every raw outbound socket except the connection to the
broker. `domain_proxy_enforced` is therefore claimed ONLY where
`network_raw_denied` is also true. The broker re-validates each CONNECT: a
per-session token, a domain and port allow-list, a single DNS resolution with
every resolved IP validated (private / loopback / cloud-metadata rejected), a
pinned destination IP with no re-resolution, a pinned TLS SNI, and caps on
connections / bytes / handshake / idle. No current backend wires a verified
raw-socket block to the broker yet, so `domain_proxy_enforced` is false
everywhere today and any allow-listed-egress spec fails closed. Installs need no
network at all, so they use `deny-all` and are unaffected.

## Environment scrubbing

A contained child does not inherit the parent environment by default. Known
sensitive variables are stripped even if they are explicitly re-added, so an
allow entry can never re-expose a credential. The stripped set covers cloud and
registry credentials and agent sockets, including `AWS_*`, `AZURE_*`, `GOOGLE_*`,
`GITHUB_TOKEN`, `GH_TOKEN`, `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `TWINE_*`,
`UV_INDEX*`, `PIP_INDEX*`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DOCKER_CONFIG`,
`KUBECONFIG`, `SSH_AUTH_SOCK`, and `GPG_AGENT_INFO`. HOME, XDG, and TMPDIR are
repointed at a fresh temporary directory so the child cannot read or poison the
real user config tree. The default-denied filesystem subtrees are a curated set
of credential and key stores (`.aws`, `.ssh`, `.gnupg`, `.kube`, `.npmrc`,
`.pypirc`, and similar), not all of `~/.config`, so a contained build still sees
the benign config it needs.

## Checking coverage on your host

`tirith doctor` reports the capsule backend selected for your platform and the
per-capability coverage it can enforce, including whether deny-all containment is
enforceable (so enforcing surfaces would work rather than fail closed) and
whether domain egress is enforceable. It also lists any optional external
containment helpers found on `$PATH`.

## Optional external helpers

tirith can detect, but never depends on, optional external sandbox runtimes on
`$PATH`: Anthropic `srt` on Linux and macOS, and Microsoft `mxc` on Windows and
WSL. Detection is presence-only and is reported by `tirith doctor` for an
operator's information. No tirith behavior or acceptance criterion depends on
them; tirith's own backends are what enforce containment.
