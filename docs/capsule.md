# Runtime containment capsule

The capsule is tirith's opt-in OS containment layer. It runs a tirith-launched
child process (a downloaded script, a previewed command, an upstream MCP server,
or a package install) inside a real OS sandbox, and it is honest about exactly
what it managed to enforce on the current host.

This is the one narrow exception to tirith's "no runtime sandboxing" non-goal
(see `docs/threat-model.md`). It is per-invocation and applies only to processes
tirith itself launches, never to arbitrary shell commands.

## Where it applies

| Surface | Flag | Network | Fail mode |
| --- | --- | --- | --- |
| `tirith run` | `--capsule` | deny-all | fail closed |
| `tirith temp-run` | `--capsule` | deny-all | best-effort (runs uncontained if no backend, and says so) |
| `tirith gateway run` | `--capsule` (or the `secure` gateway profile) | deny-all | fail closed |
| `tirith pkg install` | (always, a later milestone) | deny-all | fail closed |

"Fail closed" means: if this host's backend cannot enforce the containment the
surface requires, the command refuses to run rather than running the child
uncontained. The `temp-run` surface is the only best-effort one, because it is
explicitly a filesystem-impact preview rather than a security boundary; with
`--capsule` it hardens the run where it can and reports honestly when it cannot.

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
| `resource_limits_enforced` | CPU / memory / process / open-files / output / wall-clock caps are applied |
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
