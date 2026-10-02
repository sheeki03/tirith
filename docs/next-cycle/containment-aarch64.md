# Linux aarch64 containment decision

WP27 selects native, little-endian Linux aarch64 with deny-all networking as the
additional qualification target. Tirith already distributes GNU and musl aarch64
binaries, and native ARM Linux test access is available. This addresses an
existing distribution gap; it is not evidence that users requested a particular
new sandbox API. Native GNU and musl candidate acceptance now passes as recorded
below; qualification of the final tag-produced release artifacts remains separate.

## Existing mechanisms to preserve

| Backend already present | Enforced mechanisms and material limits |
| --- | --- |
| Linux x86_64, `landlock-seccomp` | Landlock filesystem grants, extrasafe 0.5 default-deny syscall rules, no-new-privileges, sanitized environment, closed inherited descriptors, and a ptrace guard for kernel-observed exec identity. CPU/address-space/descriptor limits and Linux's per-real-UID process limit are available; the launcher alone does not enforce output bytes or wall time. |
| Linux aarch64 baseline | The same Landlock and descriptor-bound launch machinery, including architecture-specific kernel exec evidence, already exists. The baseline extrasafe dependency is x86_64-only, so prior builds refuse raw-network requirements. This cycle adds a separate ARM syscall policy; production qualification is tracked below. |
| macOS, `seatbelt` | The fixed system sandbox-exec wrapper applies Seatbelt filesystem/network restrictions. Its launcher enforces CPU and descriptor limits and environment/descriptor isolation. Memory and per-subtree process ceilings are unavailable; a requested unsupported dimension refuses. |
| Windows, `appcontainer` | AppContainer capabilities, tracked ACL grants, and a suspended-process Job Object launch already exist. Job Objects enforce supported CPU/memory/process and supervised wall-time limits; open-handle and uncaptured output-byte ceilings remain unavailable. |

All backends retain the existing per-capability coverage ledger. The egress proxy
alone is not an OS boundary, and none of this decision grants domain-allowlist
coverage or turns package inspection into safe execution. Existing package
approval issuance/redeemability remains independently restricted to supported
x86_64 Linux authority contracts.

## Selected implementation contract

The implementation adds a native aarch64 syscall policy to the existing Linux launcher, using the
already locked rust-vmm seccompiler generation rather than copying extrasafe's
x86_64 syscall numbers or writing a separate hand-assembled BPF compiler. The
seccompiler project supports aarch64; extrasafe 0.5 does not. Keep the dependency
target-specific and preserve the existing x86_64 restrictions. Shared lifetime
and observed local readiness fixes apply to both Linux policies. Sources:
[extrasafe 0.5 architecture limit](https://docs.rs/crate/extrasafe/0.5.1/source/README.md)
and [seccompiler 0.4 implementation](https://github.com/rust-vmm/seccompiler/blob/v0.4.0/src/lib.rs).

The ARM policy must default to refusal, reject a mismatched syscall architecture,
and allow only the launcher's reviewed runtime operations. New socket creation,
socketpair, raw network syscalls, io_uring, namespace/mount changes, process-group
escape, unrestricted ptrace, cross-process limit changes, and dangerous terminal
ioctls remain denied. Descriptor-local fcntl, read-only standard-stream terminal
queries, self-only resource queries, and the exact existing exec-proof ptrace and
parent-death-signal contracts need argument restrictions equivalent to x86_64.
File operations remain independently restricted by descriptor-bound Landlock
rules. A runtime syscall omitted from the contract produces refusal; it does not
widen the allow set automatically.

Confinement setup runs only in the existing fresh, single-threaded launcher.
Failure cannot fall through to target exec. UI/CLI capability observations must
distinguish the compiled policy from usable native kernel mechanisms and actual
child enforcement. QEMU user-mode emulation is not native qualification; its
current release refusal test must keep proving that unavailable raw-network
denial cannot launch the child. No administrator access or sudo is needed to
install an unprivileged seccomp filter after no-new-privileges.

The supported resource contract must explicitly retain the distinction between
per-process address-space/CPU/descriptor limits, Linux's per-real-UID process
limit, and wrapper-enforced subtree termination, wall-time and output limits.
Root or privileged processes must not claim an effective process-count limit from
RLIMIT_NPROC alone. Kernel and outer-container policy can make mechanisms
unavailable; no implicit degraded fallback is permitted.

## Native acceptance and evidence

| Required case | Acceptance |
| --- | --- |
| Clean shell and child utility | The target executes exactly once, with the original status/signal and authenticated launch evidence. |
| Network escape | IPv4, IPv6, UNIX sockets, socketpair, direct socket syscalls, inherited sockets and io_uring cannot obtain an ungranted network capability. |
| Filesystem and descriptors | Outside read/write, symlink/rename races and inherited descriptor escapes fail; the granted fixture succeeds. |
| Guard and process escape | setsid/setpgid, ptrace attach or memory access, arbitrary signal injection, and supervisor death cannot leave an executing target tree. |
| Resource exhaustion | Requested supported CPU/memory/descriptor/process dimensions and wrapper output/wall budgets are exercised; unavailable dimensions refuse before protected execution. |
| Missing or denied mechanism | Missing Landlock, seccomp denial, wrong architecture, invalid rules and QEMU emulation return a typed refusal and no child side effect. |
| Cancellation and interrupted launch | Cancel before exec, cancel during the child, launcher death and repeated cleanup terminate the tree and preserve the protected host state. |
| Artifacts | Native GNU and musl installed-artifact tests record exact version/hash/kernel/architecture and coverage, separately from cross-build and QEMU smoke. |

Initial host inspection found native Docker Linux aarch64 with kernel
6.12.76-linuxkit. A primitive probe is separate evidence from the complete Tirith
launcher and cannot qualify the backend. G3 remains pending until the exact
production filter, launch path, negative cases and release artifacts pass, with
independent review of the syscall policy and evidence.

## Evidence recorded so far

The standalone production filter module passes its compiled-BPF argument and
architecture checks plus native subprocess cases under Rust 1.83, as root and
UID 65534. The socket fixtures establish that socket creation works before the
filter, then require IPv4, IPv6, UNIX socket and socketpair denial after it.
Additional cases cover process-group/namespace escape attempts, clone3 ENOSYS
fallback, ordinary dynamic shell execution, and refusal when an outer seccomp
policy prevents filter installation. These are filter tests, not a completed
launcher or installed-artifact qualification.

Native production qualification uses an immutable workspace snapshot, a separate
Docker build target with debug symbols/incremental compilation disabled, and
recorded source/binary/probe hashes. The installed-binary fixtures run as UID
65534 with no network and require the actual capsule receipt to report enforced
controls and confirmed cleanup. Snapshot changes receive a new identity; a
successful build of an earlier snapshot cannot qualify later source edits.

The first native production `tirith-core` test binary also passes all four ARM
filter tests as UID 65534 (5,881 unrelated tests excluded). Its immutable source
manifest is `ee02f51c22dda242efc2ec3c13ee3463266c70c459010e8a37b2716f10e1012a`.
This establishes that the actual crate integrates and executes the filter; it
does not establish that the complete CLI launch path works.

A native launcher probe identified a separate ARM breakpoint requirement: unlike
x86 INT3, ARM BRK reports the address of the trapping instruction. Continuing
without advancing the PC traps again. A fixed-address probe confirmed that
reading the 272-byte NT_PRSTATUS register set, matching the launcher's hidden
trap address, and advancing the PC by exactly four bytes resumes to exit zero.
The production fix retains that exact instruction check and restricts
ptrace register requests to NT_PRSTATUS on an existing positive tracee;
attach, memory access and other register sets remain denied. The native candidate below includes this correction.


The corrected native GNU candidate passes nine complete installed-binary cases:
clean execution with a protected original project, child exit status, denied
network operations, process-group/namespace/ptrace escape, outside filesystem
access, memory and descriptor limits, ordinary fork/wait, inherited file/socket
closure, and wrapper output-budget termination. Every case requires the actual
receipt to report all requested controls and confirmed cleanup. The immutable
source manifest is `5c4d99e5e0cdca59a1a7705b1ccce4efb6cfbd5193c62290009cd7d425937645`;
the GNU binary SHA256 is
`b9427f237c665b6ceef7adb7b6bf78d2aaa4872051ac4075d7872a3d94588237`.
The run uses Linux `6.12.76-linuxkit`, aarch64, UID 65534, Rust 1.83 and an
isolated Debian 12 container. This candidate snapshot predates subsequent cycle
edits and is not a published release artifact.

Two negative fixture results are material: an absent authenticated passwd home
refuses before copying or spawning, and a host bind-mounted executable under a
runtime directory was denied by Landlock even though its uncontained execution
succeeded. Copying the inert fixture into the reviewed project then exercised
the supported project-copy execution path. The grant policy was not widened to
make an unrelated bind mount executable.

The native ARM workflow builds separate GNU and musl archives and qualifies the
exact extracted executable as an unprivileged user. The release workflow also
requires that acceptance against each ARM archive produced by the existing
release build before publication. Evidence includes source, archive, binary,
probe and harness digests plus the actual kernel, UID and coverage. These gates
are independent from QEMU runtime compatibility, whose unavailable seccomp
boundary must continue to refuse execution. Workflow source validation does not
count as a successful native CI or release run.

The interruption qualification exposed a Linux supervisor-lifetime defect in the
initial candidate: killing the outer command could leave the contained guard and
target running. The correction arms SIGKILL before launcher exec, then installs
a guard-only parent-death handler before containment or target fork. That handler
uses only async-signal-safe libc calls to terminate its own fixed process group.
Both Linux syscall policies permit only `kill(0, SIGKILL)` for this purpose;
other groups, individual PIDs, other signals and group changes remain denied.
The kernel binds this lifetime to the creating thread, so that thread ending is
also cancellation even if sibling supervisor threads remain alive. If the guard
itself receives SIGKILL, the surviving outer supervisor owns complete-group
termination and must not wait indefinitely for descendant-held output pipes.

The exact corrected module compiles with Rust 1.83 on native ARM and passes its
three bootstrap tests as an unprivileged user. A separate native group fixture
also stops the guard and its child after both SIGTERM and SIGKILL to the
supervisor. Full artifact acceptance additionally requires cancellation before
exec, supervisor SIGTERM/SIGKILL and guard SIGKILL with a live fork descendant.
The regular native Linux CI job runs these interruption cases too. Abrupt outer
process death cannot produce a completed cleanup receipt; preserved temporary
residue must not be reported as confirmed cleanup.

Both local GNU and musl candidates pass all 16 exact-archive cases: the earlier nine,
both sleep APIs through an actual shell utility, the per-real-UID process limit,
descriptor-local epoll/eventfd/ppoll readiness, and four interruption cases
(before exec, supervisor SIGTERM, supervisor SIGKILL and guard SIGKILL). The
last three start a live target and fork descendant and require the guard and
entire target tree to stop; guard death also completes without waiting forever
on inherited output pipes. The source manifest is
`7d9788bfe34462c745b252038ac6d045265d08d940759fc82f9620c882b5d317`;
both builds consume that exact immutable source. The GNU binary SHA256 is
`a3995ae1760775e4252273736b82c0a4f69f2bafe0d4b175cf7713402f4a67e6`;
the static musl ELF SHA256 is
`6013cbf85aef4ea21a95659da92cbba6cf298392721b7b050da19da28709da5f`.
Each archive was independently extracted and ran the complete 16-case gate on
Linux 6.12.76-linuxkit, aarch64, UID 65534, using Rust 1.83 with debug symbols
and incremental compilation disabled. These exact local candidate archives
are separate evidence from the CI builds below and from published releases.

The readiness additions follow observed EPERM failures in a native syscall
probe and Node's libuv loop initialization. They allow nanosleep,
clock_nanosleep, epoll_create1, epoll_ctl, epoll_pwait, eventfd2 and ppoll. A
production-policy subprocess regression verifies these local operations while
socket creation, io_uring, namespace/group escape and signals to other processes
still fail. Passing a Node prerequisite or this generic project-copy capsule
does not qualify the separate sealed-input package-install authority boundary.

Native CI also passes both [GNU](https://github.com/sheeki03/tirith/actions/runs/34689197992/job/103541375574)
and [musl](https://github.com/sheeki03/tirith/actions/runs/34689197992/job/103541375613)
archive qualification at commit `71070bbbb02a3a6e5f96d335a048e92a7f048679`.
These jobs build their own release-profile candidates and execute the complete
16-case gate on native ARM. The tag-triggered final release-artifact lane was
not run for this pull request, so publication qualification remains separate.
Later changes to the syscall or launcher contract require fresh evidence.

Neither source-manifest-bound local result nor the commit-bound CI result
qualifies later npm runtime-pack, stdio-policy or namespace changes.
