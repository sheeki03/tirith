# Windows workspace qualification

`test-workspace-windows.ps1` runs only in the disposable GitHub-hosted Windows
test job. It creates a fresh standard local account for the existing
`control_dashboard` integration executable. It does not change Tirith's
administrator refusal or its directory/owner trust rules.

The controller reads Cargo's JSON compiler-artifact inventory, pins every test
executable and the companion CLI, and retains read handles that deny writing or
deleting those files through execution. The dashboard harness and CLI stay at
their original build paths: the harness's compiled `CARGO_BIN_EXE_tirith` still
names the same pinned CLI. Package working directories and native library search
paths are preserved. Ordinary harnesses run under the CI account; dashboard
tests run under the new account; workspace doctests run separately. Each
inventory entry receives a result even when an earlier harness fails.

`windows-test-process.cs` creates the worker suspended with
`CreateProcessWithLogonW`, `LOGON_WITH_PROFILE`, and a profile-derived environment.
The password exists only in process memory and Windows' account database. It is
never an argument, environment variable, manifest field or log entry. Before
resuming the worker, the controller reads its real token and verifies the exact
new SID, non-elevation, absence of the Administrators SID (including deny-only
groups), and an integrity level no higher than Medium. The worker then enters a
job with kill-on-close and no breakaway permission. Failure to attest or assign
the job prevents execution.

The worker creates its own disposable state under its actual loaded profile and
records the native owner SID and ancestor SDDL for diagnosis. It receives
read/execute access to the original build and fixture paths, not a product
override. Runner-owned files do not become standard-user-owned files. An
unsupported native owner or ancestor descriptor remains a failing test; the CI
runner does not relax or replace that product check.

The unchanged dashboard harness is listed and run without a filter. All current
nine test names must be present; any newly added listed tests must run too. A
successful result requires every listed test to pass with zero failures,
ignored tests and filtered tests. Output overflow, malformed results, missing
tests, changed binary hashes, a worker deadline, or leaked descendants all fail.

The native job also exercises the same CLI's elevated refusal, a wrong-SID
suspended worker, a wrong-hash worker, and a deliberately stalled worker with a
real long-lived child. The last probe must hit its deadline with an empty job
after termination. These controls cannot replace the complete dashboard suite.
Account/profile removal follows confirmed native process cleanup and verifies
the exact account SID before deletion. Only the fresh account's ACL entries are
removed from existing trees.

`test-windows-test-runner.ps1` exercises parser, inventory, immutable-input and
bounded-process contracts without provisioning an account. Passing it on another
OS does not qualify Windows logon, token inspection, nested jobs, profile
ownership, ACL inheritance or native dashboard behavior. Those gates require the
actual Windows job and its `summary.json`, inventory, native facts and complete
bounded logs. The workflow retains that evidence for seven days.

Native contracts: [Cargo JSON messages](https://doc.rust-lang.org/cargo/reference/external-tools.html#json-messages),
[Cargo dynamic library paths](https://doc.rust-lang.org/cargo/reference/environment-variables.html#dynamic-library-paths),
[CreateProcessWithLogonW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw),
[Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

## Owned Job failure diagnostics

Process results retain `leader_exit_code` separately from the final runner exit:
successful Cargo completion followed by a descendant leak still fails. The
`before_cleanup` snapshot records native Job accounting and its process-ID list
before termination. Each retained process image and creation time is read through
a held process handle only after membership in that exact Job is confirmed.
An exited or reused PID is reported as unavailable, never attributed by name or
used as cleanup authority. `after_cleanup` is captured if the Job does not empty.

The snapshot uses one fixed 256-PID buffer, at most 32 process observations and
1024 image-path characters per process. It stops between queries after one second;
the individual Win32 metadata calls have no cancellable timeout contract. Errors,
truncation and unavailable fields remain explicit. It starts no diagnostic child,
enumerates no unrelated host processes, and collects no command line/environment.
Snapshots are observations at different instants, so accounting and list counts
can differ while processes exit. They do not relax the leak or cleanup gates.

A compiler/PDB server is a hypothesis until its owned image is observed. Do not
allowlist a process name, detach it, or lengthen the grace period merely to make a
build pass. The real exited-leader Windows control must retain the known child's
PID, creation time and image before cleanup and still confirm its termination.


## Compiler tools during CI builds

Native jobs at `8fb0fbe9` and `aa530138` retained a live owned MSVC
`vctip.exe` after Cargo exited successfully. The temporary Visual Studio
telemetry policy applied/restored correctly but did not prevent that lifecycle;
it has been removed. Every surviving descendant still fails the build.

This hosted qualification job explicitly uses the installed LLVM `clang-cl`,
`llvm-lib`, and `lld-link` at `C:\Program Files\LLVM\bin` while retaining the
`x86_64-pc-windows-msvc` Rust target and Windows SDK/runtime. It therefore
qualifies Windows/MSVC ABI behavior with LLVM C compilation and linking, and
does not claim to qualify Microsoft's `cl.exe` or `link.exe` implementations.
Missing tools, reparse-point inputs, inconsistent versions, unexpected driver
output, or a non-MSVC compiler target refuse before compilation. No PATH or
project compiler preference supplies a replacement executable.

`compiler-tools.json` records fixed absolute paths, sizes, SHA256 hashes, PE
versions, bounded driver probes, selected child environment and source URLs.
Read-only handles pin these tools through build and doctests. `llvm-lib` has no
version command, so its PE VERSIONINFO version is combined with the documented
LLVM Lib help marker; all three versions must agree. Native probes themselves
must pass the same owned Job, exit, EOF, and cleanup checks as all other runs.

The child-only environment sets every documented `cc` 1.2.55 CC/CXX/AR
host/target spelling, a fixed Cargo target linker, and encoded Rust/rustdoc
linker flags. This explicit CI profile replaces ambient/project rustflags and
compiler wrappers. Native host mode (no `--target` and no inherited `CARGO_BUILD_TARGET`) ensures
linker flags also cover build-script and proc-macro compilation. Project,
ancestor and Cargo-home configuration files refuse instead of overriding this
fixed profile; the controller explicitly selects the installed stable MSVC Rust
toolchain and verifies its verbose host identity before Cargo runs. It does not change
process-wide environment, installed tools, registry, product account defaults,
Cargo.lock, or product harness cleanup. Compiler debug output is bounded by the
existing build log limits. The next full native build must still prove absence
of surviving helpers; portable fixture success is not that proof.
