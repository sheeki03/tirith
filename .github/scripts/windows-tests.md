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
