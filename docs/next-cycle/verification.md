# Implementation verification

## September 29: integrated product checks pass

All five workflows pass on `e2c94439786d2d2abf87bd50a17b227f8e632c12`, each
on its original attempt: [CI 36450736676](https://github.com/sheeki03/tirith/actions/runs/36450736676),
[native ARM 36450736531](https://github.com/sheeki03/tirith/actions/runs/36450736531),
[release validation 36450737299](https://github.com/sheeki03/tirith/actions/runs/36450737299),
[fuzz 36450736603](https://github.com/sheeki03/tirith/actions/runs/36450736603)
and [benchmarks 36450736660](https://github.com/sheeki03/tirith/actions/runs/36450736660).
The C00 capability fingerprint and generated matrix now pass on the integrated
source; the previous failure and its reviewed correction remain recorded below.

The actual CI merge is `3252fe93c96ccf308336c03e59547de77e8f0ec5`.
Of 662 captured source inputs, 661 match the submitted head; the sole difference
is main's daily root ThreatDB manifest, which tests include. Original macOS
output confirms both capability checks. Windows passes all 60 harnesses and the
nine standard-account dashboard cases, with the account's lack of elevation and
administrator SID confirmed and owned process cleanup verified. Its original
artifact is `10984038839`, ZIP SHA-256
`4214d502fa35865e24b65325786848fa869780052f1a97e54c323dbc72fde4e1`.

Release validation passes all six target builds, platform smoke tests, GNU
runtime checks on AlmaLinux 8, Amazon Linux 2023 and Rocky Linux 9, native GNU
and musl ARM containment, npm assembly, Debian/RPM assembly and RPM runtime
checks. Publication and attestation jobs are skipped on the PR as intended.
These results establish development-package checks; they do not establish
official publication, production v2 availability or a human pilot.

## September 29: capability compatibility record

(Historical: the local-leaf npm routes `pkg install-npm` and `pkg materialize` were
later retired before release; see the archive tags.)
The first integration at `cd914781` exposes one stale compatibility fingerprint:
`capability_manifest_bytes_are_frozen` fails on Rust 1.83 and Windows because the
new manifest was not reflected in its reviewed C00 contract. Windows completes
all 60 harnesses; the other 59 and all nine standard-account dashboard cases
pass, with owned cleanup verified. This is not a passing full-workspace result.

The follow-up compares all parsed manifest entries against `bd9d5068`: 89 become
90, with only `pkg install-npm` added to the existing Package firewall group.
No existing command is removed, renamed, reordered or regrouped; all existing
inspection levels and policy-completeness flags remain unchanged. Only the
legacy `pkg install` coverage prose changes, to distinguish its unchanged refusal
from the separately qualified local-leaf route. Manifest version remains 1.
The new capability retains every bounded-contract and production-feed condition
recorded below. The C00 fingerprint moves from
`36a81bdd0c28147d1395fc208855031bca72d295be07b74b985fe6e083edd6d4` to
`a7eee1dc51d11e2e1c1df73c48ed997837afc6c73ba7c2f1b1b6ccecbff7ac63`
with that explicit review; no compatibility guard is removed or relaxed.
Unreleased changelog and stability notes now describe the same qualified scope.

## September 28: complete supported native npm contract

All five ordinary workflows pass on `bd9d5068`: CI `36443830209`, native ARM
`36443830065`, release validation `36443830848`, fuzz `36443830302` and benchmarks
`36443830344`. Original macOS output confirms the corrected script-analysis
regression. The actual CI merge is `55403c7c`: all 662 captured source inputs
match the branch except main's daily test-included ThreatDB manifest. This
checkpoint precedes the platform-gate promotion described below.

[Run 36447327426](https://github.com/sheeki03/tirith/actions/runs/36447327426)
passes all seven contract cases using the exact retained `24048758` fixture
binaries from native build `36444393465`. Four coordinator cases cover success,
cancellation before effects, private unwind and published unwind. These unwinds
occur after authenticated child completion, not during live process execution.
The literal import-free lifecycle hook throws if executed; exact successful
installation proves its suppression. The implicit native-build fixture instead
refuses with `AnalysisIncomplete` before transaction, target or operation-state
effects. It is not counted as a successful install or implicit-script suppression.

The actual public CLI completes plan, reviewed JSON apply, historical status and
identical-retry refusal. Independent snapshots verify the exact canonical
members/directories and hidden-lock schema/integrity, with unchanged installed
tree and operation records across status/retry. Dynamic descriptor binding is
the product verifier's observation; no separate kernel trace is claimed.

The original artifact is `10982105336`, ZIP SHA-256
`334938c6641ebd2c0e759e1ec584d98973de5f357486bdd66004206d32b9c4b2`. All original member hashes, raw/stage streams, source,
runtime/ELF postchecks and owned-child/container cleanup are verified. Independent
review SHA-256: `c58d8cd2b81c23c2d410e9ec5fe60bcc5359968333177503913cd9153f49475a`.
Both source variants retain their sole explicit fixture-public-key difference;
the normal production-key build refuses the signed fixture. Production trust is
unchanged, and production feed availability is not established by these tests.

The compiler run uses Rust 1.98.1 and the pinned Node 26.7.0/npm 11.19.0
runtime on native AArch64. It passes strict Clippy, normal-key rejection and one
human-output apply, then removes all four owned containers. The retained suite
performs no compilation, runs as UID 65534 with no capabilities or network, and
verifies cleanup of 192 owned children and its one container. Its measured
memory peak is 1,482,534,912 bytes, with no memory-limit or OOM events.

| Original build input/output | SHA-256 |
| --- | --- |
| Source manifest | `54899e96a466099d7c9ae009f957ec777c4b92629ae03adc4f988f0eef29f6e7` |
| Compiler artifact ZIP | `d56f54ce93ea0ec8ab5d21961483916e1c25c87170212f6fc62b1ff15241a81c` |
| Fixture public key | `0aa54a88aec2a8e704b67ebc1658dd149a88eb5af24f5c6e90ac00b52dadd519` |
| Fixture signed feed | `56cf609ce14d1d0738d8ce6491397bb1408b920e3fa2c61509a4bf2c41ed54e9` |
| normal launcher | `155f99563f0a705cfa2eba3e464ccb7ea6d16761c3c6ee41e14f1889224c58e6` |
| normal libtest | `30839f29ccb472928ae72c14e22f455c0cfe12762e0bd884fa71410e3ea744f4` |
| fixture launcher | `d05bf89c191b46c633f619cff92373f48dacc4c71e2f700cb39ea08f42474d67` |
| fixture libtest | `fd8e20a30c459809edd9463123a5d55f3ca5a52a3f9e251892afc69cbf06231e` |

The integration promotion uses the six reviewed qualification/test files from
`24048758`. Two subsequent reporting corrections derive a lower-layer test's
platform-gate flag and label missing pinned inputs `InputUnavailable`; neither
widens execution authority. Only GNU Linux AArch64 passes the platform gate.
All ordinary source/tool/task/confinement checks remain mandatory, and the
published v1 feed still cannot admit the route. Final integration CI and official
release acceptance remain distinct from the recorded native fixture evidence.

## September 28: native publication succeeds; script fixtures need correction

All five original workflows pass on `caafefc8`: CI `36434532398`, native ARM
`36434532379`, release validation `36434532989`, fuzz `36434532369` and benchmarks
`36434532496`. The retained x86 and GNU ARM logs confirm the stdio controls and
the npm Landlock control. The latter has an explicit older-kernel refusal branch;
its passing line alone does not identify which ABI branch ran. The actual PR
checkout is merge `4da64b03`, tree `c3799730fde5e94e0d3bcc28c330d48939e60c4c`.
Its 662 captured inputs differ from the submitted head only in main's daily,
test-included ThreatDB manifest. Source-binding SHA-256:
`a876a7022f59841c15e7f3d0c93aaf789c89a1257aff0cd5f54f8c6ba59711f3`.

[Native run 36435493526](https://github.com/sheeki03/tirith/actions/runs/36435493526)
passes on private product `2e26baa3`, based on `caafefc8`. One human-output apply
exits 0 and publishes the exact canonical tree and hidden lock, with linked
private/committed receipts and confirmed cleanup. This is an explicitly isolated
test-key build; the normal production-key build refuses that same signed fixture.
Type checking, strict native Clippy and protected-exec parsing also pass.
Artifact `10976780931` has ZIP SHA-256
`6f5651d02d911ecaaba096e185205e4e09a86070ca9d55b2837057c4c91860c7`.
All 2,479 members are hashed; both 662-file source captures, four retained ELFs,
1,058 raw streams, 80 stage streams, 529 child cleanups and four container
removal/absence records are verified. Source/runtime postchecks pass, with no
OOM or maximum-counter event. The publication verifier independently reproduces
the receipt from the retained finished event and bounded tree snapshot. Review
SHA-256: `8fccf3aaf51d76773d8bab53315ea78a1ab7640e0f2f58757880d7323e0f36a6`.

[Retained-build run 36442252373](https://github.com/sheeki03/tirith/actions/runs/36442252373)
then passes all four coordinator cases: success, cancellation before effects,
private unwind and published unwind. The latter two are controlled unwinds after
authenticated child completion, not live process death. The script test refuses
at preparation with `AnalysisIncomplete`; the full public CLI protocol is not
reached. All 123 owned children and the single container clean up, and source
and runtime postchecks pass. Artifact `10978847592` has ZIP SHA-256
`8bb0e17f20c816f3e2115ebc186d99345d1ae359e166e016a6845231f3febcad`.

The script fixture incorrectly expected module imports and lifecycle arguments
outside the supported analyzer contract to receive an Allow decision. It now
uses a literal, import-free hook that throws if executed, and its portable
regression requires complete analysis with no coverage issues or review signals.
An ordinary retained macOS product with unchanged analyzer source independently
confirms that semantic fixture's complete static coverage. The native implicit
build case now requires `AnalysisIncomplete`, no target, no operation state and
no transaction checkpoint. The production completeness floor is unchanged.
The corrected native script and complete CLI protocols remain to be executed;
the integration branch's public execution gate remains closed.

## September 28: cache reparenting and stdio restoration corrections

The npm-specific Landlock policy now requires ABI 2 and grants `REFER` beneath
the two already held writable roots. ABI 1 denies a move between their child
directories. In the captured npm inventory, cacache moves its temporary file
into a content directory; `@npmcli/fs` falls back to `copyFile` after a cross-device
or permission error. That fallback requests file metadata changes which remain
denied. The correction enables the original confined move without adding
metadata or copying syscalls. Exact read/execute file grants and the ordinary
capsule's ABI requirement are unchanged. New native controls compare ABI 1's
refusal with the production helper, verify outside/runtime-file refusals, and
require refusal on kernels without ABI 2.
The original rename errno was not logged, so its specific `EXDEV` remains a
source-based explanation rather than a captured syscall result. Independent
Landlock review SHA-256:
`3ea0ff97b01c53926e6c638e4b5e8de7f74ee9213e6e9325a39c8f6f971518b5`.

Node 26.7.0's [stdio restoration](https://github.com/nodejs/node/blob/v26.7.0/src/node.cc#L689-L698)
uses `fcntl(F_SETFL)` after libuv changes pipe blocking mode. Both native syscall
policies now admit that command only on descriptors 0–2, with a full-width mask
limited to access bits, nonblocking mode and the architecture's kernel
large-file bit. GNU libc's zero-valued `O_LARGEFILE` macro cannot substitute for
the actual kernel bit. Setting append, asynchronous notification, direct I/O,
no-atime and high-word flags remains denied. This is a descriptor-number rule:
a descriptor rebound onto 0–2 can also have existing mutable flags cleared.
The controls cover real pipe adoption followed by restoration and continued
denial of other descriptors and flags. Independent source review found no
actionable issue; SHA-256:
`fa1c7f03d89f9567f685f5ca12005e38e2bad95371340ba7617b1dc300aa8a2f`.
Native execution and the corrected public install still require verification.

## September 28: corrected stdio reaches npm cache handling

[Original run 36429827498](https://github.com/sheeki03/tirith/actions/runs/36429827498)
builds private candidate `887944ad` from `7e8b4272` with the same explicitly
isolated qualification and fixture-authority changes. Type checking, strict
native Clippy, protected-exec parsing and normal-production-key refusal pass.
The corrected bootstrap reaches npm itself. Its single public human-output
apply fails: npm reports an unsuccessful cache `copyfile`, and Node then asserts
while restoring standard-descriptor flags. The parent apply exits 1 and records
contained status 139. Publication is false; the installed tree and journal are
absent, with only intent, started and finished records retained. The diagnostic
workflow's green result does not establish installation success.

The original artifact is `10973892443`, ZIP SHA-256
`49a46477ff1ab0e2c781cb381964cdc1a65adc7cb046bc428f89997d0cc4e4a9`.
Independent readback rehashes all 2,477 members (693,367,637 bytes). Both 661-file
source captures match, with only the expected fixture-key substitution. All
1,058 raw command streams, 80 stage streams, 529 owned-child cleanups and four
exact-container removal/absence proofs pass. Both runtime input checks and
final source/tool/executable checks pass. Peak memory is 6,083,063,808 bytes,
with no OOM or maximum-counter event. Independent review SHA-256:
`a4f64cb535c8d0aa465f42dacdbba5fb88cd3ecbb659befef0f59a0d79e7caa5`.
The transaction suite remains unexecuted pending the two compatibility fixes.

## September 28: 7e8b4272 ordinary checks pass

All five original PR workflows pass at `7e8b4272`: [CI
36428525581](https://github.com/sheeki03/tirith/actions/runs/36428525581),
[release validation 36428526046](https://github.com/sheeki03/tirith/actions/runs/36428526046),
[native ARM 36428525594](https://github.com/sheeki03/tirith/actions/runs/36428525594),
fuzz `36428525529` and benchmarks `36428525582`. All are attempt 1.
The original x86 and GNU ARM logs confirm five named filter controls, including
actual standard-output/error pipe mode changes and continued denial of other
descriptor controls. The passing ARM parent also exercises the npm filter's
inherited-pipe case. This verifies the syscall correction, not the complete
Node/npm installation transaction.

The actual checkout is merge `bebefe48a98d23a57b1bde6db88dcdc4aae55e9e`,
tree `ee744e085ceddd0a653d81f0a93cf292c8084eef`. Of 661 captured inputs,
660 match the submitted head; only main's daily test-included ThreatDB manifest
differs. Exact source binding SHA-256:
`52e9a63ff1347ccb23dd7be340fc82b43b86fc69e18a4d9f957be3c60df028b5`.
Native qualification receipt SHA-256:
`007bed8653aaf526cf6c84d74f63bb1e7825c479836b0cea0c1ce34eeda21619`.
Independent readback verifies the nine retained API/log records and the exact
checkout and passing-test lines; SHA-256:
`c931820a3f432ccc6cb48ba3bb27c2791239e63942b349cd7bdb1aa934957803`.
These are PR validation results, not official release publication.

## September 28: stdio compatibility and bounded bootstrap diagnostics

The correction permits only `ioctl(FIONBIO)` on standard descriptors 0–2 in the
ordinary x86-64 and ARM filters and the derived ARM npm filter. Ordinary capsule
supervisors also pipe their output, so the same compatibility fix applies there.
No socket, general ioctl, arbitrary descriptor-mode change or scheduling query
is added. Controls check full-width argument aliases, actual pipe flag changes,
other-descriptor refusals and continued network/unsafe-control denial.

The generated bootstrap sets refusal status 78 before a bounded raw stderr
write, using only closed stage/code/name/reason labels. Its exception message,
stack and input paths are not printed. Seven generator checks and all 128 pure
JavaScript controls pass (56 bootstrap, 37 descriptor and 35 resolver cases).
The generated bundle is SHA-256
`70d34f769895fe1424473815c3032c6a48387684439f0efa6bb3b52aac8923dc`.
Native filter execution passes on the corrected source as recorded above.
The integrated install remains a separate qualification.

A separate local Node 26.7.0 setup-only probe loads the retained 1,926-file npm
inventory into the real VFS and reaches argument binding and fetcher setup. It
stops deliberately before the npm CLI entry. The corrected inert input fixture
passes in 0.72 seconds with its child reaped and process group absent; an earlier
probe with an incomplete mocked descriptor row is retained as a fixture failure.
Native binding admission and Linux process metadata are mocked in this probe,
so it does not certify containment or installation. The corrected native
observation above separately reaches the npm CLI and records its later failure.

## September 28: retained npm diagnostic isolates a stdio incompatibility

[Diagnostic run 36425528542](https://github.com/sheeki03/tirith/actions/runs/36425528542)
uses the exact retained `dc8cb195` fixture executables without rebuilding. One
fresh public plan is followed by one human-output apply. The diagnostic workflow
completes successfully, but the apply exits 1: publication is false, the installed
tree and checkpoint journal are absent, and only the intent, started and finished
operation records remain. This is a failed installation observation, not native
installation acceptance.

The forwarded stderr contains `Error: open EPERM` in Node 26.7.0's lazy stderr
initialization, reached from the bootstrap's catch handler. Source tracing maps
this to libuv's `ioctl(FIONBIO)` on the inherited pipe; the captured ARM filter
denies that request. The `Socket` constructor in the stack adopts the existing
pipe and does not establish that network socket creation is needed. See the
[exact Node constructor](https://github.com/nodejs/node/blob/v26.7.0/lib/net.js#L636-L651),
[pipe adoption](https://github.com/nodejs/node/blob/v26.7.0/deps/uv/src/unix/pipe.c#L195-L213)
and [Linux nonblocking operation](https://github.com/nodejs/node/blob/v26.7.0/deps/uv/src/unix/core.c#L654-L665).
This secondary reporting failure masks the original synchronous bootstrap
exception. Repeated thread-scheduling query warnings do not establish the
installation's fatal cause. The discarded earlier V7 output is not recovered.

Independent readback rehashes all 310 original artifact members, 284 raw command
streams and 22 stage streams. All 142 owned-child cleanups and exact-container
removal/absence pass, as do runtime and final source/input checks. Observed peak
memory is 925,388,800 bytes, with no OOM or maximum-counter event. Artifact
`10971363105` ZIP SHA-256:
`cf286315b1e0b825042ef697d89fca20475e274b0a3a02ff94cb9994f82a040d`.
Independent readback SHA-256:
`cdd07c9f108e928523615b47054b409fbf8d20cc6c88c1ec264f671136eb588a`.
The production execution gate remains closed while the narrow stdio correction,
original bootstrap cause and seven-case native suite remain under investigation.

## September 28: 83468789 ordinary checks pass

All five ordinary PR workflows pass at `83468789`: [CI
36420022612](https://github.com/sheeki03/tirith/actions/runs/36420022612),
[release validation 36420022647](https://github.com/sheeki03/tirith/actions/runs/36420022647),
[native ARM 36420022270](https://github.com/sheeki03/tirith/actions/runs/36420022270),
fuzz `36420022385` and benchmarks `36420022275`. The release workflow includes
all six target builds and its package/runtime checks; it does not publish an
official release. Workflow result record SHA-256:
`d7b09a8c24ebe9bfa150d023d3b50ad3935638a6f684183fcd1e8307395f05be`.
The tmpfs native controls and precise actual-checkout source delta are recorded
below. The full Linux lifecycle composition also passes as recorded next;
integrated npm execution remains unqualified.

## September 28: ordinary Linux service-worker composition passes

Historical record. The browser update/rollback pipeline this entry qualified
(lifecycle journal, detached worker and `/api/lifecycle/{prepare,operation}`)
was later removed; binary updates are CLI-only.

The ordinary GNU ARM package from `83468789` passes the complete local
service → production worker → binary replacement → product-created fresh service
sequence on LinuxKit 6.12.76 as UID 65534. The installed binary changes from
SHA-256 `0dc6c9e4ef0547eabd1d506d0af5aab8cdd64f31ca3caec12ede1afe6c3e68bc`
to the retained `e282d038` package
`be7abc4df2e1de7ab56083d3179914443903a5c31fcdcfe9ee219a1b256f0742`.
Both packages remain version 0.4.2, and the prior receipt is explicitly synthetic.
This proves the actual worker composition; numeric update/rollback and host
reload are established by the separate macOS cases below.

The operation moves from accepted to completed with publication true. The fresh
service has a different PID, binary digest, service/startup identity and token;
the old token receives HTTP 401. An identical retry returns saved status without
another publication or file changes. The previous image, receipt and harmless
shell configuration retain their exact identities and hashes. The separate
non-FIFO worker refusal leaves its prepared journal and files unchanged, then
cancels successfully.

The single attempt lasts 13.44 seconds. All thirteen host jobs and four direct
guest children close; the fresh service quiesces, and the exact owned container
is removed and observed absent. All ten preexisting containers remain running,
no additional container remains, all eight input hashes match, and no OOM is
observed. The container remains the cleanup backstop. The supplemental process
observer sees the production worker, but does not claim complete phase history.
Original report SHA-256:
`af602d0536273a180ea619c60b9ef7d7c678467871b99d8f9fa0b9e32faa3403`.
Independent readback SHA-256:
`a3cd282aa83eb87c675c0411f1c670c7891fdd041326ac84d25a1831a2e85da0`.

This closes the concrete development handoff check. It does not claim an
observed macOS dashboard worker sequence, a production download, historical
receipt capture or final official channel acceptance. The remaining final-byte
release rows stay under WP19.

## September 28: aa88c7ae native corrections pass

All five ordinary PR workflows pass at `aa88c7ae`: [CI run
36396156183](https://github.com/sheeki03/tirith/actions/runs/36396156183),
[release builds 36396156598](https://github.com/sheeki03/tirith/actions/runs/36396156598),
native ARM `36396156199`, fuzz `36396156268` and benchmarks `36396156218`.
The observed PR merge `57c862192590f199b637519e7c27aa3518476d1b`
has the same tree as the integration head. These are PR builds, not published
official release artifacts.

The Windows workspace passes all 60 harnesses, including nine dashboard cases
under a standard account. All three new scoped-reader controls pass: actual
reader/writer publication coordination, recursive reads with preserved short
waits, and refusal of cross-target contention without a nested lock wait.
Build, harness, dashboard and doctest processes report reaped leaders, empty
native jobs and drained output without leaked descendants. Artifact
`10958661912` ZIP SHA-256:
`da3573838562627737d48af8f3111508b321bb55c77b350133e90d10230830ad`.

Windows PowerShell 5.1.26100.33438 and PowerShell 7.6.6 both pass native profile
resolution and the product's own-process command-line query. Profiles remain
unchanged and poisoned user modules are not loaded. Artifact `10959016083`
ZIP SHA-256:
`7e960697586ec74c155a7d120f7d0ee056307c16a933b022b8e200b842a902bd`.
Linux and macOS also pass both default and private-XDG target cases with their
owned processes and staged runtimes cleaned up. Independent readback rehashes
all 155 files from these four small evidence archives and verifies the native
reports and cleanup records. Readback SHA-256:
`9b9640b40730cb830e08a74f3c2af2dc04abb8387b8ae33373d411fce10f45a0`.
This closes the corrected target-resolution and Windows journal checks; it
does not advertise an automatic PowerShell receipt adapter.

## September 28: narrow Linux tmpfs ACL compatibility correction

The lifecycle diagnostic below identifies an unsupported ACL lookup on tmpfs.
The correction does not treat that errno alone as ACL absence: Linux invokes
the security hook before its unsupported-inode check. A successful tmpfs
attribute listing separately includes both access and default POSIX ACL names.
See the [kernel ACL implementation](https://github.com/gregkh/linux/blob/v6.12.76/fs/posix_acl.c)
and [tmpfs attribute listing](https://github.com/gregkh/linux/blob/v6.12.76/fs/xattr.c).

Only the Linux executable caller with already validated owner/mode metadata
can use this exception. It opens a no-follow descriptor, matches the admitted
identity and generation, proves the exact tmpfs filesystem type, repeats the
unsupported ACL query on that descriptor, and requires a complete bounded
attribute list containing neither ACL name. Descriptor and visible-path
generations must still match afterward. Actual ACLs continue through the
existing parser; unknown filesystems, failed lists and ambiguous state refuse.
Metadata-free callers, Android and the separate npm authority digest retain
their existing strict behavior.

Eight focused controls cover supported self and foreign ACLs, actual tmpfs
listings, list errors, malformed names, exact error/filesystem restrictions,
type mismatches and path/generation changes. All eight pass in the GNU job of
[native ARM run 36420022270](https://github.com/sheeki03/tirith/actions/runs/36420022270),
alongside all three existing Linux ACL controls. The actual checkout is PR merge
`e8541cf1e7c572bdd51982d62b577fa63996307a`, containing head `83468789`
and main's daily ThreatDB manifest update. Of 661 captured inputs, 660 match the
head exactly; only the test-included manifest differs. The ordinary product's
source files match. Native-test receipt SHA-256:
`b8b9307cb06adb0235e89a3462e94176ff1e16c589c18144060405cef805dee5`.
Actual-checkout source binding SHA-256:
`bd2281a09594d3e886ed2d4a873f3e1c43d167fcea98b198ca0150f354b7ff5e`.
The later full LinuxKit composition above passes with this ordinary binary.
Its success report does not instrument the exact ACL fallback branch; the
specific branch's use is inferred from the earlier same-platform refusal and
the narrow source change. Other filesystem exceptions remain unsupported.

## September 28: retained npm candidate reaches a post-launch failure

Private candidate `dc8cb195` and controller `4197cbc4` complete native typecheck,
strict Clippy, protected-mode parsing, fixture generation and rejection of the
fixture feed by the unchanged production key in
[run 36418502424](https://github.com/sheeki03/tirith/actions/runs/36418502424).
The first fixture transaction reaches authenticated execution, then npm exits
with status 1. Its result is `MayHaveStarted`, with publication false and cleanup
confirmed. No mechanics case passes, and the public CLI case is not reached.
This candidate separately enables the GNU ARM contract for qualification; the
integration branch's production execution gate remains closed.

Artifact `10968924300` retains all four normal/fixture launcher and test-harness
executables. Independent
readback rehashes all 2,427 members, checks the 660 normal source rows and the
fixture's sole public-key substitution, and verifies all 509 child and four
exact-container cleanups. No OOM event is observed. Final source, controller and
executable checks pass; the fixture runtime's own input-postcheck was not reached.
ZIP SHA-256:
`1c7d21475ec40dbe58798e7aeea04470a8f3acbfe88403217901cefa1f972d27`.
Independent readback SHA-256:
`c0d0f038ec2c3aa5c1650a26620d76f6b201c191a3ffe1cd9ab4bc452b27b56f`.

The test uses JSON presentation, which intentionally suppresses child output.
Its discarded npm message cannot be recovered from this artifact. The existing
non-JSON apply route forwards bounded sanitized child output and can diagnose a
fresh case using the retained executables without another build. Such a run
would not reconstruct the original failure or establish seven-case acceptance.

A read-only recheck of successful scheduled publication `36412166266`, the
`threatdb-current` asset inventory and main revision `77069300` still finds
only the legacy database generations and source-provenance files without the
matching signed integrity sidecars.
The v2 index at that immutable main revision returns HTTP 404; no v2 database
asset or signed source-integrity sidecar appears in the current release.
This is a metadata observation, not another database verification or a publisher
recovery exercise. Recheck SHA-256:
`89e431395dcc8e32fa1cc39d597d255a56814422fe049aec8ba556bf13ace53a`.

## September 28: protected Linux execute-only mode 2

Native ARM run `36394084953` executes a small static OS probe in the pinned npm
runtime image as UID 65534, with no capabilities or network and no system-setting
changes. A readable executable becomes dumpability mode 1 and permits the
same-user parent to read its inert canary through procfs and process memory and
attach/detach with ptrace. The execute-only control becomes the observed host
policy mode 2 and denies those fresh accesses with EACCES/EPERM. Before exec,
mode 0 already denies private-descriptor acquisition; the launch descriptor is
closed on exec in both controls.

Both probe children exit normally, all 23 owned CLI children and both exact
containers clean up, and all 54 retained files rehash. The static probe ELF is
709,080 bytes, SHA-256
`f0e570eae2f58d179bd4b50792abd9b5470231b604d74fe98ee3a1824f7a3605`.
Independent original-result review SHA-256:
`25d17e10be691b91491d8f74388c0df51cd6824a7a616d1b0e4436ca01f76cda`.

The launcher prerequisite now accepts the kernel's protected modes 0 and 2;
mode 1 and malformed values remain refused. Mode 2 permits administrator-controlled
core handling and is not described as disabling core dumps. This change avoids
an unnecessary system-wide configuration requirement while preserving the
ordinary same-user protection boundary. It does not identify the original npm
fixture failure or qualify integrated npm execution; that gate remains closed.

## September 28: Windows snapshot/publication coordination

At `2d723b0f`, CI run `36392165108` passes the ordinary Windows harnesses but
one of nine standard-account dashboard cases fails: profile application reaches
its applied step, then journal replacement reports `ERROR_SHARING_VIOLATION`
while the client polls status. Artifact `10956724886` ZIP SHA-256:
`7653a8a692aefb62f6fe6cefbbe83c41adef6fbcfe8057c794c001d03314e281`.
Native cleanup passes. The later PowerShell resolver check is skipped. Linux,
macOS, Rust 1.83, release, native ARM, fuzz and benchmark/resource jobs pass;
Windows and its dependent missing-evidence uploads are the only failed CI steps.

Scoped snapshot readers hold handles that intentionally deny deletion but did
not coordinate with the atomic writer. They now join its bounded per-path mutex
through the complete read, preserving file, generation and DACL checks. Explicit
shorter transaction timeouts also apply to preflight reads. Nested acquisitions
never wait while holding another transaction mutex: same-path recursion works,
and a contended different target refuses without creating a lock cycle.
Native controls cover reader/writer contention, actual replacement with unchanged
permissions, recursion, short waits and cross-target contention. Static review
and the corrected `aa88c7ae` Windows product and resolver checks pass as recorded
above.

## September 28: ordinary Linux lifecycle handoff diagnosis

Two bounded compositions use the ordinary `d0213a22` and `e282d038` GNU ARM
PR images with explicitly synthetic rollback history. Both images retain
version 0.4.2; this checks worker composition, not numeric upgrade or production
download. The actual service prepares and accepts the operation. The second
attempt records `refresh_required`, `published: false` and
`worker_handoff_failed` before cleanup; the installed image remains unchanged.
It does not produce the replacement service within the observation deadline.
The saved code cannot distinguish the initiating handoff stage. Report SHA-256:
`38e99959032da37a3e9c209aab65734baf45450d826e5ea2c2f8b3eeae28c5a3`.

The separate refusal control leaves its prepared plan, installed files and
configuration unchanged, then cancels successfully. Its original fixture label
mentions an oversized frame, but Node creates a socket pair and the worker
requires FIFO handles. It therefore establishes unsupported-descriptor refusal,
not the frame-size parser branch. Original artifacts retain their original
labels; this correction defines the supported claim.

All thirteen owned Docker CLI jobs and four direct guest children close, the
exact container is removed and observed absent, all eight input postchecks
pass, and the ten preexisting containers remain running. Source review separately
identifies buffered worker standard I/O used with raw-descriptor polling.
The correction retains unbuffered pipe files and records a finite public failure
stage separately from bounded private diagnostics. Each nonblocking write uses
the existing scoped SIGPIPE guard so a peer closing after readiness cannot
terminate the service. Five actual pipe/stdio controls, including default-SIGPIPE
refusal and signal-state restoration, and eleven lifecycle-store controls pass
locally and ordinary `aa88c7ae` CI passes. The passing numeric
replacement/death/reload cases below remain distinct from full service/worker
composition.

A third bounded composition uses the ordinary `aa88c7ae` GNU ARM archive with
the same previous image and synthetic history. The new diagnostics identify
`worker_handoff_executable_untrusted`: the fixture binary's
`system.posix_acl_access` query returns EOPNOTSUPP. The saved operation remains
`refresh_required`, unpublished, and the installed image stays unchanged.
This identifies the initiating cause of this attempt; it does not retrospectively
establish the earlier attempts' causes. The unsupported-descriptor refusal and
cancellation pass. All thirteen host child jobs and four direct guest children
close, the exact container is removed and observed absent, eight input hashes
remain unchanged, and the ten preexisting containers remain running with no
additional container left behind. There is no OOM. The attempt lasts 41.73 seconds.
Report SHA-256:
`b36467f54214810f9461144b69d72722793eaddec95804810e004a6557c07d88`.
Readback SHA-256:
`85182562085b2fb92e34201c3ac5d2cd2e70a2ad8a6c853ac08cda5125c1db32`.
This failed attempt remains preserved. The later `83468789` composition above
passes after the narrow tmpfs correction; unsupported ACL inspection by itself
is still not proof of absent permissions.

## September 28: cd062069 native PowerShell follow-up

CI run `36388805399` passes the Windows workspace and standard-account dashboard
suite, Linux workspace, Rust 1.83 workspace and native Linux PowerShell target
resolution. The Windows target artifact `10956286477` has ZIP SHA-256
`adaee46b91adb28888311852a12ef8beabc6d774aac50c616f0889a32aaf1263`.
Its original reports show Windows PowerShell 5.1.26100.33438 now starts, returns
all eleven profile fields, leaves the profile unchanged and avoids the poisoned
user module. The separate process command-line query returns unavailable, so
the complete 5.1 target check correctly remains failed. Its initiating cause is
not established by the current report. PowerShell 7.6.6 passes both checks.
Both outer native jobs report reaped leaders, empty jobs, drained output and no
leaked descendants. This is target resolution evidence, not interactive Windows
interception certification.

The same source passes Linux/macOS CI, native ARM GNU/musl containment, all
fourteen fuzz jobs, both benchmark/resource jobs and the complete PR release
workflow, including all six target builds, runtime/package checks and release
compatibility validation. Main CI fails only the Windows resolver step and
its dependent missing-evidence upload; skipped downstream Windows checks are
not passes.

A separate six-arm native diagnostic (`36391775036`, controller `088a610a`)
isolates the 5.1 query failure. Its absolute built-in CIM module import invokes
`Set-Alias`, unavailable with automatic module loading disabled. Both the two-
and twenty-second arms fail with that error; increasing the deadline does not
resolve it. The built-in `[wmi]` expression succeeds in both arms, and the
PowerShell 7 CIM query succeeds. All three return identical command-line text
length and hash for the same controller PID. Raw command lines are omitted.
All six jobs finish with confirmed cleanup and unchanged profiles. Artifact
`10956725744` ZIP SHA-256:
`3babbd13c77e7f00545f65effcacdc3a3c16c08ccaa495536c31cf1193648c29`.
These serial diagnostic arms may warm OS services and do not certify cold-start
latency. The correction uses the built-in WMI expression for Desktop edition,
keeps the absolute CIM import for Core edition, and retains the two-second
deadline, native SystemRoot-only environment and disabled module autoloading.
The ordinary `aa88c7ae` native product check now qualifies this correction as
recorded above.

## September 28: repeated actual Claude adapter measurements

Four fresh Claude 2.1.283 hosts use the ordinary `d0213a22` macOS ARM 0.4.2
product, the qualified Python runtime and actual recommended setup. Each host
performs one no-tool initialization, one unmeasured allow/block warmup pair and
six measured pairs. Independent ordinary checker preflights precede every pair.
All 56 actual tool turns, including eight warmups, pass tool/result identity,
hook-event and marker checks. Inputs, generated settings and policy stay fixed.

| Measurement | Samples | Nearest-rank p50 / p95, ms |
| --- | --- | --- |
| Allow turn, send through successful host-result return | 24 | 391.041 / 410.052 |
| Block turn, same unit | 24 | 369.972 / 395.690 |
| Recommended setup including owned cleanup | 4 | 3938.162 / 3979.042 |
| Host spawn through no-tool initialization, including owner checks | 4 | 387.658 / 409.991 |

The four-sample p95 values are the observed maxima. Turn clocks include finite
ownership checks while pumping host output; preflight and final semantic checks
are outside the timed interval. A scripted loopback provider is part of the
fixture, so no remote inference or service latency is measured. These are
observations for one recorded tuple, not universal budgets or confidence bounds.

Two direct-host resource observations per batch span warmup, turns and preflights.
CPU deltas are 1,220, 1,210, 1,200 and 1,260 ms at the native observer's display
precision. Sampled maximum host RSS is 321,781,760, 314,785,792, 318,734,336 and
322,502,656 bytes. These exclude descendant totals and are not kernel RSS peaks.
Each private fixture grows by 302,008 logical bytes after setup/initialization.
No cold-OS-cache, production-feed freshness or daemon-route claim is inferred.

The run completes in 51.54 seconds with exactly 29 requests per provider. All
75 registered children and four providers have confirmed cleanup. Independent
readback parses the four original host stdout streams, recomputes all sample
counts/distributions, rehashes 262 retained files and checks all eight input
generations. Report SHA-256:
`6ad3287a0f51f1b071989afdf93452942eff097902395c23d3d6c88d5efb3118`.
Readback SHA-256:
`3f88cdfab399285742a5701ac17e7b0d37913dc4098e83f74059b5a1804014e4`.
The separate resource regression gate continues to enforce its six reviewed
byte ceilings; these latency observations do not silently introduce another gate.

## September 28: retained-daemon grant expiry and revocation

One ordinary `d0213a22` macOS ARM daemon retains its exact PID, socket and PID-file
identities through baseline block, real one-minute grant allow, natural-expiry
block, same-UUID renewal allow and revocation block. All commands are analyzed
in an isolated offline fixture; the command string is never executed. The
production-signed database, exact URL/rule scope and private policy stay fixed.
An independent ordinary `check --no-daemon` also blocks after expiry.

The real-time wait records 117 unchanged grant-file generations and hashes;
maximum wall/monotonic divergence is 55.8 microseconds. No clock, file expiry or
cache state is injected. Eleven authenticated requests use the same daemon.
All seven owned children have confirmed cleanup, the daemon exits gracefully,
and its socket, PID file and private fixture are removed. Input postchecks and
independent readback pass. Total elapsed time is 61.77 seconds.

Report SHA-256:
`bd9004a94b168dcef6b669b08a745ccd013edeb5f087cbb43e58a7a4aa7c9326`.
Independent review SHA-256:
`368f3f821aaeee244983b8b301725f4350de3eca8785d556066613debb353995`.
This closes the planned retained-daemon expiry/revocation acceptance for these
ordinary bytes. It does not imply a new latency threshold or a cache redesign.

## September 28: retained Claude across numeric replacement

The original ordinary macOS ARM products and test controller described below
pass one actual Claude 2.1.283 composition across 0.4.2 → 0.4.3 → 0.4.2.
Recommended setup runs through the product; its generated policy is preserved
verbatim beneath an explicit schema-2 enforced restriction on untrusted
resource escalation. Actual CLI policy validation passes before publication.
This stronger policy belongs to this composition; the four earlier lifecycle
cases retain their original mode-only fixture policy and identities.

One retained host spans both replacements. Fresh hosts start after update and
rollback. All ten fixed allow/block tool turns have matching hook events,
results and once/never marker effects. Both durable publication records are
completed and published; configuration and input pins remain unchanged.
All 41 owned children and three loopback providers are cleaned up. The run uses
23 provider requests and completes in 53.48 seconds. Independent postchecks
rehash 157 retained files and all three 660-file compiler closures.

Result SHA-256:
`3e33d2ee4f4c83bc1d4fd0bf8b02693caef579234c621d62f4b591ff20c12087`.
Independent readback SHA-256:
`8bafbee67b4cc22a33b759cb6213972402d2d6eea3c5042b23f18de74db9d490`.
This observes the already-configured host across actual binary replacement;
it does not promise hot reload of newly installed hooks, expose a Claude
loaded-Tirith-version field, or qualify the production worker/download path.
The local provider supplies deterministic tool requests, not remote-model latency.

## September 28: real ThreatDB discovery and cold-client acquisition

The unchanged ordinary `d0213a22` macOS ARM 0.4.2 image runs `threat-db update`
with empty private data and state caches and a finite environment containing no
caller credentials. It installs production-signed format-v1 sequence
1790503422402, 242,343 entries, SHA-256
`47b867e2b686ce68d38402622fcd27fc54854115743b860a8bc1799c8db48112`.
A fresh ordinary `health --json` verifies the installed signature and sequence.
The independent publication verifier downloads both real primary and fallback
discovery documents and their referenced database, validates signatures and
hashes, and agrees with the actual installed bytes.

The run completes in 5.02 seconds; all three registered process groups have
confirmed cleanup, nine retained private files rehash correctly, and all input
pins remain unchanged. Result SHA-256:
`fa82302fa68a6e3e6dc24afbc5e1dc1b47b95a3a93a816aab7e2776731c0eccf`.
Independent publication result SHA-256:
`f3d214f1e924627f6fbcdf9c5e8f66a202c63e37a02403ec6b732ca4c1d5eb80`.

The source-integrity sidecar returns HTTP 404 for this legacy generation.
The product correctly retains the verified database and reports source evidence
unavailable, with no fabricated source ages. This closes real format-v1
acquisition/interoperability on these bytes. Signed v2/source-provenance
publication and actual publisher concurrency, partial upload and later-failure
recovery remain distinct operational acceptance; no remote state was changed.

## September 28: Windows PowerShell startup correction

Two bounded Windows diagnostic runs isolate the previous PowerShell 5.1
failure: the canonical device-path spelling fails startup, automatic module
discovery hangs at `ConvertTo-Json`, and an entirely empty environment lacks the
native Windows system directory. The fixed-field module-free query passes with
only OS-derived `SystemRoot`, for both PowerShell 5.1 and 7. Every diagnostic
child has confirmed native cleanup and personal profiles stay unchanged.

The product correction holds the admitted executable, verifies its bytes and
file identity before choosing an equivalent DOS path, and checks image/cwd
identity at both native process creation boundaries. Namespace-sensitive and
long paths retain their original spelling. Current-directory handles use
attributes-only access; pre-launch checks detect renamed paths rather than
claiming those handles prevent every ancestor rename. The existing owner/ACL
trust contract remains required. Parent/grandparent rename controls cover that
boundary without claiming atomic protection of every ancestor or drive mapping.

PowerShell version/startup observations opt into OS-derived `SystemRoot`.
The native profile query uses bounded fixed Base64 fields without module
autoloading. Startup observation imports the selected installation's built-in
CIM module explicitly. Poisoned module-path, malformed-field, file-identity,
handle-sharing and native startup controls accompany the correction.
The local shell-target selection passes eight tests, with the explicit native
PowerShell case correctly ignored outside its controlled driver. Formatting,
strict workspace/all-target Clippy, thirteen runtime-copy controls and eight
retained-daemon producer controls pass. Ordinary Windows/Linux CI must qualify the actual product changes;
diagnostic success alone is not product qualification.

## September 28: matched standalone and daemon workloads

The ordinary macOS ARM 0.4.2 release image from the `d0213a22` compiler closure,
SHA-256 `076d0481c2fb95ebbc1ccef9e5384b5a4c2a7e9263bf1934863160f580e5d6f2`,
passes the matched offline characterization on an Apple M4, ten logical CPUs,
macOS 27.0. No build or other qualification was intentionally run alongside
collection; ambient host contention remains uncontrolled.

Both isolated fixtures use the unchanged production-signed database
`47b867e2b686ce68d38402622fcd27fc54854115743b860a8bc1799c8db48112`:
242,343 entries, sequence 1790503422402 and original timestamp 1790503433.
Ordinary product status admits its signature. Publication age is about 19.7
hours; separate source evidence is unavailable and remains reported that way.
Disabling automatic updates prevents background collection and changes the
product's `stale` boolean; it does not refresh the signed timestamp.

Each row contains 100 samples per mode. Standalone time includes spawn through
owned-process cleanup and EOF; direct daemon time runs from request send to
response EOF after peer admission. These distinct units do not measure a shell
hook, model, cache-hit counter or cold OS cache.

| Fixture and inert input | Standalone p50 / p95, ms | Retained daemon p50 / p95, ms |
| --- | --- | --- |
| One custom rule, flat repository; URL analysis | 144.358 / 148.672 | 0.755 / 0.870 |
| One custom rule, flat repository; custom block | 132.092 / 135.905 | 1.270 / 1.412 |
| 256 rules, eight nested directories and 128 files; URL analysis | 149.175 / 154.368 | 3.621 / 4.041 |
| Same larger fixture; custom block | 136.291 / 139.935 | 4.215 / 5.972 |

One hundred fresh database-status processes have p50/p95 74.086/78.083 ms.
The two daemon startup observations are 20.639 and 20.901 ms, not a startup
distribution. Their sampled maximum RSS values are 81,166,336 and 84,426,752
bytes; observed cumulative daemon CPU deltas are 710 and 2,640 ms. Each fixture
grows by 548 logical bytes. The report keeps completed-child RSS high-water
marks, sampled daemon RSS, allocation counts and disk growth as separate units.
No new universal latency budget is inferred from this single host.

Independent review accounts for all 1,356 raw rows, recomputes 22 distributions,
compares 1,604 semantic results, checks 1,206 peer-PID/timing observations and
verifies 400 overlapping direct-client pairs. These socket pairs do not establish
simultaneous engine execution or real terminal behavior. All 552 owned children
have confirmed cleanup; the private fixture is removed and input pins match.
Twelve pure controls and eight owned responder controls passed before collection.

Original report SHA-256:
`8071fabab1c0b2fc202a8c9991ef24ee70561012493df037381015f6ed3bdaf0`.
Independent review SHA-256:
`5092c7be1cba42150a4b989168ed91edbd871f03125ea17964af80f7b5f933a8`.
The existing real-Zsh measurements and six ordinary CI byte limits remain
separate evidence. Repeated actual-host adapter distributions remain unfinished.

## September 28: numeric upgrade, rollback and observed process death

All four original native macOS ARM cases pass on the `d0213a22` compiler-source
closure: ordinary 0.4.2 → 0.4.3 → 0.4.2, and controller death at verification,
publication intent and published boundaries. The tracked package remains 0.4.2;
only an isolated source copy has the reviewed Cargo manifest/lock version delta.
The ordinary release executables are respectively
`076d0481c2fb95ebbc1ccef9e5384b5a4c2a7e9263bf1934863160f580e5d6f2`
and `2fd970cfb05b2d97e5516ca087099ed7052030b1255d78d21f9598c8c66baa41`.
The separately built test controller is
`c3aa0df7bc1b7685045916e1c3d8ab9a93229a1f3af3dfe225bec55949dbce77`.
Independent admission verifies all three builds, release/test roles, unchanged
660-file source captures and exact numeric-only variant before execution.

| Original case | Fresh ordinary-product dashboard result | Published bytes | Result SHA-256 |
| --- | --- | --- | --- |
| Complete update and rollback | Completed; rollback also completed | 0.4.3, then exact original 0.4.2 | `05524cf0841f0fa0f3beaf6f549477dbe483d21a21ef6a62c9ddeace9865db2c` |
| Death during verification | Refresh required | Original 0.4.2 | `4e6759df773fa01f4d49b2d1e2c0e5b660c331e4e80c2542037f73e8baef8519` |
| Death at publication intent | Recovery required; publication unconfirmed | Original 0.4.2 | `293603e521a17fc03709b7ca4c874fb2238d1683ff9b94d4cae045b40ada1db5` |
| Death after publication | Recovery required; publication recorded | New 0.4.3 | `24fa99ccfa294f31789c8141b990783de1a5792c1c2e321474d48f065b804cfd` |

Each death case observes an actual SIGSTOP and held production operation lock
before killing and reaping the owned controller. Two fresh product services
read the same operation UUID and return its saved result on repeated apply;
they do not resume interrupted work. Policy, startup configuration, legacy and
scoped trust, and MCP lock bytes survive. Ordinary allow/block checks pass before
and after replacement. All 44 registered direct-child cleanup records pass;
independent readback rehashes all 224 retained inventory files.

The retained interactive Zsh session reports installed version 0.4.3, loaded
version 0.4.2 and `reload_required`. A fresh session reports loaded 0.4.3 while
preserving the `matching_version_unverified` evidence grade. This is loaded
version evidence, not a fresh blocking certificate. Actual Claude host behavior
across numeric replacement remains separate.

The root readback report is
`756c58e386df09d7867718bcb93828bddf5d4b8835a8a1711e0a62d758177ebf`.
These tests composed the real verifier, compatibility checks, publication,
rollback receipt and the since-removed lifecycle store using a public fixture
signing key; the lane now stops between the CLI update primitives instead. They
do not certify an official release, production download/worker handoff, power
loss, all installation channels, or nested extractor cleanup after an outer
failure. See the [qualification contract](numeric-lifecycle-qualification.md).

## September 28: d0213a22 platform follow-up

The [CI run](https://github.com/sheeki03/tirith/actions/runs/36381188762) passes
macOS, Rust 1.83 and strict Clippy. Native ARM, fuzz and benchmark workflows also
pass, including the ordinary macOS ARM resource gate. Windows PowerShell 7.6.6
now matches the native profile target with unchanged profiles and confirmed
cleanup. Windows PowerShell 5.1 starts but fails during .NET initialization,
before the query. Linux refuses an absolute runtime symlink while preparing
the private copy, before either native query. Both original failures remain
retained and require correction; neither is counted as native qualification.
The [release workflow](https://github.com/sheeki03/tirith/actions/runs/36381189053) also passes: all six target builds, package assembly, runtime smoke checks and both canonical ARM containment checks. Official publishing remains skipped.

## September 28: current PR-package Claude qualification

All eleven Claude 2.1.283 cases pass on the actual macOS ARM PR package from
`6e79b3dd`: nine recommended-setup hook controls, MCP-only, and retained/fresh
host reload. The exact package executable SHA-256 is
`4583b1b18043f89a4fd4e642f4f0e5f645e3bd5ecb1a2bff1af7d46e0877167c`.
All 35 owned-child cleanup records pass, all input pins remain unchanged and
every isolated fixture root is removed. Independent review reproduces those
results from the original reports and exact archive/source bindings.

Both existing-host turns missed the newly published hook; the fresh host
observed it and blocked. Setup therefore continues to require a fresh host.
The qualification summary SHA-256 is
`6fc5a1f5ed9b8adbd116ecc9defdd38c89d0723b0c52bf61614f0360f8bc5821`.
See the [tuple and package record](claude-native-evidence.md#actual-6e79b3dd-pr-package).
This does not qualify numeric binary replacement or official publication.

## September 28: 6e79b3dd platform results and PowerShell correction

The [release workflow](https://github.com/sheeki03/tirith/actions/runs/36378009327),
[native ARM workflow](https://github.com/sheeki03/tirith/actions/runs/36378009053),
[fuzz workflow](https://github.com/sheeki03/tirith/actions/runs/36378009093) and
[benchmark workflow](https://github.com/sheeki03/tirith/actions/runs/36378009149)
pass on `6e79b3dd`. All six release target builds pass; publishing remains
skipped. The [CI run](https://github.com/sheeki03/tirith/actions/runs/36378009061)
passes macOS, Rust 1.83, strict Clippy and the ordinary Linux/Windows workspace
tests, but fails the new native PowerShell target step on Linux and Windows.

The retained Windows reports identify the forbidden explicit child working
directory in the test harness. The correction uses the trusted-child runner's
existing Windows directory selection. The Linux reports identify a writable
ancestor of the preinstalled PowerShell runtime. The Unix driver can now copy
the observed runtime into a fresh private directory in the current user's home,
verify its bounded file inventory, and query through that copy. The installed
runtime is not modified. Both changes preserve the production trust checks.

Seven driver controls pass, including refusing escaping links, special files,
oversized inventories and cleanup of a replaced or changed staging directory.
A real macOS PowerShell runtime copy preserves all 614 entries and 201,084,070
file bytes, then confirms owned cleanup with the original inventory unchanged.
Its receipt SHA-256 is
`70d99007c56e1fc471e693cf763351b090e88078c8f4d1b9c8571880f4ee2921`.
Independent review, formatting and workflow validation pass. Corrected native
Linux/Windows execution remains pending; the previous failed run is retained.

The corrected staging route also passes both native macOS PowerShell cases
using the newly compiled CLI test image
`c3aa0df7bc1b7685045916e1c3d8ab9a93229a1f3af3dfe225bec55949dbce77`.
Default and private XDG profiles remain unchanged, both owned test processes
complete with verified cleanup, and the staged runtime is removed after its
source/copy inventory checks. Report SHA-256:
`5470aa16d479677c9cb3b30e92d37a662146e32ad38d3a25c5e1f0f6266f11cf`.

Both canonical GNU and musl ARM archives from the same release run also pass
all sixteen native cases as UID 65534, including parent/guard interruption and
process-tree cleanup. The authenticated reports identify GNU executable
`45ea294fe3f57e73bfb6d26188f43a84d9b0261be313b00133f7c5ce1d4b183f`
and musl executable
`994a7497f2506e60b8f17eac542913d960cc3960d405fbce92288aab2428882b`.
Independent review rechecks all twelve ordinary-case predicate sets and four
cancellation records per target. This is the shared containment contract;
the integrated npm transaction requires separate qualification.

## September 28: ordinary CI resource gate on 6e79b3dd

The first ordinary PR resource gate passes in
[run 36378009149, attempt 1](https://github.com/sheeki03/tirith/actions/runs/36378009149).
Its actual measured checkout is `dfcd8ec5003fd7c09b9a452b3b25014908e3d307`,
whose tree `a7bb69f2c398cac2941ea575d09947e6e6ac5132` matches product commit
`6e79b3ddda1e9d266f144c3b4bffdcaa7f2742b7`. Source observations before and after
match. Admission and confirmation agree on the reviewed macOS ARM cohort,
Rust/Cargo 1.98.1, Python runtime, unchanged measurement tools and budget.

Independent recomputation from the retained raw samples reproduces all six
maxima, and rerunning the unchanged budget checker produces the identical
result. The owned dashboard service exits with every cleanup check satisfied.

| Measured workload | Maximum bytes | Ceiling bytes | Samples |
| --- | ---: | ---: | ---: |
| Clean analysis allocations | 48,307,398 | 67,108,864 | 100 |
| Subsequent clean analysis allocations | 120,397 | 131,072 | 99 |
| URL pipeline allocations | 72,060,053 | 100,663,296 | 100 |
| Subsequent URL pipeline allocations | 1,670,451 | 2,097,152 | 99 |
| Recent history allocations | 8,692,440 | 12,582,912 | 100 |
| Ordinary check peak RSS | 43,974,656 | 50,331,648 | 100 |

The authenticated artifact ZIP SHA-256 is
`7413911daad1c900f6334b42a10afb4871e97f48434fc797767deb739cba4676`;
the independent review is
`256eda8b272edb94922aed8e6103428eeb870e42f1d6b671185748a3fcecc426`.
The measured executable is
`1cc6abed10e6dbaf300f737154775d4082bc4ba3829cf5e318a8a5c8e5d81dba`.
This closes the pending ordinary-CI enforcement check for the six reviewed byte
limits. It does not establish a universal latency budget or qualify unrelated
host workloads. The separate Performance job also passes in that run.

## September 28: integrated hook and native qualification candidate

The complete local `cargo test --workspace --locked` run passes: 2,119 primary
CLI tests with five ignored, 6,174 primary core tests with two ignored, and all
integration suites and doctests. Its log SHA-256 is
`d5c53db5e5db630e2554599f89c1dce8998fcad3bc3b9f4b833be3431dbf3354`.
The first attempt exposed a nonblocking socket acceptance race in a test and
a bounded global setup-lock refusal during concurrent native setup work. The
socket test now retries acceptance within a fixed deadline; the production
lock deadline is unchanged. The successful full rerun followed completion of
the concurrent setup work.

Strict workspace/all-target Clippy passes. Four focused portable npm
qualification tests and strict CLI test-target Clippy also pass after the
final script-archive fixture addition. Formatting and workflow checks pass.
Independent review found no remaining actionable defects in the native npm
packet after its launcher was moved into an owned, verified temporary root.
Its four coordinator cases and two script-suppression controls still require
native ARM execution; a portable pass is not attributed to those native rows.

G0/G2 source review found no remaining code defects in its scoped acceptance
contracts. Documentation now distinguishes captured npm archive inspection
from execution, and npm/Python comparisons from npm installation. Final
integrated platform checks, including native Windows PowerShell 5.1 and 7,
remain required before closing those acceptance rows.

## September 28: hook telemetry lifecycle and current Claude tuple

Native testing of exact Claude 2.1.283 found an ordinary background telemetry
writer that could recreate state after hook completion. All nine related hook
templates now wait for optional logging and stop overdue children with bounded
cleanup attempts. A separate review caught Pi warning telemetry consuming part
of the checker's allowance; it now runs after the protection decision. The
original ten-second checker timeout remains unchanged. Eight focused controls
pass independently, including real-child reap/late-write tests and decision
invariance. An actual 9.85-second Pi checker permits the same command with both
quick and stalled telemetry. These checks do not certify unrelated native hosts.

The corrected retained development binary
`6c17baad668e8d5dfef50040eba9d1fc690cf2bef117cc2c39df781b263ef45d`
passes all nine native combined-setup controls, the MCP-only boundary and the
retained-host reload route, each once. All tuple input pins and successful
fixture-root cleanup checks pass independent rehashing. Immediate hot reload
is not guaranteed: the first retained-host turn omitted the hook, while a later
retained turn and a fresh host observed blocking. The initial cleanup failure
and the older PR package's correct exact-version refusal remain retained.
See the [complete tuple record](claude-native-evidence.md#claude-code-21283-checkpoint-september-28-2026).

The native build contains 659 source files with content digest
`97cf7e2a11a5dfa2b6e086b902ab0b04cade06e21983add0a82f502dbe81265c`.
Later changes to two TypeScript templates and one HTTP test are separately
reviewed and tested; they are not attributed to that native binary. The native
summary digest is
`18761e30a9c7e3e169768f33307688b54fe34d403aa59183db2f428e9e30da84`.
Final PR-package native checks remain distinct from this development record.

## September 28: native PowerShell target checks

The next integration candidate adds an explicit native profile-resolution test.
It invokes PowerShell without loading profiles, compares the observed
`$PROFILE.CurrentUserCurrentHost` with the shared resolver, and preserves
before/after profile contents and metadata. On Windows it also compares the
actual Documents location with the known-folder API. This verifies target
selection, not an automatic hook adapter or observed command blocking.

Both native macOS ARM PowerShell 7.6.6 cases pass: the current operator's default
profile and a child-only private XDG location. Neither profile changes; the
owned child completes with confirmed cleanup. All 578 runtime files match
before and after. Seven focused Rust checks, three Python driver controls,
strict CLI Clippy, workflow validation and Windows controller parsing pass.
Native Windows PowerShell 5.1 and 7 execution remains pending ordinary CI;
the workflow requires both and refuses missing runtimes instead of treating
absence as a successful test.

The official archive SHA-256 is
`6df833d094ebac1c1a74340d7b3437f4aaf5e03ce640484a1c4359f3ce8b3db1`;
the native executable is
`86966ef5e53763c0d7cac9981b9b36c30245185dc347ca69ddfb815c665bf515`.
The captured CLI test executable is
`a1ac7ce90f15b5085cba65b78850176fc532952260011210be7a2ec745740d47`.
The source snapshots, retained logs and native reports were independently
rehashed against review receipt
`0cd199a7d09e8f24490ea2bc402668ef728e7caa36c1390b64c3826bf7bdc7ac`.
These results apply to the retained development inputs; the combined commit
and platform CI will supply their own revision identities.

## September 28: combined source e282d038

The combined candidate is `e282d038519848caa8328cf32aa05a05daa502d2`, tree
`71c7f346aefa9de9044c3b358252ab0cfc03dae1`. Version remains 0.4.2.
All five original attempt-1 workflows pass:
[CI](https://github.com/sheeki03/tirith/actions/runs/36333438640),
[Release](https://github.com/sheeki03/tirith/actions/runs/36333439005),
[native ARM containment](https://github.com/sheeki03/tirith/actions/runs/36333438682),
[Fuzz](https://github.com/sheeki03/tirith/actions/runs/36333438583), and
[Benchmarks](https://github.com/sheeki03/tirith/actions/runs/36333438646).
Publication steps are intentionally skipped on the PR. The actual PR checkout
is merge `e82324e9132238f063b3a3b50fdaa2f60c431a23`; its API-recorded tree equals
the candidate tree. Artifact claims below use that actual checkout identity.

The corrected complete local `cargo test --workspace --locked` run exits zero.
Its primary CLI harness passes 2,114 tests with four ignored; its primary core
harness passes 6,174 with two ignored. Integration suites and doctests pass.
Nested subprocess summaries are not added again to these primary counts.
Log SHA-256:
`cbdc4f078edd9bf2d0df2a2c2ba7ce79c9a6cb9393d64466ee39150fd4440486`.
Strict workspace/all-target Clippy also passes. The earlier incomplete run and
unchanged frozen-reader fixture remain recorded below.

Current development binary
`d57b2fe07410182708f6b20e86ec5ad9127e3ac41478275f28ae62d959e74893`
passes 32 paired released-0.4.2 compatibility cases, six signed/unsigned
mixed-audit cases, and fourteen durable process-death/storage cases. The latter
observe each requested stopped boundary and include actual permission and file
size-limit failures. Every owned command's process/pipe cleanup and retained
input hashes pass. These observations do not certify power-loss behavior,
a physically full filesystem, or Windows signed replacement.

The Windows CI artifact passes all 60 harnesses; primary totals are 8,357 passed,
zero failed and three ignored. Build, doctests and native Job cleanup pass.
Separately, all nine dashboard cases pass under the created standard account:
medium integrity, no elevated token and no Administrators membership. The
ordinary workspace harness is not described as running under that account.
ZIP SHA-256:
`8852810fa64dabfbe11639cc2e1b6096b8d4423898f5c858bdde915e6105f7b6`.
The PowerShell jobs pass in CI; their larger artifacts were not independently
inspected for this record.

Both canonical GNU and musl ARM64 release archives pass all sixteen native
containment cases, including four cancellation/cleanup cases, as UID 65534.
The separate native-ARM workflow's two archives also pass sixteen cases each.
These are distinct binaries and archive hashes, all tied to the recorded merge
checkout; none is an npm private-input execution qualification. Release builds,
Debian/RPM package jobs, GNU compatibility matrices and npm assembly pass.
The retained Debian package is `0.4.2-1`, with only `ca-certificates` in Depends
and no sudo dependency or suggestion. RPM CI verifies the same absence across
its dependency classes. No official release was published.

The actual macOS ARM PR archive has SHA-256
`7f4050802588d855671e5f75c0fa9678adb2763efe5ba0619a0293dd20191714`;
its executable has SHA-256
`076d6d457a42c76bb6227e7aeadd1a0bdb369020de6c4e6c3b9fa0af308368dc`.
It passes three fresh default-MONITOR Zsh activation sessions and all three
removal cases: recommended removal/fresh-shell behavior, manual startup
preservation, and edited/malformed-block handling. No product case was retried;
all owned process/session/PTY cleanup and input postchecks pass. Provenance is
bound through CI/API and matching Git trees, not an embedded Git attestation.
The retained summary SHA-256 is
`bb8865dd5fae9f08d79a338928e47675d3fcd1f4580c35533953bbd863990d84`.

The same packaged executable passes 32 native Bash/Zsh/Fish cases using its own
materialized hook assets: 19 on Bash 5.3.15, six on Apple Zsh 5.9, and seven on
Fish 4.8.1. All twelve owned commands and 33 original PTY groups/sessions finish
with observed EOF; the disposable fixture is removed. Report SHA-256:
`0d5948b671bea982e4acbc6c6fbfdc2919a62ff7bef8b9e3f3047c5e7998b07a`.
These cases do not establish escaped-session or arbitrary descendant cleanup.

The package's embedded browser assets also pass all 24 full journeys and eight
response-order/ownership cases, each once, with zero browser errors. Candidate,
package, harness, runtime and 657 source-file identities match before and after.
Both owned services and three CLI commands exit zero with original group/EOF
cleanup; successful service fixtures are removed. Wide/narrow screenshots were
inspected. Playwright closes its private browser context, but the harness does
not claim full browser process-tree observation. Summary SHA-256:
`ca3272e0049342bea54664fc0a466b46776ee9d773393c01d3dfe808afed741f`.

Android API-24 check and link pass on the same 657-file compiler-input closure,
using Rust 1.98.0 and official NDK r30/Clang 21. The resulting AArch64 PIE uses
`/system/bin/linker64`, and the tool/sysroot/dependency identities match before
and after. This is an opt-level-zero development build, not Android runtime
qualification. No Android device, Termux execution, SELinux behavior or shell
hooks were tested. ELF SHA-256:
`971978b3ee77590298a32de684faf16302c14e52c38ffefbc909ee2b6b789b63`.

Three original native macOS resource baselines on exact `e282d038` pass independent
artifact, source/build and raw-sample verification. Allocation spreads are zero;
ordinary-check RSS maxima range from 43,646,976 to 43,974,656 bytes. Compared with
the historical cohort, URL requested-byte maxima increase by 72 bytes; other
allocation maxima are unchanged. All six original control/growth pairs now pass:
each control satisfies all six ceilings, and each growth variant exceeds only
its selected ceiling. Independent review rehashes all six original archives and
246 extracted files, then recomputes the six metrics and raw paired deltas. All
100 RSS growth samples exceed its ceiling. The completed review SHA-256 is
`0d38e2c773621ef39a13fc452d213f8b68c3a1bd2ba268b937aa805daac53207`.

The [native resource reference](resource-reference/native-e282d038-v1/README.md)
records the actual run/artifact identities, thresholds and activation decision.
Ordinary PR CI now has a native job that checks cohort/build/runtime/tool
compatibility, measures its own event source, confirms the retained facts after
collection, and enforces those six byte ceilings. Nine admission controls, fifteen
collector controls and 36 checker controls pass, as does workflow validation.
Its first ordinary CI execution remains pending the integration commit; the
six detector results do not substitute for that result.

The local native ARM v17 follow-up passes core typechecking, then reaches its
5 GiB cgroup cap while compiling the core test executable: one OOM and one OOM
kill, with peak exactly 5,368,709,120 bytes. No selected core tests, signed-v1
refusal or Clippy ran in that attempt. All owned commands clean up and the exact
container is removed. A separate bounded isolated ARM CI run,
[36338702048](https://github.com/sheeki03/tirith/actions/runs/36338702048), measures
exact product `e282d038` through controller `27c327838680d0123b2e5f61ef7f14b1cb59d043`.
It passes native core typechecking, the nested-policy regression, all 68 npm
core tests and the genuine production-signed-v1 refusal test. Its only failure
is an absent Clippy component in the pinned compiler image; the lint command
does not run and no native lint pass is claimed. Peak cgroup memory is
5,860,294,656 bytes under its 10 GiB cap, with zero max/OOM/OOM-kill events.
All 657 source files, ten build/test logs, feed bytes and 91 owned-child cleanup
records pass independent verification. The exact container is removed and the
final inputs match. Artifact ZIP SHA-256:
`c7cecc7b844059da8b0dad57fbedc3b3004582d253107c1695b1e44af1e8878a`;
report SHA-256:
`72a6551af65251a9bab51680e8b3eea48632e37ad69c0fc898c85f39982d7a33`.

These results close the recorded combined-source regressions and add native
package evidence. They do not close all release gates: official channel and
upgrade certification, the consented beginner pilot, selected wider native
journeys, genuine signed-v2 npm prerequisites and integrated npm execution
qualification remain separate outstanding work.

## September 28: combined controls and remaining native checks

The combined browser candidate
`d57b2fe07410182708f6b20e86ec5ad9127e3ac41478275f28ae62d959e74893`
passes all 24 recorded full-journey checks and eight response-order/ownership
checks. Both runs use the embedded assets, report no browser errors, retain
unchanged binary/harness identities and verify owned-service cleanup. The
large-policy journey exercises 3,600-rule compound omission and 5,500-rule
inventory omission through the actual service. Wide and narrow layouts remain
usable; the corrected socket delivers the complete response.

Complete-crate HTTP tests pass all five cases. The initial workspace run passes
2,112 main CLI tests (four ignored) and subsequent integration selections, then
stops at the frozen reader test because default local-only policy JSON acquired
a new field. The product correction preserves that legacy shape; the fixture is
unchanged. Explicit runtime CLI output and browser reads retain the new controls.
All four frozen-reader groups and nine profile lifecycle cases then pass, as do
strict workspace/all-target Clippy and the combined build. A new complete
workspace/platform run remains required; the earlier interrupted run is not a
complete pass.

Native ARM capture v16 passes combined typechecking and seven CLI selections:
7 descriptor, 1 completion-binding, 18 checkpoint, 1 unwind, 20 intent/recovery,
16 materialization and 8 output-privacy tests. It then receives SIGKILL while
compiling the core test executable. One OOM kill is observed, with peak cgroup
memory 5,353,238,528 bytes under the configured 5,368,709,120-byte cap. The
`max` and `oom` counters remain zero, so the record does not attribute the event
to that cap specifically. Core policy/npm execution, actual signed-v1 refusal
and native Clippy were not reached. All 105 owned command records have verified
cleanup; the exact container is removed, and all 657 frozen inputs and 20 result
logs rehash successfully. Report SHA-256:
`4e4858cb28c778c3a42b2cbb22b6d71149c5e4ae34fb7df656e158e03a3dbdd5`.
These results apply to v16, before the later HTTP and local-only display fixes.
Remaining native checks are being separated to reduce accumulated compiler
artifacts; unrelated host containers are not modified.

## September 27: resumed field readback and issue verification

The final field-control review catches an unbounded duplicate of compound
approval rules and a total response-budget regression. Compound summaries now
omit values above 16 KiB explicitly. If the complete browser response, including
diagnostics, still exceeds 512 KiB, only the optional field inventory is omitted;
legacy policy/provenance remains intact, missing controls stay unavailable, and
precise profile previews remain usable. Seven field-control tests and the
aggregate-budget regression pass, followed by strict workspace/all-target Clippy
and a combined build. The new browser fixture uses actual organization policies
with 3,600 and 5,500 approval rules. The first combined-source browser run
passes the compound display case, then finds a truncated 5,500-rule response on
macOS: the accepted socket inherits nonblocking mode and a filled send buffer
terminates the write. The failure and successful owned-service cleanup are
retained. Six delayed-response cases separately pass on the same binary
`b6dfd9c6be03b868d5092709decdf3af409491f3e9ecbed16b44e250fe7146a3`.
The blocking-socket correction preserves both three-second production deadlines.
A standalone native harness using the exact transport module fails two cases
before the correction and passes all five afterward, including a 4 KiB send
buffer, delayed reader, complete 512 KiB response and partial-request 408s.
That harness stubs the unrelated authentication sibling; complete-crate and
browser checks remain separate. Independent source review finds no further
product defect. The optional menu also passes an actual PTY category/back/quit smoke
check with exit zero; that smoke does not execute the selected inspection commands.
(Historical: the terminal menu was later removed.)


The September 22 follow-up's strict workspace/all-target Clippy and development
build both finish successfully. The corrected POSIX npm metadata test also
passes on macOS. These local results do not establish the Windows regression
fix; a new Windows CI run remains required.

The retained v13 native ARM check passes combined test typechecking and five
focused groups (7, 1, 18, 1 and 20 passing tests). The materialization group then
reports 14 passed and two failed: the previously identified test helper reads
the wrong state root. The driver stops there, so later privacy, core, signed-v1
refusal and Clippy selections were not attempted. All 90 owned Docker command
records have clean termination; exact container removal and absence, plus final
source/tool hashes, are verified. Peak cgroup memory is 4,941,623,296 bytes under
the 5 GiB cap, with zero `max`, `oom` and `oom_kill` events. Retained report SHA:
`9051f34648979730f34f46ab0514436bcb70b37c6bc06aed1aacd976b080369d`.

Final source review finds that approval rules and Strict's action overrides
appear in profile previews but are absent from the field-level effective
readback inventory. The inventory now includes every current profile definition
field, and the browser displays unavailable fields explicitly rather than
silently omitting them. All six field-control unit tests and nine profile
lifecycle tests pass. The complete browser journey passes 23 recorded checks
on debug binary
`051aef692e193515b1b27d114e8559eb1f111ae83a2a13ddf61d2ef417fad151`.
This includes every profile field's readback, managed-control refusal,
repository constraints, redacted paths, apply/undo and narrow layout. The first
actual browser attempt finds narrow-screen overflow; responsive field rows and
path wrapping correct it, and wide/narrow screenshots are inspected. Six
delayed-response cases separately pass on the preceding binary
`930a52598c19eb1c981c2fbebc4428c31cf897fc763db748113ff2e735a1ceef`,
including late apply readback after undo. Both runs verify owned service cleanup.
These binaries precede the two subsequently integrated issue fixes below.

Issue #265 is fixed by applying the private capture mask in the existing pinned
shell child. A save/restore implementation first fails a real fish Ctrl-C probe;
the child implementation preserves both incoming `027` and `777` in fish and
its next child. All 153 native privacy/permission cases pass on fish 4.8.1,
Bash 3.2/5.3.15 and Zsh 5.9, covering startup, command and paste paths, failed
helpers and ordinary child file/directory modes. Capture files remain `0600`.
These fixtures use inert command endpoints; they do not establish interception
or receipt authority. Source and embedded hook copies match.

Issue #266 uses one discovery predicate for resolution and snapshot rechecks.
Directory-shaped lookups need bounded listing evidence; permission errors,
inconclusive listings and genuine invalid policies remain conservative. Case,
Unicode and ignorable-character aliases are retained. Windows keeps its prior
directory behavior because enumeration cannot disprove arbitrary NTFS 8.3
alternate names. All 405 policy-selected core tests pass, including 15 new
discovery, alias, revalidation and failure cases; the integrated four source
files match the tested scratch bytes except a subsequent octal spelling fix
required by Clippy in a test permission literal. Test log SHA-256:
`fba0cd3804aedd4cdc22707873587f28a18d7315ccaba17c26a0d81a0875cffa`.
Independent review finds no remaining blocking defect in this Unix fix.
The virtual-stat seam models kio-fuse; a native KDE mount was not available.

The refreshed September 27 published feed has digest
`47b867e2b686ce68d38402622fcd27fc54854115743b860a8bc1799c8db48112`.
Its embedded signature and manifest signature verify against the production
key, but it remains format 1. The release lists no format-2 asset or index.
This separate signature check does not claim execution of the Rust parser;
that negative admission test remains part of the next native run.

## September 22: integrated checks and policy-control follow-up

The complete local macOS workspace at `2cde4cee` passes. Its main CLI harness
reports 2,095 passed and four ignored tests; core reports 6,159 passed and two
ignored. All other harness results also pass. Retained log SHA-256:
`8e5d9446cb33552e2d685aa9534b2dbca11e4de138cfe5ab2d7dc1c73d1bc485`.
These results precede the later policy controls, terminal menu and Linux unwind
follow-up; they do not qualify those changes.

The same pushed commit passes release-build workflow 35696913620, native ARM
containment 35696913329, fuzz 35696913341 and benchmarks 35696913327.
[CI 35696913332](https://github.com/sheeki03/tirith/actions/runs/35696913332)
passes macOS, Bash 5.3, installer and workflow checks but fails Clippy and the
Linux, Windows and Rust 1.83 workspace jobs. Three lint corrections are prepared.
Both Linux variants fail two legacy materialization tests whose byte-comparison
helper reads the setup-lock root instead of XDG state. Windows fails a pure npm
metadata test because a native path join inserts backslashes into a POSIX lock
key. Corrections retain both tests and their original assertions. The nine
Windows standard-account dashboard cases and their cleanup pass; the workspace
failure skips subsequent PowerShell qualification. New CI remains required.

The native integrated ARM v11 attempt ends with SIGKILL during the combined test
typecheck. No historical memory counters were retained, so the cause is unknown.
The v12 attempt passes the combined typecheck, then encounters a host log-name
collision after the first test command returns zero. Its actual test output was
not retained, so no test count is accepted. Cgroup `max`, `oom` and `oom_kill`
counters remain zero. Both attempts preserve failures and pass owned-command
cleanup, exact container removal and input posthash checks. The corrected driver
uses distinct command-transcript and test-result names and records invocation,
completion and retained output separately. These checks do not authorize npm
execution or replace the required signed format-2 threat feed.

The follow-up adds shared per-field policy authority and current source displays,
explicit managed personal controls, and effective readback after browser apply
and undo. Repository constraints remain distinct from organization/remote
replacement. An optional `tirith menu` routes to existing typed inspections and
previews (historical: the menu was later removed). Seven menu tests, two human status-path privacy tests and all nine
profile lifecycle tests pass locally. The latter includes CLI projection parity
and read-only previews. At that checkpoint browser journeys and final lint/build checks were pending;
the September 27 results above supersede that status without closing final WP14
release acceptance.

## September 22: earlier CI and integrated npm review route

Commit `87c0fdeecdbaf4c1bc3df6533b83b947e7e88819` passes
[CI 35587858181](https://github.com/sheeki03/tirith/actions/runs/35587858181),
including Linux, macOS, Windows, Rust 1.83, Clippy and Bash 5.3. This resolves
the preceding receipt-reader fixture and oversized Linux test-image failures.
The same commit passes release build checks (35587858552), native ARM containment
(35587858374), fuzzing (35587858283) and benchmarks (35587858180). All six release
target builds and npm, Debian and RPM package checks pass. Publication jobs are
skipped: this is PR validation, not a published release or final cycle evidence.

The subsequent working tree registers the separate `pkg install-npm` review,
apply, status, undo and recovery command group, descriptor-based launch adapter
and transaction coordinator. Execution remains unqualified and disabled. Local
checks pass 45 core npm tests, seven release compatibility tests, eleven stored
format inventory tests and thirteen npm-selected CLI tests. The latter selection
includes command grammar and existing package metadata tests; it does not run
the Linux-only intent tests on macOS.
(Historical: the local-leaf npm routes `pkg install-npm` and `pkg materialize` were
later retired before release; see the archive tags.)

The auditable bootstrap sources regenerate the exact previously reviewed
`41183108651b825e4712922f9056d1caf5766814f992167ac36fd200d9daa4d7`
bundle. Seven generator controls, 51 binding/configuration/runtime-pack controls,
37 descriptor parser controls and 35 synthetic resolver controls pass. These are
source controls, not installation or native containment evidence.

A separate native ARM Linux kernel probe passes all three execute-only inode
cases. Its shared-inode negative control becomes readable when a same-user peer
changes the parent's inode permissions. The corrected child-private inode stays
execute-only and nondumpable; executable/memory reads are denied both with and
without TRACEEXEC/detach. Owned process and container cleanup and input posthashes
pass. Report digest:
`ff3f92e8655f86bbf7fc1a05df3245359d8908ee564fdd311a2ad2d1cc90e4c9`.
This harmless ELF probe does not execute Tirith or npm.

The integrated v7 ARM Cargo check fails because the captured source omits two
root test fixtures required by `include_bytes!` and `include_str!`. Its source
manifest digest is
`5d12b798eaabb0ee39aa264ed104674429656ebaab18b77ae2294fbc0d61366d`.
All owned command cleanup and container removal checks pass, and captured inputs
remain unchanged. The failed check is retained; it is not a successful typecheck
or native execution result. The corrected v8 capture reaches actual compiler
errors in the descriptor adapter and coordinator; those errors are corrected.
The subsequent v9 capture reaches only new fixture compilation errors, also
corrected. The v10 check then catches a test-only call to a private core method.
The fixture now recaptures through the public preparation API and compares the
whole private plan digest without widening core visibility. No failed attempt
is a passing integrated check. Their owned
commands, container removal and input posthash checks pass.

The working tree now includes complete-only signed recovery milestones. A native
completion witness is required to issue the private milestone; publication adds
a linked committed milestone. Recovery freshly checks signed records, receipt
contents, policy, artifacts, threat data, task authority and the whole current
tree. Private or ambiguous interrupted state is preserved without replay or
recursive deletion. Fresh macOS checks pass seven compatibility and twelve store
inventory cases; nine publisher and seventeen source-capture controls pass.
These do not run Linux-only recovery or checkpoint-interruption tests.

The retained public ThreatDB artifact is production-signed but format 1, digest
`9e0e55905f3898e95805e35f44ee0287adf749a25e38805f2c3c36c06c9577f1`.
It cannot meet installation's format-2 artifact-hash requirement. The ignored
native fixtures use the real parser/signature admission path and cannot replace
it with a test signing key. Positive integrated execution remains unqualified.

The latest review binds every private npm intent field except the recursive
review digest, with a private random nonce that is excluded from output. Local
materialization advances its review envelope to schema 2. Schema 1 remains
readable, but apply, undo, recover and continued undo refuse before writes.
Checkpoint and materialization-summary schemas remain unchanged. The publisher
passes ten compatibility cases and the capture helper passes seventeen controls.
Fresh independent source review found no further review-binding, migration or
output-projection defects. A separate native authority review found no further
defects in completion, publication ordering, signed recovery or the Linux
architecture gates. These are source reviews; Linux mutation regressions and
the full current workspace suite are still being run. The current macOS
release-compatibility selection passes all seven cases.

### Native resource detector qualification

All six native control/growth pairs qualify the reviewed byte detectors on
historical product source `415565d307c39e7000255955150185f3287581a6`.
Controller `d766f9015a7a8be5e5f3f1b45c56422b514f31b1` uses the reviewed
Apple M1 (Virtual), macOS 15 ARM cohort. Each pair runs on one runner boot.
Every control passes all ceilings; every growth exceeds exactly its selected
ceiling. Artifact ZIP hashes, all 246 extracted files and the actual raw-pair
evaluations were independently rechecked. No automatic retry was used.

| Detector | Run | Control bytes | Growth bytes | Ceiling bytes |
| --- | --- | ---: | ---: | ---: |
| Clean first request | [35692411130](https://github.com/sheeki03/tirith/actions/runs/35692411130) | 48,307,398 | 81,861,830 | 67,108,864 |
| Clean subsequent requests | [35692414572](https://github.com/sheeki03/tirith/actions/runs/35692414572) | 120,397 | 153,165 | 131,072 |
| URL first request | [35692418226](https://github.com/sheeki03/tirith/actions/runs/35692418226) | 72,060,260 | 105,614,692 | 100,663,296 |
| URL subsequent requests | [35692422222](https://github.com/sheeki03/tirith/actions/runs/35692422222) | 1,670,663 | 2,194,951 | 2,097,152 |
| History requests | [35692425496](https://github.com/sheeki03/tirith/actions/runs/35692425496) | 8,692,440 | 12,886,744 | 12,582,912 |
| Ordinary check RSS | [35692430194](https://github.com/sheeki03/tirith/actions/runs/35692430194) | 43,630,592 | 61,538,304 | 50,331,648 |

All five allocation experiments show their exact injected byte dose in every
selected sample. The RSS paired median increase is 17,285,120 bytes; all one
hundred growth measurements exceed the RSS ceiling. Combined retained report
SHA-256: `0e76a8d573f7cd3f323f110e82f7216052fe9f228326aec354c97acee12055af`.
This result does not qualify the later product source or enable CI budgets.
Three final-source baselines, final detector/source compatibility review and
broader host measurements remain. Earlier CPU-mismatch refusals stay retained.


## September 21 follow-up: test failures and npm descriptor compatibility

At `094c72a9862fc0b44858b4ffda5ad59457451b5b`, release workflow
35580008125, native ARM 35580007924, fuzz 35580007914 and benchmarks
35580007911 pass. CI 35580007926 fails independently of those results:

- The release compatibility test assumes schema 1 for every stored surface,
  although shell execution receipts correctly declare readers 3 and 4. The
  correction tests every declared reader and explicit unsupported/unknown states,
  while independently asserting receipt readers `[3, 4]`.
- Linux's actual CLI test executable is 548,346,312 bytes, above the production
  536,870,912-byte identity bound. Six setup tests refuse it. Test jobs now select
  line-table debug information; the production bound is unchanged. A fresh Linux
  build and execution are still needed to confirm the correction.
- The Windows artifact digest
  `e09c48ec0dedb8b8b69499877e5332ec72a266aa8797aa4e43f1b37f8dd28e0a`
  verifies. Fifty-nine of sixty harnesses pass; the one failing CLI harness has
  only the stale receipt fixture failure. Primary totals are 8,322 passed, one
  failed and three ignored. Nine dashboard cases pass with a verified standard
  account token; this does not classify the other harnesses as standard-account
  runs or certify an interactive PowerShell integration.

The updated doctor passes 67 focused tests plus the integration case for absent
shell exports. All eight profile tests and six release compatibility tests pass.
Forty-four npm preparation/layout tests pass locally, including exact descriptor
mapping and path-free public summaries. Strict workspace/all-target Clippy and
formatting pass. These source tests do not qualify npm execution.

The embedded dashboard passes the complete browser run on local debug binary
`a261c2c124d20497c39872b6b2db3f21246ced7b8897fd653963f33ab1465f0b`.
The 21 recorded checks include explicit Claude selection reaching the real
backend, unavailable-host refusal with unchanged configuration, combined setup
and undo, all six pages, history, policy, exceptions and narrow layout. Wide and
narrow screenshots were inspected. Report digest:
`fe2bd31d1d617f54e21fbfa77ea88c8b3b74a60a09da2cf18841837d92e173ef`.
Candidate/harness/helper hashes match before and after, with owned control-service
and CLI cleanup observed. Browser process-tree cleanup was not independently
proved, and this debug result does not certify final release bytes.

The fixed Node 26.7.0/npm 11.19.0 bootstrap
`41183108651b825e4712922f9056d1caf5766814f992167ac36fd200d9daa4d7`
now passes native ARM Linux compatibility probes with both an empty target and
an independently planted hostile project `.npmrc`. Actual stock npm receives
retained descriptor inputs. Its exact project configuration read returns the
bound empty configuration, without reading or adopting the hostile file. Installed
leaf bytes and the complete hidden lock match independently derived expectations.
Arborist keys the package by the physical target relative to the FD prefix;
artifact sources remain relative to the actual artifact descriptor. The core
verifier already models this distinction. Earlier fixture-only key mismatches
remain retained as failures.

Clean report digest:
`78f04503cea64f324ed44da79a505dedf72aa7c314f8c63fc62eddc069cba177`.
Hostile report digest:
`469f62267cb19f9a1bf056fa5c2342ef372ab2f4dddfce600f2bf18902fd9eb4`.
Both runs observe ordinary child exit, same-user peer memory/runtime-FD denial,
owned command cleanup, exact container removal and input postchecks. These probes
exercise stock npm compatibility under the fixture boundary; they do not execute
the product native containment or output verifier. The hostile file remains and
must cause the product's independent output verifier to refuse publication.
Full native launch, transaction, publication and recovery qualification remain.

## Packaged shell and receipt-capacity verification (2026-09-21)

The retained macOS ARM release product from `094c72a9`, SHA-256
`862ef1c5784c691cd6611c9bb5be2afd63c46d5275a32bc3d1c93e1d7e70144b`,
passes the serial fixture-key signed replacement/rollback check and all **32
packaged shell cases**: nineteen Bash, six Zsh and seven Fish. All 33 owned
PTY sessions reach actual EOF, native original-group/session exit and leader
reaping; the twelve outer commands also pass every cleanup check. The shell
harness has separate captured build/source identity. This is local archive
qualification, not an official published release or arbitrary escaped-tree proof.

The unchanged full terminal workload then passes **600 measured submissions
plus six warmups** across one-terminal and two-terminal scenarios. Every allowed
marker appears exactly once and every blocked `curl_pipe_shell` body remains
unexecuted. The shared two-terminal scenario completes 404 framed operations,
plus setup traffic, beyond the old 256-receipt lifecycle failure. It does not
measure peak registry occupancy or cross the separate per-session ledger limit;
the core burst and clean/warning boundary regressions cover that limit.
Both commands are dispatched before response pumping. All 200 measured paired
rounds have positive overlapping outstanding-request intervals, ranging from
263.163167 to 883.545708 ms. These are two real retained Zsh sessions; the
observations do not establish simultaneous CPU execution. A September 28
readback confirms this existing coverage, correcting a later working inventory
that incorrectly described the driver as serially interleaved.

Whole-terminal wall-clock p50/p95 in milliseconds on this Apple M4/macOS 27 host:

| Scenario | Allowed | Blocked |
| --- | --- | --- |
| One terminal | 447.7 / 588.5 | 248.7 / 366.8 |
| Two terminals, first | 586.5 / 689.2 | 332.7 / 394.2 |
| Two terminals, second | 577.8 / 707.4 | 330.3 / 392.6 |

These include terminal scheduling, policy checks and receipt/ACK persistence;
they are not isolated hook CPU times or universal budgets. All three shells
exit normally, every native cleanup check passes, and all 607 captured source
inputs match through the final postcheck. The report digest is
`c7a19f60a2277464edc1e708b7b5702f62b2fa32f8bb6c1c9c21e5c1a5d6a2c2`.
Later doctor, profile-description, dashboard and npm changes require their own
checks; they are not part of this retained product.

## Platform and capacity follow-up (2026-09-21)

At revision `415565d307c39e7000255955150185f3287581a6`, the [Windows
workspace job](https://github.com/sheeki03/tirith/actions/runs/35573060680/job/106248663775)
passes all sixty harnesses. The retained artifacts include successful native
Job ownership, leader observation, output drainage and no-leak checks. Nine
dashboard tests run under a medium-integrity account with no administrator
membership or elevation. Six PowerShell 7.6.5 noninteractive cases also pass;
these do not certify interactive Windows interception or automatic setup.
Both artifact archive digests and the extracted report hashes were verified.

The same revision passes the [native ARM GNU/musl
workflow](https://github.com/sheeki03/tirith/actions/runs/35573060661) and the
[PR release compatibility workflow](https://github.com/sheeki03/tirith/actions/runs/35573060878),
including all six target builds, npm assembly and Linux package runtime checks.
Publication steps remain skipped. The overall CI run still fails Unix PTY
cleanup checks and six Linux setup checks reporting an undifferentiated binary
identity error. The follow-up retains the original process group while draining
the PTY to observed EOF and adds bounded, path-free identity diagnostics plus
CI test-image sizes. The production binary size limit is unchanged; its role in
the Linux failures is still a hypothesis awaiting native evidence.

Three independent macOS ARM resource runs at that revision (35573095026,
35573107325 and 35573122692) pass with the exact Apple M1 (Virtual), three-CPU
cohort and distinct boots. All five allocation counters are identical across
the runs; ordinary-check peak RSS ranges from 42,663,936 to 44,613,632 bytes.
Archive digests, all 63 extracted file hashes, source/toolchain/runtime identity
and cohort agreement were reviewed. Draft thresholds received an independent
review. No regression limit is enabled: actual growth sensitivity and the
final-feature source remain separate requirements.

The retained full terminal timing attempt exposed a product capacity failure:
acknowledged terminal outcomes occupied the receipt registry until expiry.
It remains failed and supplies no admitted timing baseline. Explicit terminal
acknowledgment now distinguishes received answers from lost-response recovery;
active receipts remain schema 3 and acknowledged, non-authorizing outcomes use
schema 4. Acknowledgment may end only its own exact clean shell-boundary
record's retention at the actual acknowledgment time; ordinary pressure cleanup
can later reclaim it. Normal reads retain the observation until existing ledger
or stale-session cleanup; security history retains its original window. This avoids stranding a
warning behind a ledger full of acknowledged clean observations. All ten core
regressions pass, including 264-command bursts, the clean/warning capacity
boundary, authenticated context/seals, lost responses, crash ordering and clock
boundaries. Strict workspace/all-target Clippy passes. Thirty-two selected CLI
framing, deadline, identity and stored-format cases pass on the preceding ACK
test image with all owned cleanup checks. Actual terminal verification on the
newly captured product remains in progress.

The corresponding hook fixtures pass 79 private-environment cases and 192
trace cases across source and embedded Bash, Zsh and Fish hooks, including
Bash 3.2 and 5.3. Observers check exact input frames, success-before-ACK ordering,
unchanged original status when ACK fails, and absence of private capability
values from ordinary children and trace output. Every native process cleanup
check passes; these recording fixtures do not independently prove receipt
authority or final product behavior.

## Integrated native checks (2026-09-21)

The second retained macOS ARM release product, SHA-256
`fa4c656e1322e25665ebabe0ca578d031391d1e81bb7a735583caadc177808fe`,
has 604 captured source inputs and independent before/after build records. Its
same-version fixture-key replacement and rollback passes with the new persisted
format contract, configuration preservation, exact restored bytes and all four
owned outer-process cleanup checks. This remains a test-image/release-product
fixture, with the official-release and lifecycle limits described below.

Three real newly opened Zsh sessions on that product now pass with native job
control enabled (`MONITOR=on`). Each actual recommended setup produces one
completion notice, one allowed marker, no blocked marker, and one observation
from each allow-hook, block-hook and status body. The durable phase is verified;
seeded history is restored, the shell exits naturally with PTY EOF, all four
cleanup observations pass, and the isolated home is removed. The separately
reviewed harmless PTY control observes a foreground job in a different process
group within the original session. This qualifies the retained macOS Zsh tuple,
not other shells, platforms, escaped sessions or later source changes.

All seventeen isolated read-only/dry-run command examples also pass on that
product. The runner checks the exact expected JSON contracts: project coverage
gaps retain exit 2, and tuning without audit history retains exit 1. The first
attempt incorrectly expected zero for those two cases; its failed report is
preserved separately. Binary, helper, runner and relevant source identities are
unchanged, and every command passes all four owned cleanup checks. These smoke
checks do not substitute for the six complete installed/native user journeys.

The corresponding full CLI test run passed 2,075 cases and failed one lifecycle
retention case, with three ignores. Investigation found Unix lock owners that
relied on descriptor closure: a duplicate or fork-inherited descriptor can keep
the advisory lock held. Explicit owner release and deterministic retained-copy
regressions are integrated across the affected operation, receipt, capability and
materialization paths. The corrected CLI executable, SHA-256
`8aa00180b4c155f735431df480fdfdaaeb45e313b1041e3eb1e065c575b27deb`,
passes 2,077 tests with no failures and three ignores, with all four owned
cleanup checks passing. The precise scheduling cause of the preceding suite
failure is not established; that failed run remains separately retained.

At pushed revision `c3445508`, all six task-family integration cases and strict
workspace/all-target Clippy pass. The full core run passes 6,138 tests and fails
the additional unquoted-backtick function-name diagnostic regression, with two
ignores and all four owned cleanup checks passing. The input still receives a
High incomplete-analysis block; its specific curl-to-shell finding is missing.
The follow-up rejects backticks as literal function-name bytes and retains the
existing bounded substitution scanner. Its thirteen issue-family regressions
and existing extended function-name case now pass on a newly built native core
test executable, with all four owned cleanup checks. The complete corrected
core suite subsequently passes 6,141 tests with zero failures and two ignores;
all four owned cleanup checks pass. The preceding failed run remains retained.

The corresponding new CLI suite passes 2,076 tests and fails one preview
filesystem-isolation check, with three ignores. The same test passes in isolation
on the identical executable. Its unexpected audit record matches a concurrent
self-update authorization test. Two runtime-audit tests lacked the shared
environment guard and could write into another test's temporary roots. Both now
take that guard; production logging and the preview's exact no-write assertion
are unchanged. The rebuilt suite passes 2,077 tests with zero failures and four
ignores, including the newly added explicit native-fixture ignore. All four owned
cleanup checks pass; the executable SHA-256 is
`7e3f7e1a53cc94ec98dde7fcc4085cf45231c01bdaae6391b510ef7be992ebb6`.
The preceding failed run remains retained.

The parser-corrected release product, SHA-256
`cc5558cda58e51555a87829da011cc4635f73e8499d368968ba162bbaeab5437`,
passes the signed replacement/rollback fixture with 604 retained source inputs
and all four outer cleanup checks. All seventeen read-only documentation cases
and thirty-two actual 0.4.2/candidate reader cases also pass on those exact bytes.
Later test-only Windows-path and test-isolation changes are not part of that
captured source; their verification remains separate.

The same parser-corrected product passes three fresh default-MONITOR Zsh
activation runs and all three terminal removal scenarios. These cover a custom
ZDOTDIR, preservation of unrelated profiles and history, loaded versus fresh
shell behavior, edited owned blocks and malformed-block refusal. The actual
Claude 2.1.268 host passes all nine hook/failure cases, retained-host reload
observations and the MCP-only boundary control. The host executable, invoked
path and Python runtime identities are retained; this does not qualify a newer
Claude version or a real-model workflow.

The complete browser suite passes eighteen workflow checks plus owned-service
startup and cleanup checks on those same product bytes. Five separate delayed
response cases also pass. Both use embedded assets without a source override;
all owned CLI/service cleanup observations and input rechecks pass. Wide and
narrow screenshots were inspected. The preceding attempt failed before page
checks because the Playwright-matched Chromium executable was absent; its
failed report and private fixture are retained separately. Installing the
matching browser dependency allowed the fresh attempt to proceed.

The managed-policy browser attempt applies the organization profile and then
refuses a harness path comparison: the CLI correctly projects `/Users/<name>`
as `[REDACTED:home_path]`. An owned read-only forensic clone confirms the exact
organization scope, balanced settings and profile selection; both fixture trees
remain unchanged. The harness now checks the source-derived public projection
and records actual policy/output before comparing them. Twenty predicate controls
pass, including refusal of raw private paths and different fixture/file suffixes.
The fresh managed browser run subsequently passes review, organization-only
activation, exact undo and newer-document rollback refusal, plus identified
service startup/cleanup. Its private root is removed after success, all native
cleanup facts pass, and the activated-state screenshot was inspected.

A separately compiled ignored native service fixture exercises real HTTP worker
admission, stale discovery refusal and the ten-second update drain deadline.
Its first native run correctly refuses the prepared mutation because the fixture
used a different policy resolution scope from the service. All outer cleanup
observations pass and the failed root is retained. The fixture now prepares from
the actual service context; freshness checks and the required completed mutation
remain unchanged. The rebuilt test executable, SHA-256
`3afa04bb4d6ff9564f84416f1092d4538f26410e18fbf5018527ff9ff24aa448`,
passes the complete native fixture: an admitted worker remains active across
the 10.252-second drain refusal, new mutations are refused, the released worker
finishes before service exit, and a later service requires its new identity.
Both service threads acknowledge completion and join; the update guard retains
both locks. All four outer cleanup facts pass and the successful private root
is removed. The earlier failed fixture remains retained.

The corresponding release product, SHA-256
`8399644b183e62f6d610f59bb8c5091dd8b83590693b1c61d367002dde49288b`,
is unchanged from the preceding build; the new source capture retains 607
inputs. Its same-version signed replacement/rollback fixture passes with exact
restored bytes and all outer cleanup facts. The first attempt timed out after
the extractor completion marker while the service fixture and shell compilation
were also running. Its failure and unknown nested cleanup remain retained.
A fresh serial attempt uses identical images and the unchanged 45-second child
limit and completes the selected Rust fixture in 26.611 seconds. The overlap
does not establish the precise cause of the preceding timeout. Neither run
establishes an official signed release or a numeric version upgrade.

The lock-corrected release product, SHA-256
`9f3f54647f0d619ef967e97bf1fc4841ce609187d75e40124ef783980b78a6f1`,
also passes the same-version signed replacement/rollback fixture with identical
test/product source inputs and all four outer cleanup checks. Its scope remains
the fixture-key mechanism described above.

The agent-host and packaged-shell qualification runners now retain child
ownership through process-group observation and final reap. Twenty-seven agent
runner controls and seventeen shell runner controls pass, including immediate
post-spawn failures, closed output pipes and bounded cleanup failures. These
harmless controls execute no product candidate and do not certify a host or
package. Failed or incompletely cleaned fixture roots remain available.

Fifteen publication verifier/report controls pass after the ThreatDB corrections.
They cover complete signed declarations before lag retries, duplicate and type
refusals, discovery-surface disagreement, source-sidecar binding, partial upload
reporting and recovery after a failed prior attempt. They use local fixture keys
and downloads; no remote publication or concurrent publisher success is inferred.
Seven release-compatibility generator controls, twelve native resource collector
controls, installer platform controls and npm launcher controls also pass.

The first three macOS resource attempts on `c3445508` (runs `35565819502`,
`35565843602` and `35565863397`) all refuse the selected Apple M1 CPU-class
check before measurement. Their three artifact archives match the GitHub API
digests and are retained. No cancellation occurred: the runs had already failed
when cancellation was requested. The initial refusal did not retain the actual
CPU string; a diagnostic correction records observed host facts without changing
admission or enabling any budget. These attempts establish no baseline.
Diagnostic run `35566520786` observes the actual CPU label `Apple M1 (Virtual)`
and also remains refused. The collector and reviewer now explicitly select that
exact virtual-machine class for a new cohort; fifteen controls pass, including
refusal of bare M1, M2 and altered labels. Three fresh matching, independent
baselines are required before threshold review; no budget is enabled.

## Shell and platform family corrections (2026-09-21)

The latest public reports remain issues 260, 261 and 264. The shell correction
allows static bracket conditions, bounded numeric arithmetic and proven Python
data pipelines while retaining unknown command identity and executable child
bodies. Eleven focused Rust regressions pass on the corrected native macOS core
test executable, SHA-256
`c1f17322cb41ac5fbec131131fea8240c3d4e65fd0630d2c7d1ff89571275917`.
All four owned process-group cleanup checks pass. The preceding complete core
run passed 6,131 cases and failed the newly added Zsh function-name case; the
correction now retains both name substitutions and literal body threats. That
failed attempt remains distinct from the focused corrected result.

Actual CLI comparisons on the preceding retained candidate allow the reported
bracket, numeric arithmetic and simple Python data cases. Dangerous arithmetic
and stdin code execution remain blocked. Variable executable names still report
incomplete analysis with explicit-path guidance; a literal assignment cannot
establish live shell state, so issue 264 is not claimed wholly resolved.

Android changes incorporate contributor PR 262 at
`74a6f0aa5ca43d977ba52388852e0c8d260e306d`, with unavailable-backend guidance and
installer refusal added. No native Android or BSD qualification is claimed.
The related release-selection correction preserves the full Cargo target,
including libc and ABI. Installer controls reject unknown libc and 32-bit GNU
userlands, and npm controls check glibc without diagnostic-report networking.
Shell/npm tests pass on the retained source; native GNU/musl build and provenance
checks remain part of the next CI run. Ordinary protection requires no elevation.

## Platform CI and corrective checks (2026-09-21)

For pushed head `5aa893e6`, [CI run 35558439054](https://github.com/sheeki03/tirith/actions/runs/35558439054)
tests GitHub's merge snapshot `be5ff29d` against main `800ffb3b`. It
records 9,925 Linux test passes across 70 harness results, 9,761 macOS passes
across 69 results, and 9,924 Rust 1.83 passes across 69 results, with no test
failures in those three jobs. These are aggregate harness counts, not a count
of distinct tests. Linux includes 40 core materialization cases, 63 core team
policy cases and 23 team CLI cases, plus the materializer CLI/recovery cases.
Native PowerShell and capsule interruption/receipt steps also pass on Linux. The downstream release-compatibility gate correctly fails because Windows/musl build failures skip required package-validation jobs.

The same head fails Windows compilation because the pure exact-mode transform
was gated to Unix, and ARM musl compilation because a newly added rename used
a libc wrapper unavailable on that target. Linux Clippy rejects test-module
ordering and explicit drops of non-Drop evidence values. Cargo Deny reports
RUSTSEC-2026-0285 in the locked Rustls version. The corrective source removes
the inappropriate method gate, uses the existing Linux syscall pattern without
an overwrite fallback, fixes the test lints, and updates Rustls to 0.23.45 in
both workspaces. Strict macOS workspace/all-target Clippy passes on that source;
the corrected Windows/musl jobs still need to run. The local locked workspace
advisory check subsequently passes with Rustls 0.23.45.

At `c3445508`, [CI run 35565787098](https://github.com/sheeki03/tirith/actions/runs/35565787098)
passes compilation on Windows and the strict formatting, Clippy, advisory,
installer, artifact-protocol and workflow-fixture checks. Linux, macOS and Rust
1.83 each fail only the additional backtick core regression described above.
The digest-verified Windows artifact records successful standard-account
dashboard execution, exact-account cleanup and all other workspace harnesses
passing. Its core harness has two failures: that same parser case and a local
package effect fixture whose Unix-only destination is not absolute on Windows.
The overall Windows job remains failed. The separate [native ARM run
35565787206](https://github.com/sheeki03/tirith/actions/runs/35565787206) passes
both GNU and musl jobs after the syscall correction.

The [PR release validation run 35565787403](https://github.com/sheeki03/tirith/actions/runs/35565787403)
builds all six release targets and passes native ARM, GNU distribution, macOS,
Windows, Debian/RPM and release-compatibility checks. npm assembly alone fails
because its exact package-file allowlist omitted the newly added README. A
one-line correction retains exact membership checking; local offline pack
controls reproduce the old refusal, accept all six corrected fixture packages,
and refuse a missing README, an unexpected member and changed embedded bytes.
These are inert fixture packages; the corrected CI run must validate actual
candidate archives. Publishing jobs remain skipped on this PR.

The signed replacement fixture's independent source review identified and
closed a native-target type mismatch and missing Cargo-to-checkout association.
Its 16 Python parser/crypto controls and six selected Rust parser/crypto/private
storage tests pass. The subsequent actual native macOS ARM fixture passes in
30.2 seconds overall, with the selected native test completing in 20.66 seconds.
The retained release product SHA-256 is
`7c933bf0c4f00d03891dc482722bcce10065650c5da72511746bd994529eb1c8`;
the original test-image SHA-256 is
`db0a51e1f59753d95ad6539b95a92fa49e90162c527af2e3f5f9a41324f3319a`.
All 603 captured source files are retained with matching hashes. Actual signed
archive admission, production extraction/replacement, rollback receipt checks,
stale-generation refusals, configuration preservation and final destination/
backup readback pass. Both owned outer jobs pass all four cleanup checks; the
separate trusted extractor is observed completing normally.

This is same-version test-image to release-product to original-test-image
replacement using a public fixture key. It does not establish official release
signing, numeric upgrade, startup of the swapped-in product, shell/host reload,
service migration, crash/power-loss durability, Windows, or process-tree cleanup.

All twelve historical resource experiment artifacts have been retained and
checked. Only the `url_first` control/growth pair matches the reviewed EPYC 7763
cohort: its actual allocation increase is 33,554,429 bytes, and only its selected
ceiling is crossed. The other five pairs are refused because their CPU classes
differ. Their successful workflows are not admitted growth evidence. Resource
budgets remain disabled pending comparable qualification and current-source
measurements.

## Optional team policy and local materialization (2026-09-21)

(Historical: the local-leaf npm routes `pkg install-npm` and `pkg materialize` were
later retired before release; see the archive tags.)
The resumed source matches all 62 retained changed/new inputs at base
`3629a724`. Its input manifest SHA-256 is
`fe209fcf795e589e5a35869848237749365c2282b5b9ff8108231cedbbdb4b1b`. The corrected full CLI unit executable
passes 2,064 tests, zero failures and two existing ignores. All five targeted
parser/task-policy regressions pass. The earlier corresponding core executable
passes 6,122 tests, zero failures and two existing ignores; the optional policy
server passes all 26 tests. The subsequent core change only renames a private
platform module. Strict workspace/all-target Clippy, formatting and diff checks
pass on the resumed source. Retained failed fixture runs are not counted as passes.

The real macOS HTTPS and Chromium journey passes 35 cases on its separately
retained candidate. It exercises private-CA certificate verification and explicit
address pins, authority mismatch refusal, separate connection and activation,
reviewed publication, concurrent update refusal, bounded rollback, exact-intent
reconciliation after lost replies, partial adoption, stale report retry refusal,
historical report reconciliation, explicit unknown-outcome archival, offline
withdrawal and malformed-enrollment repair. Browser checks cover explicit review
acknowledgment, read-only refresh, clearing credential input paths and absence of
credential values from the rendered page. Product processes pass all four owned
process-group cleanup checks. Browser/driver cleanup uses its own API; this is not
process-tree, remote-deployment, Windows or independent fleet-adoption evidence.

The optional server, typed client protocol, local connection/enrollment and
CLI/browser rollout controls are implemented. Personal operation remains
independent of a server. The Linux-only local package materializer has explicit
plan/apply/status/undo/recovery contracts and does not execute package code. Its
native Linux write/recovery cases subsequently pass on `5aa893e6` as recorded
above. Final installed-artifact and broader storage-fault qualification remain.
General npm/Python private-input execution remains disabled.

Three retained release100 measurements at source `6b1aed52` share the exact
EPYC 7763 compiler/image/CPU class on distinct recorded boots. They establish a
reference for six allocation/RSS limits. Six actual growth variants and six
zero-dose controls completed their benchmark workflows; raw matching-cohort
evaluation remains separate from workflow success. The resource limits are not
yet enabled. Signed replacement, final installed-package journeys, the beginner
pilot and release/channel gates remain open.

## Integrated automatic activation and recovery qualification (2026-09-13)

The local candidate built from 90 retained changed/new inputs at base
`aab72fdf` has manifest SHA-256
`42aa775c321e75281cdc78ec4ae5a9fd58efac6b46455c3d4ee31036450149f0`.
Its full CLI unit executable passes 2,032 tests, zero failures and two existing
ignores. The preceding full core executable passes 6,022 tests and two existing
ignores; the subsequent rollout-only change passes all ten targeted tests.
Strict workspace/all-target Clippy and formatting pass.

The retained release binary SHA-256 is
`b9710b2eaf7174fbeed4d5a9642a650b02ef181429589a577e4f7c002e288b8c`.
All eleven unchanged first-entry cases pass, including its first invocation.
An actual recommended setup followed by a fresh native macOS Zsh session now
completes the ordered automatic sequence: one allowed execution, zero blocked
executions and successful terminal-state restoration. This row uses the tested
MONITOR-off configuration. It does not qualify default job control, other
shells, unsupported native module generations or released packages.

The actual browser journey passes all three history/undo checks. It displays
the exact stored observation, retains it after setup undo, reports the startup
files as changed and keeps current protection unknown. Historical records are
operator-owned evidence, not durable cryptographic attestations of current
interception. Real child processes with umasks 022/027 cover private activation
parent creation and the narrowly authorized migration of existing parents.

Full native integration executables pass 22 Bash export cases, 55 Bash
enforcement cases, four shell-session identity cases and 37 shell-conformance
cases, with two existing conformance ignores. An older CLI integration fixture
could not find the binary under test and matched echoed prompt text. Its
correction prepends the built binary directory and requires fresh framed prompts
plus an observed enter-mode frame before inducing the runtime delivery failure.
The corrected targeted case passes. The fresh complete CLI integration
executable passes all 503 tests with one existing ignore, unchanged product
bytes and all four owned cleanup checks passing.

Actual fixed-capacity storage qualification passes seven signed audit recovery
scenarios, including six stopped rotation boundaries and concurrent cancellation.
A real HFS+ ENOSPC audit append preserves prior evidence and verdicts while
reporting failure. A separately owned APFS volume passes actual profile ENOSPC,
unchanged-policy refusal, freed-space same-ID retry, stable replay, exact undo
and stable undo. All owned images were detached and fixture keys removed.
Earlier failed admission and unsupported-filesystem reports remain retained.
These rows do not qualify Windows durability or power loss. The registered
storage runners pass all 36 portable lifecycle fixtures.

The resource workflow now permits an explicit 100-sample collection of its
current source. Earlier pinned references remain historical after producer
changes. New comparable references and actual growth cases are still required
before enabling allocation/RSS thresholds.

The optional self-hosted policy service and the no-code local package
materializer are being implemented separately. Neither is qualified by the
results above. G0–G3 and release certification remain open.

## Earlier retained qualification records

Run date: 2026-09-12. Source: the reviewed foundation implementation on
`codex/next-cycle-foundations`, based on
`7fd35101568bb06ee0d361dc1d4a4d193c5f60fd` (0.4.2).
Host: macOS / Darwin 27.0.0 arm64, Rust 1.98.0, Cargo 1.98.0.

All Cargo commands ran from the implementation checkout with
a shared `CARGO_TARGET_DIR` to reuse existing dependencies.
Subprocess integration tests use test-owned user, policy, audit and cache roots.
The existing build directory is not an installed/released package. No changes
were made to the user's source edits in the original checkout.

| Check | Result |
| --- | --- |
| `cargo test --locked -p tirith-core --lib policy_snapshot::tests -- --test-threads=1` | Passed: 3 tests. These are included again in the combined 151-test run below, not counted twice. |
| `cargo test --locked -p tirith-core --lib mcp:: -- --test-threads=1` | Passed: 219 tests; no ignored tests in this selection. |
| `cargo test --locked -p tirith-core --lib -- output::tests audit_tune::tests redact::tests policy_snapshot::tests force_full_runner_evaluates_regex_rule_and_returns_effective_policy --test-threads=1 --quiet` | Passed: 151 tests; no ignored tests in this selection. |
| `cargo test --locked -p tirith --test policy_effective_snapshot --test policy_tune_decisions --test c00_cli_compatibility --test help_snapshots -- --test-threads=1 --quiet` | Passed: 5 policy-snapshot, 3 tuning, 2 legacy compatibility and 209 help tests. |
| `cargo test --locked -p tirith --bin tirith cli::policy::tests -- --test-threads=1 --quiet` | Passed: 23 tests, including the 5,000-key collision regression. |
| `cargo test --locked -p tirith-core --test c00_contracts --test policy_integration -- --test-threads=1 --quiet` | Passed: 5 frozen core contracts and 46 policy integration tests. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed with no warnings. |
| `cargo fmt --all --check` and `git diff --check` | Passed. |
| Documentation relative links | Checked; all existing targets resolve. |
| Independent code review and follow-up | Completed; strict-warning wording, dynamic map-key privacy and collision complexity findings fixed, no remaining substantive findings. |

The selected runs cover **663 distinct passing tests**, with no failures or
ignored tests in those selections. The initial three snapshot tests are counted
once. Filtered-out tests are outside this evidence.

These are targeted source and CLI regression checks on this host. They do not
replace the full workspace suite, Rust 1.83 checks, Linux/Windows tests,
installed-package/real-agent certification, performance measurement, or release
artifact checks. The snapshot tests explicitly exercise deterministic remote
transport refusal, not a live authenticated policy service. Complete remote
freshness/revision and native host evidence remains open in the acceptance
matrix. No release gate is closed by this record.

## Subsequent implementation checks (in progress)

The earlier 663-test result applies only to the foundation commit `6b83e302`.
The larger working-tree implementation has separate partial evidence:

- Core profile selection/ownership tests: 7 passed.
- Core trust grant tests: 6 passed before later identity strengthening.
- Core evaluation/output/contracts/escalation/session selection: 189 passed,
  one new evaluation fixture failed because it expected `pipe_to_interpreter`
  for a curl pipeline. The fixture now correctly expects `curl_pipe_shell`;
  the correction is pending recompilation and rerun.
- Bounded history selection: 16 passed (five new history tests and eleven
  registry-history tests). This includes a 300 MiB source, oversized-line
  forward progress, partial appends, retry identity and source replacement.
  Later timestamp/filter spelling changes are pending rerun.
- Core snapshot selection: 10 passed and one fixture used a nonexistent policy
  field. The fixture now changes `scan.require_complete`; later cache and
  operator-destination tests are pending recompilation.
- ThreatDB Python operational recovery tests, source watcher tests, transactional
  fetch fixtures and actionlint passed before the final compiled test batch.
- Packaged shell certificate Python tests: four passed, including ambiguous
  archive entry identities; native Bash/Zsh/Fish script syntax checks passed.
- Embedded dashboard JavaScript passes `node --check`. The service and browser
  workflows are not yet qualified by that syntax check.

A consolidated `cargo check --locked --workspace --all-targets` is in progress
for the full working tree. Complete current-revision core/CLI/service tests,
Clippy, formatting, native platform checks and browser evidence remain required.

## Current working-tree checkpoint (2026-09-12)

The core library executable built before the latest npm/aggregate additions ran
its complete suite: **5,812 passed, 2 ignored, 0 failed**, in 364.56 seconds.
The log is `/tmp/tirith-cycle-core-full-runtime.log`; this does not certify later
source edits or native platforms absent from that run. The captured working
inputs and manifest for the corresponding control build are kept in the local
evidence directory `control-build-inputs`.

The associated workspace all-target check passed. Selected current core tests
(159/159), real control-service integration tests (2/2), bounded history CLI tests
(2/2), and policy simulation integration tests (3/3) passed. The profile suite
exposed an undo failure after unrelated personal-policy edits, and a unit test
still assumed denial could not create a coordination lock. Both now have source
fixes, awaiting relink and regression execution.

Chromium exercised all six pages against the real candidate, hostile history
rendering, profile preview/apply/undo, and scoped exception add/explain/revoke.
The narrow-layout assertion found overflow from long project paths; wrapping is
fixed in source and awaits the next browser run. No complete browser pass is
claimed from a run that ended on that assertion. Subsequent browser tests also
cover reopening saved operations and owned shell setup/undo.

## Integrated CLI checkpoint before retention and lifecycle adapters

The `integrated-cli-build-inputs` source manifest identifies the candidate with
CLI SHA-256 `482e05633bb37099ea2f507b7ed15fdc9edcf96f20272e8af5baa641852321cb`.
On this candidate:

| Selection | Result |
| --- | --- |
| Shared operation, profile/settings, control, trust, lifecycle and npm unit tests | 63 passed |
| Profile lifecycle subprocess tests | 8 passed |
| npm inspection/comparison subprocess tests | 2 passed |
| History subprocess tests | 2 passed |
| Policy simulation subprocess tests | 3 passed |
| Selected core npm, aggregate and self-update tests | 67 passed on the corresponding core build |
| Packaged macOS Bash/Zsh/Fish shell checkpoint | 27 passed: 17 Bash, 4 Zsh, 6 Fish |
| Control subprocess suite | 3 passed; one service startup timed out under concurrent hashing load |
| Isolated rerun of that control test | Passed |
| Chromium dashboard launch | Timed out before browser workflow assertions; no browser pass claimed |

Native sampling identified repeated software SHA-256 hashing of the large debug
test executable during retained-identity checks. The development/test profile
now optimizes only the SHA dependency; release compilation and exact-byte
identity requirements are unchanged. This change requires a new candidate and
reverification and is not a release performance measurement.

The new retention, reviewed rollout, support selection/export, feedback,
private-file edit, lifecycle worker and ARM production changes have later
source manifests. The first combined typecheck found four adapter compile
errors; the second found one optional undo-document test assignment. These were
fixed before the `private-export-test-build-inputs` linked test build. Runtime
results for that checkpoint are recorded below; the earlier counts do not certify it.

Independent review of those adapters also found and corrected custom DLP/home
replacement ordering, missing selected-history projection, excessive RFC3339
fraction storage, scope mismatch for CLI audit apply, empty compensation reuse
and privacy-mode drift on feedback writes. Support exports now use the shared
policy/task-authorized private-file operation rather than a direct writer.
Regression fixtures for these fixes passed on the linked candidate below.

No native Windows/Nushell/PowerShell qualification, real-agent certification,
beginner pilot, published release, or full G0–G3 completion is claimed here.

## Private export and retained lifecycle test checkpoint

The `private-export-test-build-inputs` capture linked successfully in 5m 57s.
Candidate CLI SHA-256:
`e811d8cc999dd24294c6f30e22a62a413aee2170a0d48c48c17f441f990cc270`.
All **198 selected tests passed** on the captured macOS candidate:

- 84 core npm/aggregate/update/retention/rollout/task-family tests (4.56s).
- 85 CLI control/operation/private-file/shell/profile/trust/lifecycle/support
  unit tests (77.52s).
- 4 support export, 3 feedback, 3 rollout, 8 profile lifecycle, 2 history,
  3 simulation, 2 npm CLI and 4 real service subprocess tests.

The four service tests completed in 12.91s, including the startup case that
previously timed out. This is a debug candidate observation, not a general
performance guarantee. Existing unused legacy trust/doctor helpers still emit
warnings and must be reconciled before the final strict Clippy check.

The first expanded Chromium run reached audit rotation after profile,
exception, feedback and support-download workflows. Rotation refused the
synthetic unchained history tail as required. The browser fixture now appends a
real `hook-event` audit-writer record before rotation. After also correcting the
test's wrapping-label dropdown selector, the expanded browser run passed all
12 workflows. Evidence is `private-export-browser-final-fixture/browser-results.json`
with wide/narrow screenshots. This includes feedback apply/undo, selected support
download, exact audit rotation/undo, impact review across activation/undo, saved
operation recovery, shell setup/undo and zero narrow-screen horizontal overflow.
No browser JavaScript errors were observed.

The full core test binary from this same capture subsequently passed **5,862
tests**, with **two ignored and zero failures**, in 504.41 seconds. This does
not include later project review, caller-shell verification, archive controls,
or signing-drift changes, which require the next captured build.

Later review identified additional work before release: signing-key drift
guards for retention, partial-publication cancellation reporting, idempotent
lifecycle apply responses and the native ARM initial-breakpoint resume path.
Passing this checkpoint does not close those findings or certify later edits.

## Published 0.4.2 baseline and legacy trust compatibility

The published `tirith-aarch64-apple-darwin.tar.gz` from tag `v0.4.2` was
retrieved separately from the implementation build. Its SHA-256 is
`551f9a6ebf58344e7d0aa06bcc78d7a4f2f7b44b8011be563e0a91976cc9c4df`
and matches the published checksum document. Cosign verified that document
against the GitHub Actions issuer and the exact release-workflow identity
`https://github.com/sheeki03/tirith/.github/workflows/release.yml@refs/tags/v0.4.2`.
The extracted executable SHA-256 is
`873d8834902dbc47f339f79088d0a839f8932f5a8c34dcaedacb60fa6f2d0922`.

Eight isolated baseline commands captured version, help, unconfigured status,
quick doctor, effective policy, a clean check, a blocked pipe-to-shell check and
an empty trust listing. The unconfigured status exit and blocked-command exit
were preserved as expected failures, not relabelled as healthy states. Neither
check executed its input command.

Five compatibility assertions passed against that actual old executable and
the `e811d8cc999dd24294c6f30e22a62a413aee2170a0d48c48c17f441f990cc270`
candidate. A newly created one-hour, rule-specific project grant allowed the
candidate's enrolled project and blocked its sibling. The released 0.4.2
executable blocked both. It also continued blocking when the new grant envelope
was copied into the legacy trust-store location. Evidence is retained in
`baseline-0.4.2-macos/contracts.json`, `signature-verification.log` and
`legacy-trust-compatibility.json`. These checks do not replace the remaining
copy/move, worktree, expiry, native-platform and final-candidate matrix.

## Native Linux ARM production launcher checkpoint

The captured source snapshot
`5c4d99e5e0cdca59a1a7705b1ccce4efb6cfbd5193c62290009cd7d425937645`
built with Rust 1.83 on native Linux aarch64. The resulting GNU executable
SHA-256 is `b9427f237c665b6ceef7adb7b6bf78d2aaa4872051ac4075d7872a3d94588237`.
Nine production-launcher cases passed as UID 65534 on Linux 6.12.76 aarch64:
clean execution, child exit propagation, network and io_uring denial,
namespace/ptrace denial, project/outside-file isolation, secret-environment
removal, memory/file-descriptor limits, fork/wait and inherited-handle closure,
and bounded-output termination. Cases combine related assertions; every case
confirmed required coverage and cleanup. The exact case list, receipts and
fixture image identity are retained in `wp27/production/qualification-v2.json`.
No emulator was used. Cancellation, musl, release-artifact qualification and
later source revisions remain separate evidence requirements.

## Shell trace and inherited-export regressions

The standalone native shell suite passed **96/96 cases** with no failures on
system Bash 3.2, current Bash, Zsh and Fish, against both source and embedded
hook copies. Controlled fake capabilities were used throughout. The assertions
cover tracing enabled/disabled, verifier and ordinary receipt callbacks, full
hook registration and inherited exported placeholders. Each relevant body ran
exactly once, capability/raw hook state remained absent from trace output,
ordinary child processes inherited no capability, and caller tracing state was
restored. Evidence is `tirith-shell-trace-final.jsonl`.

The preceding 64-case callback-only suite had exposed 32 trace failures before
the fix. Expanded source-registration cases additionally exposed 16 inherited
export failures before explicit unexporting was added. These are shell-source
regressions; they do not replace actual receipt/caller-shell PTY tests on the
next linked executable. A later independent status-proof review also required
a fresh intercepted status command for every verified result; its newly added
core regression still awaits the next candidate.

## Integrated review and resource measurements

The integrated `reviewed-shell-cache-browser-lifetime-inputs` snapshot passed
`cargo fmt --all --check` and strict
`cargo clippy --workspace --all-targets --locked -- -D warnings` (6m31s).
This includes the bounded cache capture, retained project-root checks, fresh
shell-status proof and complete npm/privacy diagnostic capture. A corrected
failed-rollback integration fixture then passed its targeted Clippy check.
The subsequent offline-probe and Linux readiness additions are included in
commit `71070bbbb02a3a6e5f96d335a048e92a7f048679`; their complete linked
recertification is in progress.

The exact ARM readiness policy and tests from source snapshot
`7d9788bfe34462c745b252038ac6d045265d08d940759fc82f9620c882b5d317`
compiled with Rust 1.83 and passed six native tests as UID 65534. They exercised
eventfd/epoll readiness, polling and timers while retaining socket, io_uring,
namespace and arbitrary-signal denial. These are isolated production-policy
tests; the complete launcher and interruption cases require separate results.

`scripts/measure-local-control.py` accepts `--binary`, `--output`, `--samples`,
`--history-rows` and an optional `--baseline` executable. It measures identical
version, quick-doctor, local-policy and ordinary-check commands against both
executables, alternating order, plus candidate-only policy/profile and service
requests. The report records exact executable hashes, first and subsequent
samples, median/p95 distributions and enforced history/response bounds. First
samples do not imply cold OS caches. Ambient host contention is uncontrolled,
and debug-versus-release ratios do not define release regression budgets.

A three-sample runner validation against the previously linked `e811d8cc`
candidate and signed 0.4.2 baseline passed all eleven measurements and bounds
with a 10,000-row, 3,940,000-byte history fixture. It is recorded in
`performance-runner-checkpoint.json`; final packaged resource measurements,
peak memory/CPU/allocation measurements and reviewed budgets remain pending.

## Linked offline-readiness candidate and follow-up regressions

The `offline-probe-readiness-test-build-inputs` capture linked successfully in
10m52s. Its executable SHA-256 is
`b2ba2d23c8091eaac111cbaefa3fa877617d2716aca20be808a92db838f360de`.
The selected core/CLI/integration run passed 173 tests and failed seven. The
failures identified root anchoring to a linked manifest, newest-record selection
in busy small logs, and fresh recommended-setup policy discovery, plus three
fixture problems (canonical pip version, stale-shell refusal precedence and
explicit history logging). These are recorded failures, not a passing candidate.
Fixes and expanded regressions await integrated recertification.

The same executable passed all 17 actual Chromium workflows in
`offline-readiness-browser-expanded-details/browser-results.json`, including
retained-root project review, npm inspection/comparison, six pages, hostile text,
feedback apply/undo, tuning, profiles, exceptions, saved operations, selected
support download, rotation/undo, segment export and irreversible deletion,
impact activation/undo, shell setup and combined setup with an existing policy.
Screenshots were visually inspected; no browser JavaScript errors occurred.
An expanded busy-history browser case is prepared for the next candidate.

The new history module, SHA-256
`84f252f14a7a3bd2c79b2d9eab9f6ea5aefe89f3cd92bc46dce4e177b13dcb79`,
passed ten isolated native tests linked against the frozen dependency graph.
They cover newest selection, forward compatibility, older pages, append/retry,
filter/direction invalidation, split-record recovery and progress over giant
records. Evidence is in `history-module-current`; this does not replace the
integrated CLI/API/browser run.

CI on `71070bbbb` passed strict Clippy, formatting, dependency policy, installer
fixtures, native ARM GNU/musl qualification and the performance workflow. Native
Linux/macOS/MSRV tests found the recommended-setup and completion-generation
regressions; Windows compilation found retained-handle thread ownership and an
unconditional Unix permission API. The Bash hook job found a fixture mutation
blocked by the actual hook. The release check found its read-only ARM job missing
from the validation-job classification. Fuzz preflight found one missing direct
dependency edge in its lockfile. Each failure is being fixed and rerun; none is
waived by the passing jobs.

## Resource runner validation and corrective candidate

The resource runner now accepts `--resources`. Each measured command runs under
one fresh wrapper that collects kernel child CPU time and peak RSS; the timed
interval excludes wrapper startup. CPU and memory records stay attached to the
same command and candidate/baseline role. Detached service memory, concurrent
process-tree totals and allocator activity are explicitly not measured by this
method. The fixture report records regular-file bytes before and after the run.

The retained `b2ba2d23` checkpoint passed a three-sample resource-runner check
with 10,000 history rows and all eleven request/response bounds. Fixture growth
was 2,481 bytes. A second self-comparison using the same executable for both
roles confirmed three separate resource samples per role for all four paired
commands; fixture growth was 4,362 bytes. Every completed-child RSS sample was
positive and CPU samples were nonnegative. Reports are
`resource-runner-checkpoint.json` and `resource-runner-self-comparison.json`.
The final checked runner SHA-256 is
`dcdd99ab38209aac758894ebdbc62b4d6ed88a2dacf5b400f866f2a547d4bc82`.
These validate the measurement tool; concurrent compilation made host contention
uncontrolled and these samples establish no release regression budget.

The `history-setup-native-fixes-inputs` capture passed formatting and strict
workspace/all-targets Clippy in 11m49s. Its selected test executables were linked
for integrated runtime verification. The capture includes a separately
hashed shell-conformance supplement: native Zsh binding changes now prepare the
helper-drift fixture without asking the active security hook to execute a
command it correctly blocks.

## History, setup and native-target corrective candidate

The corrected source capture linked in 16m20s. Candidate SHA-256 is
`11fde156220c6e9bf2cbfd7e26af0b7929b3850bc6c3cdabbdbb37f38bc04172`.
The focused run initially passed 307 tests and found one error in a newly added
feedback test: apply returns the stored operation status, whereas the test read
the dry-run preview shape. The corrected test now checks completed state, the
persisted event UUID and expectation, and unchanged audit bytes. All four feedback
tests passed on the same candidate. The reconciled selection passes **308 tests**
with no failures or ignored tests; the initial failure report and separately
hashed test supplement are retained. The complete core suite passed **5,892 tests**
with two existing ignored tests; the complete CLI unit suite passed **1,899 tests**
with two existing ignored tests. Both had zero failures. The report collector
initially selected an embedded child-test summary; the retained raw logs and
`*-verified-results.json` reconcile counts against the final anchored libtest
result without rerunning or discarding the original reports.

Five actual native caller-shell cases passed on this candidate: Bash allow/block
verification, Bash interceptor removal, Fish verification, Zsh helper replacement
and Zsh disabled interception. These confirm the full Darwin executable-identity
fix and actual helper-drift preparation. Packaged Bash/Zsh/Fish qualification
separately passed 32 cases. Four additional cases passed: three controlling-terminal
confirmation/refusal cases and the npm launcher across all three shells. Native
Claude 2.1.268 baseline checks passed allowed, blocked and explicitly disabled
cases; the binary and each executed configuration stayed unchanged. These results
do not qualify the separately prepared guarded-hook changes.

The first browser attempt reached the combined three-step setup but exceeded its
40-second fixture wait while two steps were applied and the third was applying.
The fixture now allows a bounded 120-second wait for combined apply/undo and
records both elapsed times; this is not a release latency budget. A second attempt
correctly refused mutation after a test relink replaced the build-path executable
identity. Final browser recertification uses a retained candidate outside Cargo's
mutable output path. Both failed attempts remain recorded; neither is counted as
a successful browser run. A third retained-binary attempt passed fourteen checks
but remained at a planned impact operation after Apply; its request timeline was
not recorded and the cause remains unresolved. The instrumented focused five-flow
reproduction passed impact apply/undo, shell setup, combined setup and narrow
layout with actual operation transitions recorded. The full instrumented run subsequently passed all **eighteen workflows** on the
retained candidate, including busy-history pagination, impact review and combined
setup. Binary identity remained unchanged. That pass does not erase the earlier
intermittent result: independent review found same-operation stale-response and
dialog-replacement races. A guarded UI and deterministic delayed-response
regressions are being prepared as a separate correction.

## Bounded npm-reader fuzz checkpoint

The npm artifact reader completed **36,320 executions in 301 seconds** with
AddressSanitizer, eleven inert seeds, a 256 KiB input ceiling, a 1 GiB RSS limit
and a ten-second per-input timeout. No crash artifact was produced; final reported
RSS was 453 MiB. The source was exactly `71070bbbb` plus the one-line fuzz lockfile
dependency correction. The isolated development build used Rust nightly
`1.100.0-nightly (0fc141305 2026-09-11)` and cargo-fuzz 0.13.2; the workflow uses
its separately pinned nightly. `npm-fuzz-71070/qualification.json` preserves the
source/lock/target hashes, seed hashes, executable identity, corpus and full log.
This is bounded fuzz evidence, not an exhaustive claim or a closed G2 gate.

A separate allocation-counter prototype linked against the corrective candidate's
core dependency graph and passed its known-layout counter self-check plus six
isolated three-sample workloads. It records thread-local Rust allocation requests
and full reallocation request sizes, excluding native allocation bypasses, other
threads, children and live-heap size. The 10,000-record fixture was 4,360,000 bytes.
Evidence is `allocation-runner-prototype-v2`; the production benchmark registration
and release-profile measurements remain pending.

## Corrective checkpoint CI follow-up

Checkpoint `13e18ca8` passes formatting, Clippy, dependency policy, Bash hooks,
Linux/macOS install scripts, action-runtime checks, artifact transport and the
existing performance gate. The Linux/MSRV CLI unit suites pass 1,957 tests with
two existing ignores; macOS passes 1,899 with two existing ignores. Their later
C00 compatibility test rejects an added recovery field in legacy schema-3 command
JSON. The frozen fixture is retained; a separate opt-in schema-4 recovery format
is being prepared so ordinary JSON retains its existing shape.

Windows now compiles and reaches native tests, finding 47 CLI unit failures.
Many share private journal-directory ACL validation, and one finds an in-place
binary edit that metadata-only validation missed. These are open defects under
investigation, not permission checks to waive. The test workflow now uses
`--no-fail-fast` to report later executable failures in the same run while still
failing the required check.

### Retained audit-health, Claude and dashboard candidate

The next development candidate, SHA-256
`a70b8eba427c8cfbc20287c94102d0da59ce7d44a01e2f0e388f1baddcae156f`,
was retained before additional compatibility/native corrections. Its source
capture is `health-claude-ui-inputs` on `13e18ca88e6c923c1c2df547741735bb17dda930`;
the candidate manifest pins all seventeen linked test/benchmark executables.
This is a development executable, not a signed release artifact.

All eighteen complete browser journeys passed using its embedded assets and
real local service. The five separate delayed-response cases also passed with
no source override. The old embedded candidate failed the stale planned-status
negative control, demonstrating that the new response-order assertions detect
the original defect. Real Claude Code dispatch passed all nine configured-hook
and explicit boundary controls; the three boundary controls document behavior
outside the protection claim rather than expanding its scope.

The selected Rust runtime run completed with 310 passing tests and six failures.
Three failure-notice unit fixtures timed out on the shared filesystem-root setup
lock; the cross-process fixture then found no persisted notice. A generation
change was refused with a newly bounded snapshot error that the older assertion
did not recognize. The concurrent audit writer test assumed every call succeeds
and discarded its results; bounded lock waiting now explicitly reports refused
appends. These failures are retained as evidence and require correction or an
appropriately isolated verification of the documented contention behavior.
Passing browser or host tests do not substitute for those checks.

On pushed commit `13e18ca8`, the separate Fuzz, Benchmarks, Release workflow and
both native ARM containment checks completed successfully. The ordinary CI
workflow failed for legacy command JSON compatibility and native Windows
storage/identity/fixture defects described above. Release workflow success on a
branch is not evidence that a release was published. The next candidate preserves
the legacy schema and adds explicit schema-4 recovery selection, atomically
private Windows storage, and a retained executable write lease.


### Compatibility and private-storage candidate

The next retained native macOS development executable has SHA-256
`181aa10334856a5d6947e933c6b943086d5cdbb012d213b696917a0808a474ae`.
Its source capture is `compat-health-native-inputs-v2` on `13e18ca8`; its manifest
pins the CLI and eighteen linked harnesses. Unregistered npm installation drafts
are explicitly excluded from the compiled graph. All registered Rust input
hashes matched the capture before the executable and harnesses were retained.
The selected build completed in 13 minutes 21 seconds without warnings.
Strict workspace/all-target Clippy passed on these same registered sources in
4 minutes 20 seconds; formatting and diff checks passed.

All **385 focused checks passed**, with zero failures or ignores: 144 selected
core checks, 186 selected CLI checks, four compatibility checks, nine dashboard
API checks, five history checks, four feedback checks, eight profile lifecycle
checks, three local rollout checks, three tuning checks, two project-review
checks, four support-bundle checks and thirteen release-security checks. This
includes the schema-3/schema-4 compatibility correction and the audit-notice,
concurrent-writer and generation-change regressions that failed on the preceding
candidate. The production notice lock budget remains 25 milliseconds; the tests
exercise bounded refusal and use a longer explicit budget only for positive
unit-fixture creation. The cross-process integration retries the actual inert
check and verifies the unchanged verdict on every attempt.

The same source contains native Windows ownership/DACL and binary write-lease
corrections. A macOS pass does not validate those Windows branches; the next
native CI run must do so. Linux private-input namespace corrections have separate
primitive evidence, while the actual wheel pipeline remains under qualification.
The update dry-run side effect found during the lifecycle audit is a separate
pending correction and is not included in this executable.

### Receipt, npm staging and combined agent setup candidate

Retained macOS ARM development binary
`f703dad659d12899330f6c214ded5363f45dc6381d13afe5245fbe8190752f2e`
was built from `npm-receipt-claude-inputs-v2` on `24be3f28`. Its manifest pins
the CLI and fourteen test executables. The linked build completed in 14 minutes
44 seconds without warnings. Registered npm staging, runtime-pack models,
checkpoint extraction and schema-3 npm receipt types are included; npm execution
qualification still refuses installation.

The complete core unit suite passed **5,931 tests**, with two existing ignores.
The complete CLI unit suite passed **1,925 tests**, with two existing ignores.
Eleven selected integration targets passed **258 tests**, including frozen
contracts, freshly private saved receipts, explicit npm ecosystem routing,
tuning, profiles, rollout, feedback, dashboard transport, shell helpers and help.
The separate 502-case CLI integration executable recorded **498 passes, three
failures and one existing ignore**. The failures were the generated capability
table, an inherited-status assertion that expected a verified-looking prompt,
and a receipt error-message compatibility substring. The table was regenerated
with this exact compiled renderer and its isolated check passed. The other two
corrections require the next linked candidate. Earlier failures remain retained.

Real recommended setup, followed by actual host dispatch, passed all nine
configured-hook and explicit boundary cases on this binary. Every case used
the installed command and default user settings; there was no replacement of
the candidate command after setup. Allowed commands executed once; policy
blocks, missing interpreter/checker, hook crash and checker deadline cases
executed no marker. The three controls demonstrate limitations: disabled hooks,
a shorter host timeout and an unmatched tool each executed once. The deadline
case observed exactly one actual check start. A separate real MCP-only run
reported the candidate server connected while the policy-denied Bash marker
still executed once, confirming that tool availability alone is not interception.
These are named native host controls, not a beginner pilot or release certificate.

The first combined run exceeded its 120-second setup deadline under concurrent
test load. That failure is retained separately. A diagnostic allowed case with
a longer bound completed setup in 45.86 seconds, and the subsequent complete
nine-case run passed using the original bound. Profiling found full executable
rehashing at every shell mutation callback. A later correction retains native
input handles during each operation and rehashes when an operation resumes;
its whole-setup performance and integrated regressions require a new build.

The lifecycle dry-run regression passed with logging both enabled and disabled:
the fixture's files and directories were unchanged. PowerShell 7.6.6 native
testing against this binary and a separately pinned corrected hook passed 22
cases across redirected processes, real-terminal noninteractive invocations,
Enter and paste handling, missing checker/storage, unexpected checker exits,
recovery and exact multiline text. This is hook-source qualification on Unix,
not proof of a Windows terminal or a final packaged hook. A quick-exit Darwin
PTY cleanup failure was retained and fixed in the repeatable runner.

The Windows CI runner now inventories the actual compiled workspace harnesses
and runs the dashboard's nine tests under a disposable real standard account.
Its parser, inventory, result and process-bound contracts passed 26 local
checks. Native Windows logon, token, job, ACL and account cleanup remain unrun
until the next Windows job. Product refusal to start an elevated dashboard and
protected storage ACL checks are preserved.

### Retained shell input and packaged PowerShell candidate

Development binary `39f6acc9929cdb53fcd0f9a0b4d82187aadf8e6b50af54058085d40812e09d3a`
and nine linked test executables are retained under `retained-inputs-native-v3`.
The source capture is `retained-inputs-powershell-inputs-v3` on `24be3f28`; all
captured Rust and embedded asset hashes matched after linking. Strict workspace
Clippy with all targets and warnings denied passed on those sources.

All **445 selected tests passed**, with one existing ignore: 133 CLI unit tests,
274 core unit tests, five core compatibility contracts, four CLI compatibility
contracts, three receipt privacy cases, six shell helpers, eight profile lifecycle
cases, nine real dashboard API cases and the three corrected CLI integration
failures from the preceding candidate. The core selection's nested subprocess
results are not counted again. These tests include retained native input handles,
changed paths/content/permissions, resume rehashing, exact lease/precondition
binding and owned undo after an executable change.

The exact binary passed all eighteen complete embedded-browser workflows and
five separate delayed-response cases without a source-asset override. The
PowerShell hook materialized by this binary matched the reviewed hook digest
`9a8e1ef63e8d4a83618ffdda33ed3932037c30bc0d9300466059b1f53a14a35e`;
all 22 native Unix PowerShell 7.6.6 cases passed using those extracted bytes.
Native Windows terminal behavior remains separate.

The repeatable actual-host runner passed all nine recommended-setup cases, the
MCP-only boundary and retained-host reload observation on the same binary. It
used the native macOS ARM host 2.1.268 and normal isolated user settings. Complete
setup operations took 6.933–24.918 seconds under the unchanged 120-second bound;
these measurements include process cleanup and are not release performance
budgets or a controlled before/after comparison. Every requested setup step
completed and every executable, interpreter, alias and harness postcheck matched.
In the reload case, the next turn 0.003 seconds after publication omitted the
hook and executed once. The same host blocked after a policy recheck, 2.107
seconds after publication; a fresh host also blocked. This does not establish
immediate or universal hot reload. The evidence manifest is
`claude-repeatable-native-v3`, digest
`a4efd68cd64b22467fafe6a721523fd6ac12c337378136b97c16a95af8da6edd`.

The repeatable mixed-audit runner passed six native cases against the signed
official macOS 0.4.2 baseline: signed and unsigned sequential rotation, two mixed
concurrent-writer bursts, and an actual legacy descriptor held across completed
rotation. The rotator was paused only after observed lock ownership, the old
writer's open log descriptor was observed before truncation, and the unchanged
rotator resumed. Active inode identity remained stable, retained archive bytes
matched exactly, and both clients verified the archived and active chains. Undo
after later appends and rotation without the signing key refused without changing
the active log. Public fixture signing keys were removed after each case.
The runner and its 20 process/format/cleanup fixtures are registered under
`tools/qualification`; fixture results do not substitute for native client tests.

Subsequent public receipt-reader consolidation and private-input execution
qualification refusal have independent source review. A native package-backend
investigation invalidated the assumption
that read-only private mounts establish complete input-lifetime protection
against another same-user process. The experimental metadata/uv extensions are
not registered. Package execution is restricted at public and hidden
launch boundaries; ordinary capsules and static inspection retain separate
capability requirements. No earlier package primitive result qualifies this
unresolved boundary.

### Public receipt APIs and package qualification refusal

Development binary
`1a72833d6d2f8b3dffa13a57259c3b73c8856cc96661bf2937ceab89b0a6a936`
and seven linked test executables are retained under
`receipt-qualification-native-v4`, with source capture
`receipt-qualification-inputs-v4`. Strict workspace/all-target Clippy passed.
The captured core source hashes matched after linking; CLI sources matched
when its executables were retained, before the subsequent help-copy changes.

All **349 selected tests passed**, with one existing ignore: 253 core receipt
tests, 72 CLI package/checkpoint/receipt tests, twelve public package/inspection
and hidden-launch integration cases, five core compatibility contracts, four
CLI compatibility contracts and three receipt privacy cases. Nested subprocess
results are not counted again. Direct public Rust readers now share record,
inventory and cache bounds and requested identity checks; tests include wrong
embedded IDs, oversized records/inventories, symbolic links, mixed historical
schemas and cached-byte changes. Inspection remains separate from signature or
content verification and publication authority.

Valid public package-install requests refuse before resolver/network,
quarantine, checkpoint and execution effects in both supported output formats.
Private hidden launcher operands also refuse. Opt-in flags and administrator
access do not bypass qualification; ordinary capsule parsing and static artifact
inspection retain their own contracts. The focused refusal is also proposed
against current main in [PR 254](https://github.com/sheeki03/tirith/pull/254).
The cycle candidate results do not certify that separate branch.

The Windows runner now creates current-account children suspended, assigns them
to an owned kill-on-close Job, and resumes only after assignment. Both success
and expected-refusal results require confirmed leader reaping, an empty Job,
complete output drainage and no process/cleanup errors or descendant leak.
Independent review and 45 portable parser/process contracts passed, including
nineteen cleanup-result regressions. Native Windows process, token, handle-list,
logon, ACL and account cleanup behavior still requires the platform CI run.

The subsequent help-only CLI candidate
`7823f71e6a2523163241a49e47daf37a7cc44e1336a08e0bb87002f419822ad4`
retains source capture `help-claims-inputs-v5`; all captured Rust and embedded
asset hashes matched after linking. The complete help suite and selected public
package refusal, hidden launcher and static inspection integration checks passed.
No package execution path was enabled by the help/documentation corrections.

A repeat of the six native mixed-audit cases on candidate `1a72833` passed five;
the unsigned held-writer case failed when its native descriptor observer exceeded
the unchanged three-second deadline during compilation load. That failed report
is retained separately from subsequent runs. Observation timeout does not count
as a completed descriptor-crossing proof.

### Authenticated canonical status and stricter native observations

Source commit `897bad30` incorporates main through `d121b57c` and remains version
0.4.2. Its Linux, macOS and Rust 1.83 workspace jobs passed. The macOS installer
job initially failed downloading the pinned checkout action before repository
execution; its rerun passed. Windows Cargo completed compilation, but the owned
Job retained a descendant after the ten-second grace. The runner terminated it,
confirmed cleanup and failed qualification before workspace harness execution.
The preserved artifact digest is
`53a201147f86a5af8591cf18c22d6744ff2e49095d827eb80314bc75aa077de9`.
New bounded Job diagnostics preserve the leader exit separately and record held
member identities before cleanup. All 45 portable contracts pass; identifying
the actual Windows survivor and completing native tests remain required.

Development binary
`fad9af58fa5ba5e902d61e1571b7d934645d3bce5b07b15136247014f9714f39`
is retained as `authenticated-status-native-v7`, with source capture
`authenticated-status-inputs-v7`. Captured Rust hashes matched after linking.
Strict workspace/all-target Clippy passed. All 51 selected runtime tests passed:
thirteen core verification tests, thirteen CLI status/evidence/helper tests,
twenty status integration tests and five real Bash/Zsh/Fish terminal cases.
Two compile-fail proof doctests also passed. The helper's canonical status now
consumes an opaque, one-use proof after status collection and revalidates live
shell identity, context, loaded definitions and original evidence expiry.
Ordinary status and background dashboard reads remain unverified. This does not
qualify automatic activation or new PowerShell/Nushell receipt adapters.

The shared native qualification helper now retains the waitable child until
owned-group signaling and native membership observation finish, then reaps once.
It refuses unsupported runtimes and never signals a saved group after reaping.
Twenty-nine fixture tests passed on macOS/Python 3.14 and in a native Linux ARM
container as an ordinary user. The helper certifies only its owned process group;
descendants that escape the session and close inherited pipes are outside scope.
Earlier reports lack the new `group_members_exited` proof and remain historical.

On the exact `fad9af58` binary and final helper
`913a3499bd78b39c6870b9dc280fcaad8a49739db7f2781bbfe914ff4db12e75`,
all six signed/unsigned mixed-version audit cases passed again, including actual
legacy descriptors held across rotation. The report digest is
`c5a6f11c750b30f415dad172ba3aceb235913d1168d6590df946895db871cc0f`.
All 32 paired policy, trust, inherited-shell-mode and download-receipt reader
cases passed against the separately authenticated 0.4.2 baseline; report digest
`854c90c1ca7795431604b9ddc14fad53149993abc1359ea9278e28e7f534b2c7`.
Both runs retained all four cleanup facts and unchanged input hashes. The compact
reader fixture records observed contracts, with explicit synthetic-input scope;
it does not certify receipt creation, signatures or publication authority.

Resource qualification now validates measured units, sample counts, raw timing
distributions, memory/CPU observations and exact source/host/report context.
Twenty validator fixtures and three accounting fixtures passed. CI records
`validated_unbudgeted`; no new limits are enabled until at least three independent
pinned release distributions and runner variance support reviewed thresholds.
The existing Criterion budgets retain their separate scope.

The reviewed process-death runner then passed all fourteen native cases on the
same `fad9af58` binary. Eleven stopped boundaries exactly matched the requested
stage with a running/applying journal and observed held locks. Ten cases killed
the actual owner with SIGKILL; all 112 commands retained complete cleanup facts.
Recovery preserved audit inode identity and exact archive/head bytes, refused a
concurrent owned policy edit, and retained intended profile publication across
retry. Real ordinary-user EACCES and RLIMIT_FSIZE/EFBIG failures preserved verdicts
and exposed append failures; the mismatched audit head was explicitly refused.
All 27 runner fixtures passed on macOS and in a native Linux ARM container.
The native report digest is
`a5c6c3ff61824a9a908ebb6b4fcc16395bcbd338454cd4a8ea33f48f757c195e`;
evidence manifest `durable-boundaries-reviewed-native-v7` has digest
`dfe4f544ea016af592faa3d6662616c59d6290789bc8ebf5eaece4b0eb432bbc`.
This qualifies the named macOS process-death/storage cases only. Power loss,
actual ENOSPC, every write boundary, signed recovery, Windows and signed binary
publication still need separate evidence.

### Managed policy, setup intent and curl diagnostics

The ordinary macOS ARM development candidate
`d9e3ce9ed178e3405f5865c811b30ead4a78378ae34bc5ac946b74bfcbf408ca`
is retained as `managed-exact-undo-native-v14`, with source capture
`managed-exact-undo-inputs-v14`. Strict workspace/all-target Clippy passed.
All 64 focused harness tests passed: fifteen setup-binding fixtures, four
recommended-setup fixtures, 32 journal tests, nine rollout lifecycle tests and
four reader-contract groups covering sixteen CLI cases. The preceding candidate
also passed the six unchanged managed-authority, rollout API and rollout-unit
checks. These counts do not count nested commands as additional unit tests.

The actual embedded dashboard passed all six managed-policy browser checks:
public launcher reuse of an identified owned service, explicit organization
review without executing representative commands, complete materialized policy
agreement with the CLI, exact original-document rollback, refusal after a later
organization edit, and actual service exit with all four native cleanup facts.
The run used Chromium 149.0.7827.55 and PyYAML 6.0.3; no asset override was used.
Seventeen independently reviewed harness fixtures passed. Both resulting views
were visually inspected. Remote publication, fleet adoption, Windows managed
writes and first detached dashboard launch are outside this journey's evidence.

The stronger rollback check initially failed on candidate
`27f732345d81ff7ce80178d14903d6330c03a39c3a7360aa191393b2b2323726`:
an empty `severity_overrides` map remained after reported undo. Both failures
and the actual residual document are retained. Managed rollback now restores
the original bytes only after complete-generation checks; personal rollback
continues preserving unrelated later edits. No existing completed journal is
silently replayed or repaired. Three additional native restart fixtures pass
across four compensating-state scenarios: before publication, after exact
restoration, and later edits to either generation. These simulate persisted
restart boundaries; they do not inject a process death. The separately retained
`managed-undo-restart-native-v15` harness has digest
`8bca36e9aab46656cb79731b3cacbd3cd7dd41623ca150deaeec6d25664d3135`.

Recommended setup now retains a private versioned verification intent even
when no files change. A completed-file lease holds operation ownership, native
input identities and complete planned postimages while revalidating policy,
cancellation, undo and drift. Its public request scope is
`fresh_terminal_activation`; it is not an execution or protection proof.
Historical file-only records never acquire startup behavior on replay.
Automatic verification in the real newly opened terminal remains under
implementation; no new automatic shell row is certified by these fixtures.

The focused current-main curl correction is [PR 256](https://github.com/sheeki03/tirith/pull/256),
head `3998ed261b08db782811c03c6293784b5e149058`. All seventeen new native
extraction/diagnostic regressions and 5,744 core unit tests passed, with two
existing ignores. CI Clippy, Rustfmt and the Windows workspace job passed;
other platform jobs were still running at this snapshot. The fix distinguishes
numeric URL operands from real option values, retains original host spelling,
and excludes userinfo from host evidence. Existing special-scheme empty-hex
curl/generic-parser differences remain a separately tracked authority issue.

The Windows controller's temporary telemetry policy did not stop the actual
owned MSVC helper in `aa530138`. Commit `012a4d59` instead selects and retains
explicit LLVM C/archive/linker inputs for the Windows MSVC ABI job. All 62
portable contracts pass. Native compilation and doctests now pass with complete
owned-process and pipe cleanup. The subsequent test run exposes Windows fixture
and account-setup failures; standard-account qualification remains open. Process
success, descendant, EOF and cleanup requirements are unchanged.

The first native release resource run validated 293 metrics without enabling
thresholds. Two later reference attempts refused a changed CPU class before
measurement. The separate EPYC 7763 cohort pins measured source
`150e753a0adf8f9f13c8cc2b38f7a9325de40d91`, tree
`53123b9d0aa615d4135ce6c42f37abe6a5cdca16`, compiler, manifests and 100 samples;
workflow/event revisions are recorded separately. The first admitted 100-sample
reference, run `34709899626` attempt 1, passes all 293 metric validations. The
retained artifact digest is
`39da04ffc040767bac371c0dd0944b2ba0d5a3e14093982aaa66949d381b679d`;
local reevaluation is byte-identical to the CI evaluation. Two further independent
admitted measurements and reviewed limits are still required. CPU classes are
not pooled.

### Fresh-terminal completion clock and closed protocol

The private completion path now retains one native clock stamp after the exact
setup-file postconditions have been observed. Existing completed records return
before capture, so retry cannot make an old shell appear newer than setup. The
stamp marks observed file completion before durable journal acknowledgment; it
does not claim the shell started after the UI reported completion. Changed,
cancelled or undone setup is rejected again by the retained file lease.

An opaque core context authenticates the current process's direct parent through
its protocol-v3 capability, native start/UID identity and executable. It is not
serializable or clonable, and revalidation rejects use from another process.
Three native context fixtures passed. Linux freshness uses a conservative tick
ceiling and explicitly checked zero time-namespace coordinates; macOS compares
raw Mach process-start ticks within the same boot/timebase. Persisted clock data
alone is never activation authority or interception proof.

The retained `activation-protocol-native-v19` harness passes all 67 selected
CLI tests, including native-clock, completion/replay, journal, recommended-setup
and closed-frame contracts. Strict workspace/all-target Clippy passes. The Mac
Mach binding matches the retained SDK ABI and avoids deprecated libc wrappers.
The scheduler protocol permits only fixed stages, canonical IDs and closed
refusal reasons; no command, executable path or endpoint can appear in a frame.
A `complete` scheduling frame is not a protection proof.

Actual automatic activation remains unavailable while the direct-child broker,
setup-bound core challenge mode, foreground deadlines and real installed Zsh
hook journey are connected and qualified. Separate disposable Zsh mechanism
experiments do not certify those product paths. Ordinary status and dashboard
reads continue to report their own unverified scope.

### Windows follow-up at 11689356

The Windows workspace run 34746043256, job 103694063081, completed with failures.
Its retained artifact 10314501317 matched the API ZIP digest
`873d902e7c595361ccc8358bebd24c8300ff8d225bb39432c04d6f4d262a99ca`.
LLVM compilation and doctests completed with all native Job, leader and pipe
cleanup gates passing (1,207 and 17 total processes respectively). The real
standard account launched with medium integrity and no Administrators membership;
all nine dashboard tests then failed ancestor ACL validation. The ordinary core
harness passed 5,416 tests with one failure and one ignore; the CLI passed 1,544
with ten failures. Other ordinary harnesses passed.

The remaining C-volume ACL failure is an explicit create-subdirectory right at an
intermediate ancestor. Directory guards now distinguish that case from a terminal
parent: the exception requires the next child to be independently validated and
held without delete sharing. Terminal directories, private leaves, deletion,
replacement and security-changing grants retain their existing restrictions.
Native disposable-chain fixtures cover the distinction and guard release.

The build-file failure admitted a mixed digest of two different same-size file
generations. Windows build hashing now selects a capability-relative read lease
that refuses existing writable handles/mappings and denies new writers throughout
the read. Existing identity, generation, size and second-walk checks remain.
Native fixtures cover a real mid-chunk write attempt, existing writer/mapping
refusal and successful writes after lease release. These corrections require a
new Windows run; the preceding successful process cleanup does not certify them.

### Windows follow-up at 82389acc

Run 34748687259, job 103701238877, completed with failures. Artifact
10315217919 matched its API ZIP digest
`e4320adbd010a28271d2426febabd926d95afde28cec27b92a40f62874ed0781`.
LLVM compilation and doctests passed with all owned cleanup gates (1,207 and
17 total processes respectively). The core passed 5,419 tests with one ignore;
the CLI passed 1,563 tests with two failures. Stable build hashing and its native
read-lease cases now pass. Both CLI failures show directory renames succeeding
while a guard is held. Metadata-only Windows access does not participate in
delete-sharing exclusion; control guards now request directory read access on
every retained ancestor and leaf. Focused cases check sharing violations,
preexisting delete handles, compatible readers and release.

The first real standard-account dashboard test timed out at 840 seconds. The
native Job contained four active processes of five created; this alone cannot
identify whether the remaining Tirith process was the launcher or service.
All cleanup gates passed. Source review found unrestricted inherited handles in
the service spawn path, which can retain a launcher's captured pipe writers.
That defect is being corrected with an explicit handle list; its role in this
particular timeout and all nine dashboard tests require native revalidation.
These remaining failures keep Windows qualification open.
