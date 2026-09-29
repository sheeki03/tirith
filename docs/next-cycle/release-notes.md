# Next-cycle release notes draft

Unreleased. These notes describe the integrated product at `e2c94439` for release
review. The workspace remains 0.4.2; a candidate version and publication date have
not been selected. They will become a versioned release-notes file through the
[release checklist](../release-checklist.md).

## Personal protection and controls

Recommended setup combines an explicitly selected shell with a personal
protection profile. Comfortable, Balanced and Strict profiles preserve manual
settings and cannot weaken mandatory policy. Fresh-shell verification reports
observed blocking separately from configuration that still needs activation.

The CLI and authenticated local dashboard share policy sources, change previews,
saved operations, cancellation, retry and owned undo. Scoped exceptions retain
their target and expiry; resolving one finding leaves other blockers visible.

History and support tools report incomplete coverage, bound their reads and
apply current redaction to selected exports. Sharing remains deliberate. Update,
rollback and removal preserve unowned configuration and distinguish saved state
from freshly loaded protection. Use the [everyday workflows](user-journeys.md)
for setup, agent protection, interruption recovery, inspection and maintenance.

## Elevation and optional team policies

Ordinary user installation and protection require no sudo or administrator
session. Native packages no longer require or suggest sudo. Privileged package
approval is off by default; status explains when its prerequisites are missing
and which capability is unavailable. System-wide package-manager destinations
still follow operating-system permissions. Elevation cannot enable unsupported
containment or general package installation.

Teams can optionally bring their own policy server. Explicit enrollment,
authenticated publication, reviewed activation, rollback and client reports
preserve policy authority and distinguish missing or stale clients. Personal
protection requires no server; publishing a policy does not prove adoption.

## Inspection

Project review and local npm inspection/comparison report inspected identities,
skipped inputs and incomplete analysis without executing package scripts.
To check an npm package before installing it, use `tirith install npm <pkg>`
(analyze first, then run npm) or inspect a local tarball with `tirith pkg
inspect` and compare releases with `tirith pkg diff`. General npm/Python
`pkg install` remains disabled.

## Reliability fixes

- Preserve fish's inherited umask while retaining private capture files (#265).
- Avoid phantom repository policies on Unix virtual filesystems when bounded
  enumeration proves the apparent names absent; genuine policy errors retain
  conservative handling (#266).
- Correct independent shell receipt sessions (#257), numeric curl diagnostics
  (#255), and supported bracket, arithmetic and Python data-pipeline analysis
  (#260 and parts of #264). Unresolved executable identity remains explicit.
- Correct Windows PowerShell profile/process queries and standard-account
  dashboard coordination, and preserve the release libc/ABI during updates.
- Fix Android clipboard/errno compilation based on @uspourmirza-boop's #262;
  Android/Termux device runtime remains unverified (#261).

## Validation and release status

CI, native ARM, release validation, fuzz and benchmark workflows pass on the
recorded integrated product. The local-leaf npm install contract was retired
before release; `tirith install npm`, `pkg inspect` and `pkg diff` remain.
Exact artifacts, platform limits and earlier corrected failures remain in
[verification](verification.md) and the [acceptance matrix](acceptance-matrix.md).

Production v2/provenance publication and publisher recovery, final official
channel checks, and the consented beginner pilot remain release gates. The
[channel record](channel-report.md) tracks public availability separately from
development builds. No new release or registry version is announced here.
