# Beginner pilot record

Status: prepared; no participant session or release acceptance is recorded here.
This is the human-use portion of WP19/G1. Automated shell, browser and host
fixtures establish separate technical evidence and cannot complete this record.

## Candidate and participation

Before a session, identify the exact candidate archive, executable digest,
installation channel, OS, shell and selected agent version. Use only a tuple
with passing native evidence in the [acceptance matrix](acceptance-matrix.md).
A later source build or another agent version requires its own qualification.

The participant must explicitly agree to try the candidate, the changes to the
chosen test account/project, the observations being recorded and any sharing.
Use a disposable account or project with no credentials or confidential input.
Keep observations local unless the participant deliberately agrees to share
them. Record consent and withdrawal without collecting unnecessary identity.

Give the participant the [everyday workflows](user-journeys.md), the selected
artifact and an ordinary task. Record where they need help before supplying
instructions. Do not run the steps on their behalf and call that an independent
beginner result. Stop and restore only unchanged owned state if they withdraw
or encounter an unsafe or confusing outcome.

## Session record

Use a fresh copy for each participant and exact candidate. `Not attempted`,
`needs help`, `failed`, `unsupported` and `completed` are distinct results.
Elapsed times describe that session; they are not a performance budget.

| Field | Recorded value |
| --- | --- |
| Pseudonymous session ID and date | Not recorded |
| Agreed scope and local recording consent | Not recorded |
| Candidate revision/archive/executable SHA-256 | Not recorded |
| OS, architecture, account privilege and installation channel | Not recorded |
| Shell and selected agent versions | Not recorded |
| Relevant passing native evidence | Not recorded |
| Prior experience and help supplied | Not recorded |
| Withdrawal, failures and retained local evidence | Not recorded |

| Journey | Observation required | Result |
| --- | --- | --- |
| Install and protect terminal | Ordinary user completes recommended setup without YAML edits; required fresh terminal is clear; harmless allow executes once and inert block never executes | Not attempted |
| Ordinary work | Participant completes the agreed task and distinguishes an advisory, confirmation, block and analysis limitation when encountered | Not attempted |
| Protect selected agent | Participant understands restart and coverage limits; the actual qualified host withholds the inert blocked operation | Not attempted |
| Resolve a legitimate interruption | Participant can read all remaining blockers, review a narrow applicable change and recheck the exact intended command | Not attempted |
| Profile or exception change | Browser and CLI agree on effective scope and restrictions; participant can find the change and its expiry or owned undo | Not attempted |
| Inspect project and support information | Participant understands skipped/unsupported coverage and previews redacted support data before deciding whether to share | Not attempted |
| Upgrade | An actual eligible later candidate is installed through the owning channel, settings persist, and required integration reload is understood | Not attempted |
| Remove | Owned configuration is removed without deleting unrelated edits; a fresh terminal no longer loads the hook; retained data choices are understood | Not attempted |

The upgrade row needs two actual eligible versions and their verified artifacts.
A same-version fixture-key swap cannot fill it. A channel awaiting publication
or external review remains pending rather than being substituted with a local
copy. No elevation is needed for ordinary protection; record whether optional
privileged approval guidance is understood when that feature is unavailable.

For every problem, retain the participant's description, the visible state,
minimal redacted evidence, assistance supplied and the eventual result. An
“expected operation” label reports friction and is not permission to weaken a
security decision. Link a fix and a fresh check to each actionable failure.

## Acceptance

A maintainer reviews the session against the recorded candidate and all eight
journeys. Any unsupported selection, unattempted journey, unexplained failure,
missing artifact identity or absent consent stays visible. Record who reviewed
it and the result; do not infer sign-off from a merged PR. Combine accepted
human evidence with final package/platform checks and the channel report in the
[release checklist](../release-checklist.md) before declaring G1 complete.
