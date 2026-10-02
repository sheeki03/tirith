# Local dashboard

The dashboard is a local web page for checking and changing your own Tirith
setup. It runs on your computer only, needs no account, and loads no fonts,
scripts or other content from the network.

## Open it

```sh
tirith dashboard
```

`tirith dashboard` (the same as `tirith dashboard open`) starts the local
service, or reuses the one already running, and opens your browser.

- Add `--no-browser` to print the private local URL instead of launching a
  browser.
- Add `--json` to get the launch result as JSON. It includes `single_use_code`
  and `code_expires_in_seconds`.

The URL carries a single-use sign-in code that expires after 2 minutes. The page
exchanges it once for its own browser session and CSRF value. Each launch,
including a reopen of a running service, gets a fresh code and a fresh one-hour
session counted from sign-in. When the session expires, run `tirith dashboard`
again. The service stops on its own after 30 minutes without activity.

## Pages

- **Overview:** what is configured and what has actually been observed, with
  the next action to take. Run an explicit [project review](project-review.md)
  or [inspect an npm tarball](npm-inspection.md) in the service's project
  directory.
- **Activity:** recent recorded checks, newest first, with older pages on
  request. Label an operation as expected or unexpected; a label is review
  metadata and never grants trust.
- **Protection:** compare the Comfortable, Balanced and Strict profiles and
  change personal settings. Every change shows a preview first. See
  [profiles and settings](profiles-and-settings.md).
- **Exceptions:** list, explain, shorten and revoke [trust grants](trust-grants.md).
- **Integrations:** shell and agent integrations and their state.
- **Settings:**
  - the running version and install channel, with the exact upgrade and
    rollback command to copy into a terminal;
  - **Refresh threat DB now**, which runs the same signed update as
    `tirith threat-db update` and shows [freshness](threatdb-freshness.md);
  - [team policy](team-policy.md) connection, activation, rollout review and
    reports;
  - saved changes and recovery (status, retry, cancel and undo of every saved
    operation);
  - a support report built only from the incidents and saved changes you
    select, previewed and downloaded with fresh redaction;
  - audit segment retention: rotate, export and delete retained segments.

Every change goes through a typed plan that you review and apply, and is saved
with an operation ID. Closing the tab does not cancel an accepted job; inspect
the saved operation before retrying (`tirith policy operation OPERATION_ID`).

## The older HTML report

`tirith dashboard export` writes a static HTML security report to a file, and
`tirith dashboard serve` serves that report on loopback with an ephemeral token.
Both are unchanged; see `tirith dashboard --help`.

## Limits

- The dashboard is a configuration view. It cannot observe that the shell you
  are typing in blocks commands; run `tirith doctor --verify-shell` in that
  shell for that.
- It never replaces the Tirith binary, asks for credentials or elevates. Binary
  updates stay in the terminal.
- "Refresh threat DB now" refuses a redirected database path, an
  administrator-owned data directory, the root account, and a remote policy
  that forbids local changes. Only one refresh runs at a time.
- Read-only views (state, integrations, activity, history, freshness,
  operation status and the job list) never contact a policy server. The
  effective-policy view and applying or undoing a change resolve the full
  policy, which can.
- Keep the URL private. On Linux, connections from another ordinary account
  are dropped before they are served. Other platforms have no API for the owner
  of a loopback connection. Root-owned clients and clients missing from the
  kernel's socket tables are still served (a Windows browser reaching a WSL2
  dashboard through the localhost relay, and WSL1), and still need the sign-in
  code.
- The browser cannot choose file paths or send arbitrary file contents.
  Project review and artifact inspection use the service's own project
  directory; a replaced directory requires reopening the dashboard.
- Saved project-review reports live in the service process: at most four, each
  recheckable for ten minutes. Restarting the service requires a fresh review.
- A request whose headers take longer than 1 second is cut off. At most 8
  connections are served at once.
