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

`tirith dashboard export` writes a static HTML security report to a file; it
is unchanged. `tirith dashboard serve` serves that report on loopback with an
ephemeral token, as before, but now uses the dashboard's loopback transport and
handles HTTP more strictly: a request head must arrive within 1 second, an
absolute-form target with a non-loopback authority gets 403, user info in the
target gets 400, a request that may carry a body closes the connection, and at
most 8 connections (8 requests each) are served at once. It also refuses some
requests 0.4.2 answered: a tab anywhere in the request head, a header name with
a character other than a letter, digit or `-` (for example `X_Foo`), trailing
whitespace or extra words on the request line, a target longer than 2048 bytes
or a path starting with `//` or containing `\` all get 400; a method token
longer than 16 bytes gets 405; and a request head larger than 64 KiB gets 431.
It differs from 0.4.2 in a few more cases: a target containing `#`, any other
ASCII control byte in the request head (or a bare LF inside the request line or
a header value), and an HTTP version other than `HTTP/1.0` or `HTTP/1.1` get 400
and close the connection, where 0.4.2 served `HTTP/0.9` and answered
`HTTP/2.0` and `HTTP/3.0` with 505 on a kept-open connection; leading
whitespace before the method gets 405, where 0.4.2 trimmed the request line;
an `Expect` value other than `100-continue` is ignored, where 0.4.2 answered
417; and responses still carry a `Date` header but no longer the `Server`
header tiny_http added. Every 405 carries `Allow: GET, HEAD` and says the
method must be a token of 1 to 16 bytes. Ordinary browser and `curl` requests
are not affected. See `tirith dashboard --help`.

## Limits

- The dashboard is a configuration view. It cannot observe that the shell you
  are typing in blocks commands; run `tirith doctor --verify-shell` in that
  shell for that.
- It never replaces the Tirith binary, asks for credentials or elevates. Binary
  updates stay in the terminal.
- "Refresh threat DB now" refuses a redirected database path, an
  administrator-owned data directory, the root account, a remote policy that
  forbids local changes, and a refusal by the task gate (`self_update`
  boundary; under `task_gate.mode: enforce` with
  `action_incomplete_analysis: block` it is always refused). Only one refresh
  runs at a time.
- Read-only views (state, integrations, activity, history, freshness,
  operation status and the job list) never contact a policy server. The
  effective-policy view and applying or undoing a change resolve the full
  policy, which can. With a legacy remote policy server configured, the
  exceptions list and explain also resolve the full policy when a local policy
  input has changed since the cached snapshot or no full resolution has
  finished yet, so they can contact it too.
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
