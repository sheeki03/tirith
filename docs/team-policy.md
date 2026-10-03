# Team policy

Run your own policy server, publish one reviewed policy for your team, and enroll each device explicitly. Personal protection works without a server. Team policy is off until a user activates a saved connection on that device. Connecting, fetching, reviewing and publishing are separate actions; none enrolls another device.

Tirith includes a separate `tirith-policy-server` executable. Run it on infrastructure your team operates, or implement the documented Tirith policy-management API on an existing service. An arbitrary file server is not sufficient: reviewed publication, concurrent-update checks, rollback, authentication and client report reconciliation require the API contract in [the server guide](../tools/policy-server/README.md).

The server runs under an ordinary Linux or macOS account. It does not install a privileged service or require sudo. Windows clients connect to a server on a supported host.

## Host the authority

Build the optional executable with `cargo build --release -p tirith-policy-server`. Choose an existing private directory you own. The data directory passed to `init` must not exist yet; its parent must already be private. Use absolute native paths, including `/private/tmp` instead of the macOS `/tmp` alias for temporary experiments.

```sh
tirith-policy-server --data-dir /absolute/private/authority init --policy /absolute/private/policy.yaml
tirith-policy-server --data-dir /absolute/private/authority serve --listen 127.0.0.1:8778
```

Initialization prints the authority ID, policy ID, revision and roster revision. Keep the authority and policy IDs for connection verification. Put an operator-managed HTTPS reverse proxy in front of the loopback listener. The client requires certificate verification even when the server is on a private network. An ordinary account can use a TLS port above 1024; exposing a system port or configuring a system service follows the host's permission rules.

Do not log bearer credentials or request/response bodies at the proxy. Restrict network access to the intended team.

## Choose credentials for each job

| Role | Permitted work |
| --- | --- |
| Publisher | Read policy, review/publish/roll back policy, inspect fleet reports |
| Observer | Read policy and inspect fleet reports |
| Client | Fetch policy and report only its registered client identity |

Use a distinct credential for each operator or client. Credentials expire explicitly, at most 90 days after issuance. A stable principal UUID identifies the same operator across credential rotation. A Client credential also binds one registered client UUID. Tokens are written only to a new private file and are never printed. See the server guide for issuance, revocation and rotation commands.

## Save an optional connection

On the intended machine, save the credential in a private file owned by the current user. Then authenticate the exact authority and policy:

```sh
tirith policy team connect --server-url https://policy.example.test:8443 --authority-id AUTHORITY_UUID --policy-id POLICY_UUID --credential-file /absolute/private/client.token
tirith policy team status --refresh
```

For a private CA, additionally pass `--private-ca-file /absolute/private/team-ca.pem`. For a deliberately private LAN or tailnet endpoint, select one to eight distinct addresses with repeated `--address IP_ADDRESS` options. For example, add `--address 10.20.30.40` while keeping `--server-url https://policy.example.test:8443`; the address does not replace the certificate hostname. The client connects only to those explicit addresses while still verifying the configured HTTPS hostname and certificate. Cloud metadata, link-local, unspecified and other prohibited address classes remain refused. Without explicit address selection, public-endpoint DNS admission applies. Redirects and ambient HTTP proxy settings are not used.

An identical connection is unchanged. Replacing an existing connection requires its current `--expected-connection-id`. A saved connection does not activate policy. `tirith policy team status` reads local selection; only `--refresh` authenticates over the network.

## Activate one client

Use a Client credential on this machine. Activation fetches policy, validates the complete composition with local restrictions, and saves the exact private cache for Runtime:

```sh
tirith policy team enrollment activate --expected-connection-id CONNECTION_UUID
tirith policy team enrollment status
tirith policy team enrollment sync --expected-connection-id CONNECTION_UUID --expected-activation-id ACTIVATION_UUID
```

Activation and sync do not send Applied reports. Commands read the enrolled local cache and never contact the team server. Repository restrictions and the ordinary local overlays still apply.

Touching or changing the permissions of the saved connection file does not invalidate an activation. Replacing the file with a different file (even one with the same bytes) does; activate again. The activation binds the file's index on its volume and, on Linux, its birth time, so a replacement that reuses a freed inode number (as ext4 does) is still a different file. On macOS, setting the file's modification time to before its creation time also moves its birth time; tirith does not bind birth time there, so this does not matter.

### Automatic refresh and the offline grace period

You do not have to run `sync` by hand to keep the cache current:

1. **Fresh (under 24 hours).** Runtime enforces the cached team policy.
2. **Background refresh (after 1 hour).** When `tirith check` sees a cache that is at least an hour old, it starts a detached `tirith policy team enrollment sync` child and continues immediately. The command never waits for the network. At most one refresh is started per 15 minutes per user, and only one runs at a time. `--offline` and `TIRITH_OFFLINE=1` disable it. The child uses the same checks as a manual sync: it only refreshes the exact current activation and connection, so it cannot re-enable a withdrawn activation. Only `tirith check` (the shell and agent hooks) starts this refresh; the MCP server and gateway enforce the cache but never start one. The cache is per user, so a hook refresh also covers them, but a setup whose only traffic is the MCP server or gateway needs a periodic `tirith policy team enrollment sync` (for example from cron) to stay out of the grace period.
3. **Grace period (24 hours to 24 hours + grace).** If no refresh has succeeded, Runtime keeps enforcing the last-known-good team policy and prints a warning on every command that says how old the cache is and when enforcement ends. A long-running process (the MCP server or gateway) prints it once.
4. **Expired (after the grace period).** Every command is blocked (fail closed) with a message that explains how to sync or leave team policy.

The grace period is 72 hours by default. The team authority sets it in the published policy with `team_offline_grace_hours` (0 to 720; 0 blocks commands as soon as the cache is 24 hours old). The value is read only from the team policy document; a local or repository policy cannot extend it.

```yaml
# In the team policy you publish
team_offline_grace_hours: 24
```

`tirith policy team enrollment status` shows the activation and connection IDs, and while the cache is usable its `fetched_unix_ms`. Its `offline_cache` field says which of the stages above applies: `state` is `fresh`, `grace`, `expired` (fail closed), or `future_timestamp` / `missing` / `invalid` (also fail closed), with `fresh_until_unix_ms`, `grace_hours`, `grace_until_unix_ms`, `time_left_ms` (until the next stage, or until fail closed during grace), `refresh_due`, `enforced`, `fails_closed`, `runtime_refused` and a one-line `summary`. `state` describes only the cache age: when the top-level `state` is `runtime_refused` (for example a competing `TIRITH_SERVER_URL`/`TIRITH_API_KEY`, an organization policy, a legacy `policy_server_url`, or a changed connection file), `runtime_refused` is `true`, `enforced` is `false` and `fails_closed` is `true` even for a fresh cache. Without `--json` the summary is also printed on stderr. To refresh immediately, run `sync` as shown above.

### Competing policy authorities

An enrolled device refuses a second managed authority instead of guessing which one wins, and every command is blocked until one is removed. Each case prints what to change:

- `TIRITH_SERVER_URL` and `TIRITH_API_KEY` are both set: unset them in that environment. `TIRITH_SERVER_URL` on its own is not an authority and does not conflict.
- The trusted local policy sets `policy_server_url` (with a stored or ambient API key): remove `policy_server_url` and `policy_server_api_key` from that file.
- An organization policy is installed: the organization operator removes it.

In every case you can instead leave team policy with `tirith policy team enrollment disable --expected-activation-id ACTIVATION_UUID`, which works offline. Tirith does not silently prefer the team policy over the other authority, because that authority's policy may be stricter.

To turn team policy off, withdraw the exact activation. This works offline and does not require a fresh cache or working server connection:

```sh
tirith policy team enrollment disable --expected-activation-id ACTIVATION_UUID
```

If enrollment bytes are malformed and no activation ID can be safely read, explicitly remove only the currently malformed record:

```sh
tirith policy team enrollment repair --remove-malformed
```

This offline action captures one bounded private record and retains its native identity through deletion. It refuses a valid enrollment, unsafe storage, or a changed record. It does not salvage fields from malformed JSON, infer an activation ID, or use a status token from an earlier process. The browser requires a separate acknowledgment for this removal. Connection and report records remain intact.

Disconnecting a connection is a separate action and does not withdraw enrollment.

## Review and publish policy

Use a Publisher credential on the publishing workstation. Prepare a review with representative workflows:

```sh
tirith policy team rollout prepare --policy-file /absolute/private/candidate.yaml --command 'git status' --command 'npm test'
tirith policy team rollout show OPERATION_UUID
tirith policy team rollout publish OPERATION_UUID --reviewed REVIEW_UUID
```

The review records its scope, supplied workflows, unavailable evidence, and known exception owners and expiry. It does not approve commands or exceptions. Publication requires the exact reviewed operation, unchanged relevant local inputs and the current server revision. A concurrent publication invalidates an older candidate. Local pending intent is durably recorded before the publication request.

If a response is lost, inspect the retained operation and explicitly refresh it:

```sh
tirith policy team rollout show OPERATION_UUID --refresh
```

Refresh reconciles the exact submitted intent and publisher identity without publishing again. An operation UUID by itself is insufficient to claim that the reviewed policy was committed.

Rollback requires a new review and explicit action. It is available for seven days while the original publication remains the current revision:

```sh
tirith policy team rollout rollback-plan PUBLICATION_UUID
tirith policy team rollout rollback ROLLBACK_UUID --reviewed REVIEW_UUID
```

Rollback creates a new revision from the retained prior policy. It does not overwrite later publications or undo local device activation automatically.

## Understand client reports

After actual local Runtime resolves successfully, a Client may explicitly send a report:

```sh
tirith policy team enrollment report --expected-connection-id CONNECTION_UUID --expected-activation-id ACTIVATION_UUID
```

The exact report is saved privately before sending. An uncertain response leaves the request pending. Explicit retry uses the same report ID, sequence and timestamp, and still requires matching current Runtime; it cannot turn an old or changed activation into a fresh Applied claim.

```sh
tirith policy team enrollment report --expected-connection-id CONNECTION_UUID --expected-activation-id ACTIVATION_UUID --retry-report-id REPORT_UUID
```

If Runtime has changed or the cache has expired, use read-only reconciliation instead of resending an Applied report:

```sh
tirith policy team enrollment reconcile --report-id REPORT_UUID
```

Reconciliation authenticates the same selected Client and compares the complete original request with the server's latest retained report. It works without a valid current cache or activation and never submits an Applied observation. A confirmed receipt is a historical fact.

An unresolved request can be explicitly archived locally before preparing a new report:

```sh
tirith policy team enrollment abandon --report-id REPORT_UUID --acknowledge-unknown-outcome
```

Abandonment preserves the exact request and its private context with an unknown server outcome. It neither cancels an in-flight request nor asserts no commit. A new report still requires actual valid Runtime and fresh authenticated server sequence. A late older request can win the server update race, leaving the new request in conflict; Tirith retains that exact request instead of inventing another sequence.

Status shows an opaque local archive ID for historical entries. To reconcile one explicitly, use `enrollment reconcile --report-id REPORT_UUID --archive-id ARCHIVE_UUID`. Without an archive ID, reconciliation selects the current stored report. Archive IDs distinguish different retained contexts if a never-confirmed sequence produced the same deterministic report ID again.

If storage reports an unconfirmed outcome (including retained Windows recovery), inspect the reported storage result and retained state before another explicit action.

A Publisher or Observer can fetch fleet status with `tirith policy team rollout fleet`. The roster includes all explicitly active registered clients and distinguishes unreported, stale, downloaded, applied-current, applied-older and failed reports.

The [dashboard](dashboard.md)'s Settings page has the same connection, activation, rollout review and reporting actions.

## Limits

- The server's private SQLite storage has no Windows implementation. Native
  filesystem and platform limits are listed in the
  [server guide](../tools/policy-server/README.md).
- The server has no public registration, browser login, payment or license
  service. It keeps a bounded set of policies, credentials and clients; when
  full it refuses visibly instead of forgetting replay history.
- Missing, changed or malformed enrolled policy fails closed; Tirith never falls
  back to personal policy silently. Replacing the saved connection file (even
  with identical bytes) requires a new activation.
- After the 24-hour cache window plus the grace period, every command is
  blocked until a sync succeeds or you leave team policy. The background
  refresh does not run with `--offline` or `TIRITH_OFFLINE=1`.
- A competing managed authority (`TIRITH_SERVER_URL` with `TIRITH_API_KEY`, a
  trusted `policy_server_url`, or an organization policy) blocks every command
  until one is removed. Disconnecting while enrolled also blocks until the
  activation is withdrawn or repaired.
- Rollback is available for seven days, and only while the original
  publication is still the current revision.
- A client's Applied report is its own observation, not independent proof of
  enforcement. Publication never claims that every client adopted the policy;
  an unreported client is not assumed offline.
- `OperationNotFound` during reconciliation can mean the report is absent or
  superseded; it does not prove that the old request never committed.
  Abandoning a report does not cancel an in-flight request.
- The private `report.json` holds at most four historical entries and 16 KiB;
  either limit refuses instead of evicting history.
- A report is sent only after its pending record is confirmed durable; an
  unconfirmed storage outcome blocks the request.
- The dashboard never shows private tokens, CA contents, raw pending requests or
  private review commitments, and contacts the server only on an explicit
  action.
