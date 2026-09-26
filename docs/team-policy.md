# Bring your own team policy server

Personal protection works without a server. Team policy is off until a user explicitly activates a saved connection. Connecting, fetching, reviewing and publishing are separate actions; none automatically enrolls another device.

Tirith includes a separate `tirith-policy-server` executable. Run it on infrastructure your team operates, or implement the documented Tirith policy-management API on an existing service. An arbitrary file server is not sufficient: reviewed publication, concurrent-update checks, rollback, authentication and client report reconciliation require the API contract in [the server guide](../tools/policy-server/README.md).

The server runs under an ordinary Linux or macOS account. It does not install a privileged service or require sudo. Its private SQLite storage currently has no Windows server implementation; Windows clients connect to a supported server. Native filesystem and platform qualification limits remain in the server guide.

## Host the authority

Build the optional executable with `cargo build --release -p tirith-policy-server`. Choose an existing private directory you own. The data directory passed to `init` must not exist yet; its parent must already be private. Use absolute native paths, including `/private/tmp` instead of the macOS `/tmp` alias for temporary experiments.

```sh
tirith-policy-server --data-dir /absolute/private/authority init --policy /absolute/private/policy.yaml
tirith-policy-server --data-dir /absolute/private/authority serve --listen 127.0.0.1:8778
```

Initialization prints the authority ID, policy ID, revision and roster revision. Keep the authority and policy IDs for connection verification. Put an operator-managed HTTPS reverse proxy in front of the loopback listener. The client requires certificate verification even when the server is on a private network. An ordinary account can use a TLS port above 1024; exposing a system port or configuring a system service follows the host's permission rules.

Do not log bearer credentials or request/response bodies at the proxy. Restrict network access to the intended team. The server has no public registration, browser login, payment or license service. It keeps a bounded set of policies, credentials and clients; capacity exhaustion refuses visibly instead of forgetting replay history.

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

Activation and sync do not send Applied reports. The command hot path reads the enrolled local cache without contacting the team server. The cache must remain valid and less than 24 hours old. Missing, stale, changed or malformed enrolled policy fails closed; it does not silently return to personal policy. Repository restrictions and the ordinary local overlays remain part of Runtime. A competing organization or legacy remote authority requires an explicit migration instead of undefined precedence.

To turn team policy off, withdraw the exact activation. This works offline and does not require a fresh cache or working server connection:

```sh
tirith policy team enrollment disable --expected-activation-id ACTIVATION_UUID
```

If enrollment bytes are malformed and no activation ID can be safely read, explicitly remove only the currently malformed record:

```sh
tirith policy team enrollment repair --remove-malformed
```

This offline action captures one bounded private record and retains its native identity through deletion. It refuses a valid enrollment, unsafe storage, or a changed record. It does not salvage fields from malformed JSON, infer an activation ID, or use a status token from an earlier process. The browser requires a separate acknowledgment for this removal. Connection and report records remain intact.

Disconnecting a connection is a separate action and does not withdraw enrollment. Disconnecting while enrolled therefore causes Runtime to refuse until the activation is deliberately withdrawn or repaired.

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

Reconciliation authenticates the same selected Client and compares the complete original request with the server's latest retained report. It works without a valid current cache or activation and never submits an Applied observation. A confirmed receipt is a historical fact. `OperationNotFound` can mean the report is absent or was superseded; it does **not** prove that the old request never committed.

An unresolved request can be explicitly archived locally before preparing a new report:

```sh
tirith policy team enrollment abandon --report-id REPORT_UUID --acknowledge-unknown-outcome
```

Abandonment preserves the exact request and its private context with an unknown server outcome. It neither cancels an in-flight request nor asserts no commit. The same private `report.json` holds at most four historical entries and is capped at 16 KiB total; either limit refuses without evicting history. A new report still requires actual valid Runtime and fresh authenticated server sequence. A late older request can win the server update race, leaving the new request in conflict; Tirith retains that exact request instead of inventing another sequence.

Status shows an opaque local archive ID for historical entries. To reconcile one explicitly, use `enrollment reconcile --report-id REPORT_UUID --archive-id ARCHIVE_UUID`. Without an archive ID, reconciliation selects the current stored report. Archive IDs distinguish different retained contexts if a never-confirmed sequence produced the same deterministic report ID again.

Report submission requires a confirmed durable pending write. An unconfirmed storage outcome, including retained Windows recovery, does not permit a report POST. Inspect the reported storage result and retained state before another explicit action. Browser status and the report's initial Runtime resolution cannot fall through to a legacy authority network request after concurrent withdrawal.

A Publisher or Observer can fetch fleet status with `tirith policy team rollout fleet`. The roster includes all explicitly active registered clients and distinguishes unreported, stale, downloaded, applied-current, applied-older and failed reports. An unreported client is not assumed to be offline. Applied means the authenticated client reported its local observation; it is not independent proof of enforcement across the fleet. Publication never claims every client adopted the policy.

The local browser's Settings page exposes connection, activation, rollout review and reporting actions under the existing local authentication and CSRF protection. Browser status loads remain local; remote contact requires an explicit action. Private tokens, CA contents, raw pending requests and private review commitments are not projected into the browser.
