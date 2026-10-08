# Trust grants

A trust grant is an operator-owned exception: it lets one target (and usually
one rule) through where policy allows exceptions. Grants are narrow and expire
by default. They live in your configuration directory's `trust-grants.json`;
older `trust.json` entries keep working until you migrate them.

## Add a grant

```sh
tirith trust add https://example-tool.sh/install.sh --rule pipe_to_interpreter
tirith trust add example-tool.sh --broad --rule shortened_url --ttl 7d
```

- Name a rule with `--rule`. To cover every suppressible rule, pass
  `--all-rules` explicitly.
- A grant expires after 30 days. Pass `--ttl` (for example `1h`, `7d`) or
  `--permanent` to change that, and `--reason` to record why.
- A whole domain, wildcard or bare TLD needs `--broad`.
- Repeating `add` for one matching active grant replaces its expiry instead of
  adding a second grant.

## Limit a grant to one checkout

```sh
tirith trust add https://example-tool.sh/install.sh --rule pipe_to_interpreter --scope project
```

A project grant is bound to this checkout: its canonical root, filesystem
identity and creation time, and your home directory. It covers the checkout's
ordinary subdirectories. Symlinked paths to the same checkout match.

## Inspect, change and remove

```sh
tirith trust list                  # add --expired to include expired and revoked grants
tirith trust explain GRANT_ID      # or a pattern: scope, expiry, and broader grants that also match
tirith trust expiry GRANT_ID --ttl 1h
tirith trust revoke GRANT_ID
tirith trust remove PATTERN --rule RULE
tirith trust diff                  # what changed in the trust set since the last diff
tirith trust gc --expired          # prune expired grants and old revocations
```

- `revoke` keeps a revoked record and reports broader grants that still apply.
- `remove` selects by pattern, like earlier releases, revokes the selected
  grants and shows any permission that remains, including rule-scoped grants
  that still cover the target. `--rule` matches rule IDs case-insensitively.
- `gc` prunes expired grants and revocations older than 30 days. When the store
  is still above 768 KiB, it also prunes the oldest remaining revocations.
- `diff` covers the grant store and the legacy stores; revoked grants are not
  part of the trust set.

Each grant has one of these states: `recorded`, `effective`, `overridden`,
`expired`, `revoked` or `invalid`.

## Move legacy entries

```sh
tirith trust migrate --scope user
```

Migration moves your legacy user entries into the grant store, keeping their
expiry and rule. Expired entries are dropped (enforcement already ignored
them), blocklisted entries stay in `trust.json`, and malformed records are kept
for repair. Migrate a matching legacy entry before adding or shortening its new
counterpart; otherwise the permanent legacy copy would still apply.

## Limits

- An effective grant is only an eligible exception. Blocklists and other
  security decisions can still block the operation. `explain` reports
  eligibility; it does not evaluate a command.
- A suggestion from the last trigger that lacks a rule, or names only a domain,
  is refused; choose the breadth yourself.
- An expiry at or before now counts as expired. Malformed or non-string expiry
  values make the grant invalid, never permanent.
- Project grants need a platform with usable filesystem identity and creation
  timestamps; elsewhere project enrollment is refused. Moving or replacing the
  checkout, a sibling or nested repository with its own `.git`, a linked
  worktree, or a copied configuration on another account does not match.
- A repository-owned `.tirith/trust.json` is recorded but inactive; it cannot
  authorize its own contents. Repository entries cannot be migrated globally;
  add individual project grants after review.
- Tirith 0.4.2 and older ignore `trust-grants.json`, so after a downgrade the
  grants stop applying (they never become global). Migrated entries are removed
  from `trust.json`, so older clients lose them too.
- Every trust store is read with a 1 MiB limit. A change that would write a
  larger store is refused, except a revocation: `revoke`, `remove` and `gc`
  write the compact form when the indented one does not fit, and delete a
  revoked record that no longer fits even as a compact tombstone.
- When the grant store cannot be read (corrupted, oversized, or from a newer
  version), `diff` leaves its grants out with a note, still shows the other
  sources, and does not record that partial snapshot as the next baseline.
- Output redacts targets, rules, reasons and project paths; grant UUIDs stay
  visible. The dashboard always identifies a grant by its UUID, never by
  redacted target text.
