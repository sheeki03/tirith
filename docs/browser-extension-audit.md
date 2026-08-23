# Browser extension integrity audit

`tirith browser audit` answers one question: are the extensions loaded into this
browser profile the same ones that were there last time, byte for byte.

It is explicit, one-shot, and read-only. It never removes, quarantines, or
watches anything, and there is no daemon and no background monitor to unwind.

```bash
tirith browser audit                                  # chrome, all discovered profiles
tirith browser audit --browser all --format json
tirith browser audit --write-baseline ~/ext-baseline.json
tirith browser audit --baseline ~/ext-baseline.json    # report drift
```

Chrome, Chromium, Brave, and Edge. **Firefox and XPI are out of scope and are
refused by name**, not silently skipped.

## The privacy boundary is the point

A security tool that reads a user's browsing history to check their extensions
has done more harm than the extensions it audits. The read set is therefore
closed, enumerated, and enforced in one place.

**Read:**

- `<user-data>/<profile>/Extensions/<id>/<version>/**`, every regular file, for
  the sorted tree digest. `manifest.json` is additionally parsed.
- `<profile>/Preferences` and `<profile>/Secure Preferences`, restricted to
  exactly three fields beneath `extensions.settings.<id>`: `location`,
  `from_webstore`, and `was_installed_by_default`. Install class genuinely lives
  there and nowhere else, and only for extension ids already discovered on disk.

**Never read:**

- `Cookies`, `History`, `Login Data`, `Web Data`, `Local Storage/leveldb`,
  `IndexedDB/`, `Local Extension Settings/`, `Sync Extension Settings/`, any
  wallet database, any seed material.
- `<user-data>/Local State`. Chrome keeps the human profile names there under
  `profile.info_cache.<dir>.{name,user_name,gaia_id}`, and `user_name` is the
  signed-in Google account email. **Profile identity in this command is the
  profile DIRECTORY NAME and nothing else.** That is a deliberate capability
  reduction: the audit cannot tell an operator which human a profile belongs to,
  and it should not be able to.
- Preferences as a document. The three fields are converted to typed values
  inside the reader; no `serde_json::Value` from that file crosses its return
  boundary.

Every open is gated on two independent predicates: the shared sensitive-asset
classifier returning "not a credential or wallet store", and no path component
naming one of a lexical never-read list. The lexical list is what makes the
statement above about this module rather than about which extension ids happen
to be catalogued.

Neither predicate can see a HARD link, which is not a symlink and carries no
distinguishing name, so a regular file inside an extension tree with more than
one link is refused outright rather than hashed: the same bytes are reachable
under a name the walk never selected.

## Two limits, stated rather than implied

**The baseline is signed, when a key exists, but never anchored in the audit
hash chain.** It carries an ed25519 signature when the installation has an audit
key, and its
`receipt_id` is a content address that the signature binds. It is not entered
into the tamper-evident audit chain, because the chain's receipt anchors are
typed per receipt kind and mint their trust capability by re-reading a receipt
from a tirith-owned directory under a `0600` owner contract, which an
operator-chosen `--write-baseline` path cannot satisfy.

**Chrome's `Secure Preferences` MAC is not verified.** The three install-class
fields are read from it and used for classification; the file's own integrity
signature is not checked. A local attacker who can rewrite that file can change
the reported install class.

## Risk and drift are different questions

Permission risk says how much authority an extension holds: `<all_urls>`,
`debugger`, `nativeMessaging`, MV2 `webRequestBlocking`, `proxy`, `cookies`,
`history` or `browsingData`, and `management` each carry their own reason.

Drift says what changed since the baseline. A wallet extension legitimately
holding `<all_urls>` is not the same event as a wallet extension whose bytes
changed without its version changing, and an operator has to be able to tell
them apart. Nothing lets a risk level create a drift entry or a drift entry
raise a risk level.

Wallet extension ids are FIXTURES for labelling only, read from the shared
sensitive-asset catalogue. They are never a trust anchor: a matching id changes
no digest, no risk level, and no drift verdict. Enterprise and developer
installs are likewise classified, not condemned.

The drift vocabulary distinguishes a new extension, a removed one, a version
change, a **version-directory reuse** (the declared version moved while its
directory did not, and the bytes changed with it, which no real Chrome update
can produce), a **version-directory set change** (a second complete tree dropped
beside the audited one), an integrity result that is not comparable, and a
baseline written under older hashing rules.

## Coverage is honest or it is nothing

Any unreadable file, locked directory, symlink, name collision, oversize file,
or exhausted budget makes the enclosing result `partial` and sets the tree
digest's `complete` flag to false. A partial digest is never emitted as if it
were complete.

Honest coverage is only worth something if the COMPARISON can see it, so:

- a gap directly beneath `Extensions/<id>/` marks that extension's enumeration
  incomplete, which the baseline carries and which becomes an
  `integrity_not_comparable` drift entry;
- an extension that cannot be audited at all is still REPORTED, with partial
  coverage and empty facts, because an id that vanishes from the inventory
  produces no drift entry and a newly installed one would otherwise be
  invisible;
- a `--baseline` run whose report is partial exits 1 even with no drift
  entries, because a verify run that could not verify must not print a clean
  comparison it did not make.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no drift, and any JSON write succeeded. Partial coverage with NO baseline is also 0, and says `partial` in the output |
| 1 | drift, including partial coverage WITH a baseline |
| 2 | usage error, or a JSON write failure with no drift |

The `(no drift, broken write) => 2` case is deliberate: a JSON-write failure
must not collapse "drift, exit 1" into "usage error, exit 2", and drift
dominates either way. This matches the `tirith mcp verify` contract.

## What this is not

**Not browser forensics.** No browsing data is read, no browser is monitored, no
extension is quarantined or removed, and no infostealer is attributed. There is
no continuous monitoring, no daemon, and no collection of wallet data.

## See also

- [Enforcement coverage](enforcement-coverage.md), the per-capability ledger
- [Untrusted projects](untrusted-projects.md), the workflow this fits into
- [Browser native messaging](browser-native-messaging.md), the separate clipboard-provenance host
