# Spike 5b: web3 phishing feed

Status: research spike, go/no-go decision record. This is a source-class and
schema sketch plus a legal review. There is no code change, no wired enum
variant, and no shipped feed in this PR.

Question under test: should tirith ingest a web3 phishing feed (known crypto
phishing hostnames and wallet-drainer addresses) as a threat source?

Hard boundary, stated up front: no shipped feed, and no ingestion of
nonstandard-licensed or unlicensed data into the signed threat DB, until legal
explicitly clears the data license and its redistribution terms. The two leading
candidate datasets both fail that bar today (see Legal review).

External facts checked 2026-07-16. tirith behaviour claims cite the file and line
read on branch `security/spikes` (PR3 tip, commit bb95bd40).

## Current baseline

tirith already has two offline web3 heuristics, both in
`crates/tirith-core/src/rules/ecosystem.rs`, run from `check` at
`ecosystem.rs:15-16`:

| Rule | Location | Severity | What it flags |
|------|----------|----------|---------------|
| `Web3RpcEndpoint` | `ecosystem.rs:110` `check_web3_rpc` | Low | A URL whose path looks RPC-like (`/v1/`, `/rpc`, `/jsonrpc`) on a known provider host (infura.io, alchemy.com, moralis.io, chainstack.com, getblock.io), listed at `ecosystem.rs:114-120` |
| `Web3AddressInUrl` | `ecosystem.rs:141` `check_web3_address_in_url` | Low | Any 40-hex Ethereum address in a URL, matched by `ETH_ADDRESS_RE` (`0x[0-9a-fA-F]{40}`) at `ecosystem.rs:139` |

Both RuleIds are declared at `crates/tirith-core/src/verdict.rs:128-129`. These are
structural, reputation-free heuristics: they recognise the shape of a web3 URL or
address, not whether it is malicious. There is no crypto-phishing reputation data
anywhere in the tree today (grep for `web3`/`phishing`/`drainer`/`scamdb` across
`rules/` and `threatdb.rs` returns only the two heuristics above and the unrelated
PhishTank/PhishingArmy website feeds). That absence is the gap this spike scopes.

## Source-class and schema sketch (not wired)

A web3 phishing feed splits into two indicator kinds, which fit tirith's existing
schema very differently.

### Kind 1: phishing hostnames (clean fit)

Crypto phishing sites are hostnames, identical in shape to the phishing website
data tirith already ingests. They fit the existing feed machinery with no schema
change:

- Parser: a `parse_web3_phishing_*` function in
  `crates/tirith-core/src/threatdb_feeds.rs`, following the URLhaus/ThreatFox
  pattern (`threatdb_feeds.rs:26` and `:60`), emitting into the existing
  `FeedEntries { hostnames, ips }` struct (`threatdb_feeds.rs:6-19`) and reusing
  `FeedEntries::sort_and_dedup` (`threatdb_feeds.rs:13`). One parser detail to get
  right: `extract_hostname_from_url` (`threatdb_feeds.rs:21`) calls
  `url::Url::parse`, so it only accepts absolute URLs. A web3 phishing feed is
  usually bare hostnames (`example.com` rows, not full URLs), so those entries must
  be normalized directly (lowercased and pushed to `hostnames`, the way
  `parse_domain_blocklist` already handles bare hosts) rather than passed through
  `extract_hostname_from_url`, which would drop them. Use `extract_hostname_from_url`
  only for URL-shaped rows.
- Source: a new `ThreatSource::Web3Phishing` enum variant in
  `crates/tirith-core/src/threatdb.rs` (the enum is at `threatdb.rs:273`; the
  current last variant is `ExfilEndpoint = 11` at `threatdb.rs:288`, so this would
  be the next free discriminant). Adding a variant is all-or-nothing across eight
  method sites, the same edit set every existing source has: the enum discriminant,
  `from_u8` (`threatdb.rs:292`), the `ALL` array and its count (`threatdb.rs:311`,
  currently `[ThreatSource; 12]`), `as_str` (`threatdb.rs:328`), `tier`
  (`threatdb.rs:347`), `upstream_url` (`threatdb.rs:365`), `label`
  (`threatdb.rs:386`), and `default_confidence` (`threatdb.rs:404`). The
  out-of-range discriminant test at `threatdb.rs:4047` (`from_u8(12).is_none()`)
  would move to the next value.
- Routing: the compiler forces two more arms, because
  `crates/tirith-core/src/rules/threatintel.rs` enumerates `ThreatSource` with no
  `_` fallthrough in both `hostname_rule_for_source` (`threatintel.rs:627`) and
  `ip_rule_for_source` (`threatintel.rs:658`) ("Enumerated explicitly (no `_` arm)
  so the compiler flags any new variant", `threatintel.rs:642` and `:666`). A
  phishing hostname source routes naturally to `RuleId::ThreatPhishingUrl`
  (High), the same rule PhishTank and PhishingArmy already map to
  (`threatintel.rs:634-638`).

This kind is a drop-in. The only real work is the parser and the license.

### Kind 2: wallet-drainer addresses (needs schema work)

The higher-value web3 indicator is a set of known malicious contract or wallet
addresses (drainers, approval-phishing contracts). These do not fit the
`FeedEntries { hostnames, ips }` model at all, and they do not fit the
hostname/IP routing in `threatintel.rs`. Two options, both schema work:

1. Enrich the existing heuristic. Today `check_web3_address_in_url`
   (`ecosystem.rs:141`) flags any Ethereum address at Low. It could be upgraded so
   that an address present in the drainer set escalates to High with a
   known-malicious finding, while an unknown address keeps the Low structural
   signal. This reuses the existing extraction and rule site but needs a new
   address-indicator dimension in the threat DB (the current DB indexes hostnames,
   IPs, and, since DB-D, SHA-256 hashes, but not 20-byte addresses).
2. A dedicated address indicator and rule. A new normalized-address index in the
   DB plus a new `RuleId` (for example `Web3MaliciousAddress`) following the full
   RuleId registration checklist. Cleaner separation, more surface.

Either way, kind 2 is a schema addition (a new indicator type), not a drop-in, and
should be a separate follow-up from kind 1.

## Legal review of candidate feeds

This is the blocker. Both leading public datasets fail the redistribution bar for
a signed, redistributed DB.

| Dataset | License | Redistribution into signed DB | Source pinned to immutable revision (checked 2026-07-16) |
|---------|---------|-------------------------------|---------------------------|
| MetaMask `eth-phishing-detect` | "DON'T BE A DICK PUBLIC LICENSE" v1.2 (DBAD), no SPDX identifier, informal | No, not until legal clears it | `github.com/MetaMask/eth-phishing-detect/blob/09467d0f4927/LICENSE` (default branch `main`, commit `09467d0f4927`, 2024-12-13) |
| CryptoScamDB `blacklist` | No LICENSE file present (all-rights-reserved by default) | No | `github.com/CryptoScamDB/blacklist` at commit `2208d2e99a23` (default branch `master`, 2022-06-28; GitHub API `license: null`) |

Detail on each:

- MetaMask `eth-phishing-detect` is under the "DON'T BE A DICK PUBLIC LICENSE"
  version 1.2, whose only substantive clause is "Do whatever you like with the
  original work, just don't be a dick." It has no SPDX identifier and is not an
  OSI-recognised license. Its vague, subjective conditions (it enumerates
  "dickish" behaviour including "profiting without sharing benefits with
  creators") make it legally uncertain to vendor into a redistributed, and
  commercially dual-licensed, product. This is the nonstandard license the plan
  flagged. Reference-only until legal rules on it.
- CryptoScamDB `blacklist` has no LICENSE file at all, so by default it is
  all-rights-reserved and not redistributable without explicit permission. It is
  also effectively unmaintained: the GitHub API reports the last commit on the
  default branch (`master`) as 2022-06-28, commit `2208d2e99a23`, and the last
  push as 2023-04-29 (checked 2026-07-16), so the data is stale as well as
  unlicensed. Fails both the license bar and a freshness bar.

Neither dataset can enter the signed DB today. A permissively licensed and
maintained web3 phishing source (MIT/Apache/CC0/CC-BY with a clear redistribution
grant) would need to be found before kind 1 ships, and legal would need to sign
off on the specific dataset and its terms. The revisions above are pinned to
commit hashes so this review is reproducible; because upstream branches move, a
formal legal sign-off should re-verify the license against the then-current
revision before any ingestion.

## Recommendation

No-go for shipping now. Defer. The source-class design for kind 1 (phishing
hostnames) is ready and is a genuine drop-in into the existing feed and routing
machinery; kind 2 (malicious addresses) needs a new indicator dimension and is a
separate follow-up. Nothing ships until the data problem is solved.

Gating conditions, all required:

1. A candidate dataset with a clear, permissive, redistribution-granting license
   (not DBAD, not unlicensed), and legal sign-off on that specific dataset and its
   terms for inclusion in the signed, dual-licensed DB.
2. A freshness and liveness check on the chosen feed, matching the gate the
   DigitalSide feed spike applies (a stale feed stays defined but CI-disabled).
3. For kind 2 only: a threat-DB schema addition for a normalized-address indicator,
   under its own follow-up, before any address-reputation rule escalates severity.

Until then, tirith's two structural web3 heuristics (`Web3RpcEndpoint`,
`Web3AddressInUrl`) remain the baseline, and this document is the design that a
cleared, permissively licensed feed would slot into.
