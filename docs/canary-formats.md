# Canary token formats (M11 ch3)

`tirith canary` plants **honeytokens** — deliberately-synthetic, secret-shaped
tokens you place where nothing legitimate should ever read them (a decoy
`~/.aws/credentials`, a fake `.env`, a bait line in a private repo). tirith
records each token locally; when that exact token later appears in a command you
run, a paste, or a tool output tirith inspects, the engine fires
`CanaryTokenTouched` (High).

This document specifies the generated token shapes. The defining property is
that every shape is **clearly synthetic**: it carries a literal, obviously-fake
marker. That serves three goals:

1. **No accidental real-credential collision.** A canary must never resemble a
   genuine third-party credential closely enough to trip an external provider's
   abuse / take-down workflow when it surfaces in a log or a paste.
2. **Still matches tirith's own detection.** The shapes keep the recognizable
   provider prefix so the token reads as a secret to a human and to tirith.
3. **Human-recognizable.** A developer who notices the token can immediately
   tell it is a tirith canary, not a real leak.

## Shapes

| kind                 | format                                                    | example (illustrative)                                  |
| -------------------- | --------------------------------------------------------- | ------------------------------------------------------- |
| `aws-like`           | `AKIA00CANARY` + 8 base32 chars                           | `AKIA00CANARYBMJY3PVA`                                   |
| `github-like`        | `ghp_canary_` + 30 alphanumerics                          | `ghp_canary_ZDuktRyqJjF0YNEP1KbpI2wHBzCnXv`             |
| `gcp-like`           | `AIzaCANARY` + 30 URL-safe chars                          | `AIzaCANARY8fK2…` (40 chars total)                      |
| `env-line`           | `TIRITH_CANARY_TOKEN=canary_` + 24 hex                    | `TIRITH_CANARY_TOKEN=canary_3f9a…`                      |
| `private-key-shaped` | PEM block whose body is `TIRITHCANARY` + 52 base64 chars  | `-----BEGIN TIRITH CANARY PRIVATE KEY----- …`           |

### Why `AKIA00CANARY` can never be a real AWS key

A real AWS access-key ID is `AKIA` followed by 16 characters drawn from the RFC
4648 **base32** alphabet (`A`–`Z` and `2`–`7`). The digits `0` and `1` are NOT
in that alphabet. The canary's `00CANARY` infix therefore guarantees the token
can never collide with a genuine AWS key, while keeping the recognizable `AKIA`
prefix so it reads as an AWS credential. The random suffix uses the base32
alphabet so the overall length and character set otherwise resemble a real key.

The `ghp_canary_`, `AIzaCANARY`, `canary_`, and `TIRITHCANARY` markers play the
same role for the other kinds.

## Randomness

The random portion of every token is drawn from the OS CSPRNG (`getrandom`),
with rejection sampling to avoid modulo bias, so tokens are unguessable. tirith
does not depend on the `rand` crate at runtime for this (it is a dev-dependency
only); the entropy source is the same one the anomaly-baseline salt uses.

## Storage

Tokens live in a local-first JSONL store at `state_dir()/canaries.jsonl` (mode
`0600` on Unix), one `{id, token, kind, created_at, callback_url?}` object per
line. `tirith canary list` shows them; `prune` / `rotate` manage them.

## Detection scope

Detection is a **store lookup**, not a shape match: ONLY tokens you registered
fire `CanaryTokenTouched`. An unrelated, genuine AWS key in a paste fires the
existing `CredentialInText` / `HighEntropySecret` rules instead — never the
canary rule, because that key is not in your store.

## Local-first, opt-in callback (D3)

By default a canary is **local-only**: a hit raises the finding and writes to the
local audit log; nothing leaves the machine. A canary MAY be created with
`--callback-url <url>`, where `<url>` is an endpoint **you self-host**. On
detection (and only on detection) tirith sends one best-effort POST of
`{kind, detected_at, context}` — **never the token value** — to that URL. There
is no tirith-operated endpoint. A callback failure is logged to the audit log
and never blocks the verdict. This is the single exception to tirith's
no-network rule, and it is gated entirely behind your explicit `--callback-url`.
