# Browser native messaging (M12 ch3)

tirith's [paste provenance](paste-provenance.md) feature attributes a pasted
command to the web page it was copied from. The attribution data is produced by
a **companion browser extension** (shipped from a separate repository) and
delivered to tirith over Chrome's **Native Messaging** protocol, which this
document specifies.

The Rust side is two commands:

- `tirith browser host` — the native-messaging host Chrome spawns.
- `tirith browser install-extension` — writes the per-OS host manifest so Chrome
  knows how to launch the host.

The TypeScript extension is out of scope here.

## The two ends

```text
  Chrome extension  --(native messaging, stdio)-->  tirith browser host
        (separate repo)                                    |
                                                           v
                                          <state-dir>/clipboard_source.json
                                                           |
                                                           v
                          tirith engine (paste_source_mismatch rule) reads it
```

The extension writes a small JSON record each time it sets the system clipboard.
tirith only ever **reads** the record file from the engine side; the host is the
**only** writer.

## Wire protocol (frames)

Chrome's native messaging framing is a length-prefixed stream on stdin/stdout.
Each message is:

```text
  [ 4-byte length prefix ][ N bytes of UTF-8 JSON ]
```

- The 4-byte prefix is an unsigned 32-bit integer in the host machine's
  **native byte order** (decoded with `u32::from_ne_bytes`, per Chrome's spec).
- The prefix gives the length `N` of the JSON body that follows.
- The host reads frames in a loop until stdin reaches EOF (Chrome closes the
  pipe to end the host).

The host writes a tiny acknowledgement frame back per message, using the same
framing:

```json
  {"ok":true}    — the record was validated and persisted
  {"ok":false}   — the frame was rejected (bad schema) or the write failed
```

## Host name

The native-messaging host is named:

```text
  sh.tirith.browser
```

The manifest file is therefore `sh.tirith.browser.json`. The extension passes
`sh.tirith.browser` to `chrome.runtime.connectNative(...)`.

## JSON schema (the clipboard-source record)

The JSON body of each host-bound frame must deserialize into the M12 ch1
on-disk contract (`tirith_core::clipboard::ClipboardSourceRecord`):

```json
{
  "updated_at": "2026-05-30T00:00:00Z",
  "content_sha256": "<lowercase-hex sha256 of the clipboard content>",
  "source_url": "https://docs.example.com/install",
  "source_title": "Install",
  "hidden_text_detected": false
}
```

| Field                  | Type    | Required | Meaning                                                        |
| ---------------------- | ------- | -------- | -------------------------------------------------------------- |
| `updated_at`           | string  | yes      | RFC-3339 timestamp the extension set the clipboard.            |
| `content_sha256`       | string  | yes      | Lowercase-hex SHA-256 of the clipboard content written.        |
| `source_url`           | string  | yes      | The page URL the content was copied from.                      |
| `source_title`         | string  | no       | The page title (best-effort; defaults to empty).               |
| `hidden_text_detected` | boolean | no       | Whether hidden / invisible text was found (defaults to false). |

Unknown extra fields are ignored, so a newer extension that adds fields does not
break an older tirith. A frame missing any **required** field is rejected and
never written.

The `paste_source_mismatch` rule later compares `content_sha256` against
`sha256(pasted_input)`; a mismatch means the paste did not come from this
recorded source, so no attribution is made.

## Output file

On a valid frame the host writes the validated record to:

```text
  <state-dir>/clipboard_source.json
```

where `<state-dir>` is resolved by the same state-dir helper the engine uses
(`policy::state_dir()` — currently `$XDG_STATE_HOME/tirith`, else
`~/.local/state/tirith`); `tirith browser host` resolves it exactly the same way.
The write is **atomic** (a sibling temp file is fsync'd and renamed over the
destination), so the engine's paste hot-path never observes a torn or
half-written record.

## Security model — input is UNTRUSTED

The host writes a file the engine trusts, so the browser side is treated as an
untrusted input boundary. Three defenses are enforced in `tirith browser host`:

1. **Hard frame-length cap.** Incoming frames are capped at **256 KiB**
   (`MAX_FRAME_BYTES`). Chrome's documented maxima are 1 MiB host→browser and
   4 GiB browser→host, but the host must never allocate an attacker-controlled
   size: a length prefix larger than the cap is rejected **without** reading or
   allocating the body, and the host aborts the stream (a desynced or hostile
   peer does not get to keep sending). The 256 KiB cap has generous headroom
   over a genuine record (which is well under 1 KiB) and mirrors the 64 KiB read
   cap on the file side.
2. **Schema validation before write.** The frame bytes must deserialize into
   `ClipboardSourceRecord`. A frame that does not parse (non-JSON, wrong shape,
   missing a required field) is dropped with an `{"ok":false}` ack and never
   touches disk. The host re-serializes the **validated** struct (not the raw
   bytes) before writing, so only schema-clean JSON ever lands in the file.
3. **Atomic write.** As above, via the shared `write_file_atomic` helper, so a
   concurrent reader never sees a partial record.

A truncated frame (a prefix that promises more bytes than the stream delivers)
is treated as fatal — the framing is no longer trustworthy — and the host exits
non-zero rather than guessing where the next frame starts.

## Installing the host manifest

`tirith browser install-extension` writes the manifest into the selected
browser's per-OS `NativeMessagingHosts` directory. `--browser <chrome|chromium|brave|edge>`
(default `chrome`) selects which one — each Chromium-family browser keeps its own
directory, so installing to the wrong vendor leaves the manifest silently
unfound. The macOS/Linux directories are (all hold `sh.tirith.browser.json`):

| Browser  | macOS (`~/Library/Application Support/…`)             | Linux (`~/.config/…`)                  |
| -------- | ----------------------------------------------------- | -------------------------------------- |
| chrome   | `Google/Chrome/NativeMessagingHosts`                  | `google-chrome/NativeMessagingHosts`   |
| chromium | `Chromium/NativeMessagingHosts`                       | `chromium/NativeMessagingHosts`        |
| brave    | `BraveSoftware/Brave-Browser/NativeMessagingHosts`    | `BraveSoftware/Brave-Browser/NativeMessagingHosts` |
| edge     | `Microsoft Edge/NativeMessagingHosts`                 | `microsoft-edge/NativeMessagingHosts`  |

On **Windows** every browser is registry-based (see below) — the command prints
guidance per browser and does NOT write the registry.

The manifest body is:

```json
{
  "name": "sh.tirith.browser",
  "description": "tirith browser native-messaging host (paste provenance, M12)",
  "path": "<absolute path to the current tirith executable>",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<EXTENSION_ID>/"]
}
```

`path` is the absolute path of the running `tirith` binary (Chrome spawns it).
`allowed_origins` lists exactly which extension IDs may connect.

The command is a **dry-run by default**: it prints the manifest and the target
path. Pass `--apply` to write it (the directory is created if needed). The write
is idempotent — re-applying identical content is a no-op.

Because the companion extension is not yet published, its Chrome extension ID is
unknown. Pass `--extension-id <id>` (a real Chrome ID is 32 lowercase letters
`a`–`p`); without it a clearly-marked placeholder is used and the command prints
a note that the real ID is required before the host will accept a connection.

### Windows

On Windows, Chromium-family browsers discover a native-messaging host via a
**registry key** rather than a directory drop. `tirith browser install-extension`
does not modify the registry; it prints the manifest body and tells you to:

1. Save the manifest to a file (e.g. `%LOCALAPPDATA%\tirith\sh.tirith.browser.json`).
2. Create the key `HKCU\<root>\sh.tirith.browser` with its default value set to
   that file's path, where `<root>` is the registry root for the `--browser` you
   selected:

   | Browser  | Registry root (`HKCU\…`)                                |
   | -------- | ------------------------------------------------------- |
   | chrome   | `Software\Google\Chrome\NativeMessagingHosts`           |
   | chromium | `Software\Chromium\NativeMessagingHosts`                |
   | brave    | `Software\BraveSoftware\Brave-Browser\NativeMessagingHosts` |
   | edge     | `Software\Microsoft\Edge\NativeMessagingHosts`          |

   (The printed guidance fills in the root for the browser you passed, so
   `--browser edge` names the Edge key, not Chrome's.)

## Examples

```sh
# Print the manifest + target path (dry-run):
tirith browser install-extension

# Write it with the real extension id:
tirith browser install-extension --extension-id abcdefghijklmnopabcdefghijklmnop --apply

# Machine-readable:
tirith browser install-extension --json
```

`tirith browser host` is invoked by Chrome, not by hand. It reads
length-prefixed JSON frames from stdin and writes `clipboard_source.json`.
