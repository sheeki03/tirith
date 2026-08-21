# Synthetic browser extension fixtures (C16)

Every tree here is written by hand for `tirith browser audit` tests. No file is
copied from a real published extension: the scripts are one-line comments and the
manifests declare only the fields the audit reads.

Extension ids are supplied by the test that installs a fixture, not by the
fixture itself, so the same tree can stand in for a wallet-shaped id or an
ordinary one. Where a test uses a real wallet extension id it does so purely as a
classification fixture; an id is never a trust anchor.

| Directory | Shape |
|-----------|-------|
| `wallet-mv3` | MV3, service worker, one content script, `externally_connectable` |
| `legacy-mv2` | MV2, background scripts, host pattern inside `permissions` |
| `broad-mv3` | MV3 holding `<all_urls>`, `debugger`, `nativeMessaging`, `webRequestBlocking` |
| `enterprise-mv3` | MV3 with a `_metadata` store signature, for the enterprise install class |
