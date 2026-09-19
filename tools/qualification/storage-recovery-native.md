# Native full-filesystem and signed audit recovery qualification

This opt-in runner uses an explicitly supplied, SHA256-pinned candidate and a
matching retained `candidate.json`. It never builds Tirith or installs a hook,
starts a service, or reads operator configuration. A successful report qualifies
only its exact requested cases and captured native candidate. An unobserved
boundary, missing route, wrong exit, incomplete process cleanup, input drift or
failed volume detach makes the aggregate unsuccessful. The manifest must select
the exact `tirith_product` entry with `profile_test: false`; a test executable or
an arbitrary matching manifest entry is refused.

The default routes are six signed audit rotation process-death boundaries, one
signed concurrent cancellation, actual ENOSPC during audit recording, and actual
ENOSPC during profile publication. Select routes with repeated `--case` flags.
Signed routes can run without a disk image on supported macOS/Linux hosts.

## Preconditions and invocation

Use ordinary-UID native Python with `os.waitid`/`WNOWAIT`, the reviewed
`mixed_audit_native.py` helper, and the `cryptography` package for signed routes.
No packages are installed by this runner. Its RFC8032 known-answer fixture checks
the independently used Ed25519 implementation. Signing uses only the publicly
disclosed [RFC8032 section 7.1 test vector 1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1).
Each case removes its private fixture seed after all owned children have finished.

```sh
python3 -m unittest -v test_storage_recovery_native
python3 storage_recovery_native.py \
  --candidate /absolute/retained/tirith \
  --sha256 ACTUAL_SHA256 \
  --candidate-manifest /absolute/retained/candidate.json \
  --output /absolute/new/evidence-directory \
  --create-owned-64m-image
```

No image is created unless an ENOSPC route is selected and the explicit image
flag is supplied. The fixed-image implementation currently requires macOS
`hdiutil create` with journaled HFS+ support and `diskutil image attach`; unsupported
systems fail explicitly. `--filesystem apfs` selects a fixed-size APFS image via
the documented `hdiutil create -uid/-gid/-mode` flags for the ordinary creator's
UID/GID and requested mode 0700, retaining the same 64 MiB cap and enforced owners.
The native creator honored UID/GID but produced mode 0755; write admission accepts
only actual creator UID/GID and mode 0700 or 0755 beneath the fixture's verified
owner-private 0700 ancestor. Group/other write permission, special modes, foreign
owners and public/symlink ancestors refuse. No `sudo`, ownership
disablement or post-format privileged `chown` is used. Installed
`newfs_apfs(8)`, `diskutil image create blank --help` and Apple's Disk Utility guide
document this filesystem but specify no numeric minimum for this native build.
If the formatter rejects 64 MiB, that refusal is preserved; the runner does not
enlarge the image, add a volume to a host container or choose another device.
APFS admission additionally requires its observed filesystem type. The native
64 MiB blank formatter was observed to succeed, but its default volume root
refused ordinary-user directory creation before any product execution; that
zero-case run remains failed and retained. This route is
needed for atomic identity exchange, which the tested HFS+ image does not support.
It does not substitute EACCES, EFBIG, EDQUOT or a mocked
write error for ENOSPC. This is not a Windows or release-artifact qualification.

## Owned filesystem and cleanup

The runner creates one fixed 64 MiB writable image inside its fresh private
evidence directory, with a UUID image name, volume label and private mountpoint.
Neither image shares APFS allocation space with the host. Only the selected
case's data or configuration root is placed on this volume; candidate, HOME,
cache, operation journals, system-tool environment, keys and evidence remain in
fresh roots outside it. Host free-space admission estimates a 512 MiB reserve;
this is not a continuously guaranteed free-space reservation.

Before filling, the runner retains the image file descriptor and mount-directory
descriptor, checks their native device/inode identities, checks the exact
image-path to mountpoint relation, and binds the volume UUID and label. The
mounted filesystem must differ from the host device and report 16–64 MiB total.
Filling opens only a fixed new regular file relative to the retained mount FD.
Every exhaustion attempt writes at most 64 MiB in aggregate, with no sparse seek,
fallback filesystem or large-file limit. A cooperative 20-second deadline bounds
the write loop; this is not a hard deadline for a stuck kernel filesystem call.
The final one-block write/fsync must return the kernel's ENOSPC. The report also
requires the actual product failure path to identify ENOSPC.

All CLI/system-tool children use the existing bounded WNOWAIT ownership helper.
Only their owned process groups are signaled. Native disk services are not owned
descendants and are never signaled. Before detach, candidate processes have been
reaped and their output drained, then image inode, UUID and mount relation are
rechecked. Write eligibility is independent of normal detach authority: a failed
private-mode admission must not prevent cleanup of the fully identified owned
image. The retained identity tuple is serialized even when later write eligibility
fails. The mount FD stays pinned throughout filling and candidate execution,
and closes just before normal detach of the owned mountpoint. No remembered
device identifier, `sudo`, force detach, unrelated image or user mount is used.
The image is retained as evidence after successful detach. Owned descriptors
close in a `finally` path, including partial admission and detach failures. A
partially completed attach is detached only if its exact image, mount, UUID and
held identities can be positively admitted. An empty inventory after a failed or
timed-out disk client does not prove its system-service request is complete; that
cleanup remains explicitly unresolved. Ambiguous attachment or cleanup never
triggers a guessed detach. Inventory shape is validated at every absence check.
This does not claim safety against a hostile same-UID owner racing namespace
replacement, or power loss while macOS disk services are performing an operation.

## Assertions

Audit exhaustion preserves exact allow/block verdicts and requires visible audit
failure. The original log prefix and committed head must survive on the same log
inode. After the filler is removed, the runner either verifies unchanged history
and a fresh append, or requires the precise integrity refusal for a partial append
and proves rotation refuses without changing retained bytes. It does not invent a
repair or accept arbitrary nonzero exits as successful refusal.

Profile exhaustion requires `recovery-required`, an ENOSPC detail, unchanged
original policy generation and released operation lock. After capacity returns,
the same operation must publish the exact intended strict-profile fields. Replay
must preserve the published generation; undo restores exact original bytes and
repeated undo must preserve that generation.

Signed rotation uses the existing acknowledged-SIGSTOP lock-owner observer,
unchanged observation deadlines, exact post-stop stage/journal classification,
SIGKILL, lock-release proof, reopen, same-ID retry and exact-byte undo. It verifies
the signed plan, checkpoint, current log and heads independently, then uses the
actual candidate's audit verifier on both current and retained archived history.
These are six observable process-death boundaries, not every filesystem durable
write, storage-controller/power-loss simulation or hostile-key test.

## Evidence and limits

The report includes bounded native stdout/stderr and all four owned cleanup
facts, image/volume identities, actual ENOSPC errno and byte count, before/after
file hashes/inodes, exact requested/observed stages, candidate/manifest/helper
hashes, Python identity and cryptography version. Source/candidate hashes are
rechecked after all cases. Keep failed and unobserved runs immutable; use a new
output path when correcting a fixture. Portable tests validate runner predicates
and rejection paths only; they are not native product or mount evidence.
