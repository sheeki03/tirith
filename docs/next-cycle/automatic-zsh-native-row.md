# Automatic Zsh native module admission

Automatic activation is implemented for the exact macOS ARM64 Apple Zsh 5.9
row below. Three fresh native sessions with default job control enabled
(`MONITOR=on`) passed on the retained September 21 product, SHA-256
`cc5558cda58e51555a87829da011cc4635f73e8499d368968ba162bbaeab5437`.
They observed the ordered allow/block/status sequence and restored history;
see [integrated native checks](verification.md#integrated-native-checks-2026-09-21).
This qualifies the recorded product and native tuple, not later source changes,
other platforms, or a final tag-produced package.

The initial module-import row is macOS on ARM64 with the exact Apple Zsh 5.9
files listed in `setup_activation/native_modules.rs`. Full-file SHA-256 values
include every architecture slice and signature. During row review, the native
files passed their Apple anchor and exact identifier requirements:
`com.apple.zsh`, `com.apple.rlimits`, `com.apple.system`, `com.apple.stat` and
`com.apple.files`. The inspected load commands import only these fixed system
libraries: `/usr/lib/libpcre.0.dylib`, `/usr/lib/libiconv.2.dylib`,
`/usr/lib/libSystem.B.dylib`, and `/usr/lib/libncurses.5.4.dylib`.

The fixed internal `__setup-activation modules --channel zsh` route authenticates
the actual direct parent through its existing receipt capability. It then checks
the native process path, fully enabled System Integrity Protection, root-owned
non-writable directory ancestry, restricted regular files, exact bytes and
retained file/directory identities. It repeats the parent, file and protection
checks before returning. It has the automatic helper's one-second self deadline,
creates no child and emits no output. It neither reads a caller-supplied module
path nor loads module code. Broker/relay admission independently repeats the
same rule. No receipt, setup completion or protection observation is created by
module qualification.

Unknown binaries, changed hashes, other architectures, Linux and modified SIP
configurations are unavailable for this row. An OS update may require a new
reviewed row. Signature similarity or a matching version string is insufficient.
The exact-hash rule avoids running a signature verifier during shell startup;
the admitted files are the bytes whose signatures and dependencies were reviewed.

The shell initializer refuses preloaded, aliased or redirected required modules
and uses the actual special readonly `module_path` parameter
with the one fixed system directory. Those checks are about importing new code;
they do not attest all previously loaded shell code or process memory.

The implemented keymap collector bounds retained bytes and producer CPU time. Zsh
5.9 formats a complete key-binding macro before writing it, so a large existing
macro can cause additional allocation before output is refused. This is not a
total heap or resident-memory limit. The native results above cover only their
recorded startup, editor and receipt scenarios. Other configurations, cancellation
paths and later product/native bytes require their own qualification; final
package and complete upgrade acceptance remain open.
