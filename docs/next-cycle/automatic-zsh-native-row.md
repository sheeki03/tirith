# Automatic Zsh native module admission

Automatic activation is under integration; the presence of this admission rule
does not certify a completed installed-terminal journey.

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

The shell initializer must additionally refuse preloaded, aliased or redirected
required modules, and use the actual special readonly `module_path` parameter
with the one fixed system directory. Those checks are about importing new code;
they do not attest all previously loaded shell code or process memory.

The proposed keymap collector bounds retained bytes and producer CPU time. Zsh
5.9 formats a complete key-binding macro before writing it, so a large existing
macro can cause additional allocation before output is refused. This is not a
total heap or resident-memory limit. Installed startup, editor restoration,
user-input cancellation and the complete receipt sequence still require native
end-to-end qualification before automatic verification can be advertised.
