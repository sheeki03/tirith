# Installation and administrator privileges

Tirith's ordinary checks, shell integration, agent setup, and doctor do not
require sudo or administrator privileges. Installing into a protected system
directory or changing a system package database requires an administrator;
sudo is one way to obtain that access, and an existing root session also works.

| Channel | Install, update, and removal | Native package approval |
| --- | --- | --- |
| Debian / Ubuntu `.deb` | Administrator manages the system package database. No sudo dependency or suggestion. | The package ships an inert root-owned helper on x86_64 Linux. Explicit issuance also needs trusted `/usr/bin/sudo`. |
| RPM | Administrator manages the system package database. No sudo dependency or suggestion. | The x86_64 package ships an inert helper; explicit issuance needs trusted `/usr/bin/sudo`. |
| AUR | Build as the normal user; package installation/removal needs an administrator. No sudo dependency or suggestion. | The x86_64 package ships an inert helper. The aarch64 package does not support issuance. |
| Shell installer | Defaults to the user's `~/.local/bin` and needs no elevation for a fresh install. An existing helper is updated as a protected pair. | Explicitly opt in with `TIRITH_INSTALL_APPROVAL_HELPER=1`; see below. |
| Manual release archive | Copy the CLI into a user-writable directory without elevation. A protected system destination requires administrator access. | A helper copied into a home directory cannot issue approvals. |
| Cargo | A user-owned Cargo prefix needs no elevation. Update with Cargo. | User-installed helper binaries are not trusted native authorities. |
| npm | A user-owned npm prefix needs no elevation. A system prefix follows its filesystem permissions. Update with npm. | The npm packages do not install a privileged helper. |
| Homebrew | Use the normal Homebrew account and package-manager update/removal commands. | The formula does not install a privileged helper. |
| Nix | A user profile needs no sudo. System configuration changes follow the host's administrator policy. | The flake does not install a trusted helper into the fixed authority paths. |
| mise / asdf | User-owned tool directories need no elevation; update/remove through the owning manager. | Extracting the archive into a tool directory does not install a trusted authority. |
| Windows installer / Scoop | The installer uses LocalAppData and user PATH; Scoop defaults to a user install. | Native package-approval issuance is unsupported on Windows. |
| Chocolatey | Follow the permissions of the Chocolatey installation, commonly an administrator-managed system prefix. The Tirith package does not request elevation itself. | Native package-approval issuance is unsupported on Windows. |
| Docker | Image construction installs system dependencies; the released runtime runs as the `tirith` user and contains no sudo dependency. | The runtime image does not install the native authority. |

## Optional helper for manual Linux installs

Tirith never installs sudo, grants passwordless sudo access, creates a sudoers
rule, starts an elevated approval service, or invokes the approval authority
as part of ordinary command checks. The packaged helper has ordinary executable
permissions, with no setuid/setgid bits. Its private key is created only during
an explicitly requested, freshly confirmed `tirith pkg approve` operation.

The shell installer accepts `TIRITH_INSTALL_APPROVAL_HELPER=0` (the default)
or `TIRITH_INSTALL_APPROVAL_HELPER=1`. Other values are rejected. On a fresh
x86_64 Linux installation, `0` installs only the CLI; checks and shell
protection work, while `tirith pkg approve` remains unavailable. Set `1` when
running the installer to also install the root-owned helper. That operation
requires a root session or trusted `/usr/bin/sudo`. The opt-in is rejected on
platforms where native approval issuance is unsupported.

If the manual helper or its rollback state already exists under
`/usr/local/libexec`, either setting preserves paired installation. Setting
`0` cannot skip updating an existing helper. Removing or replacing a protected
helper still requires administrator access.

`tirith update` and `tirith update --rollback` keep a manual installation
without helper state unprivileged. When helper state exists, they preserve the
paired update and rollback checks. Package-managed installations are directed
to their owning package manager instead of being overwritten by self-update.
`tirith verify-self` verifies a manual CLI without requiring an optional helper;
an installed manual helper, or a helper required by the Debian/RPM package,
must still match the release.

## Approval, setup, and cleanup

Fresh package approvals require a non-root interactive operator, a protected
helper, and trusted `/usr/bin/sudo` with fresh administrator confirmation.
Missing sudo, unsafe permissions, noninteractive execution, and passwordless
approval channels remain blocked. Running `tirith pkg approve` as root does
not bypass operator-presence checks. Existing approval verification continues
to require the protected public keyring.

`tirith init` prints shell integration, and `tirith setup` writes the selected
user/project integration files with ownership and symlink checks. They do not
invoke sudo. A protected destination must be configured by its administrator.
Doctor and ordinary command checks remain usable without the approval helper.

`tirith status --json` and the full `tirith doctor --json` report the separate
`package_approval` capability. `unavailable` means protected helper or sudo
prerequisites are missing or untrusted; `unsupported` identifies other
platforms. `available_on_explicit_request` means filesystem prerequisites are
present, not that any approval was issued or administrator access was verified.
All states report `automatic_elevation: false` and
`ordinary_protection_requires_sudo: false`. `pkg approve` refuses missing native
prerequisites before policy-server access, resolver execution, or quarantine
work, with an explanation of the optional feature and how to enable it.

Uninstall the CLI with its owning package manager or remove its user-owned
binary, then remove the shell/integration entries and user data. Only remove a
shared privileged helper and `/etc/tirith/package-approval` after all
installations using them are gone. The [uninstall guide](uninstall.md) lists
the exact paths.
