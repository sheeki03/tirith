# Uninstall

Removing files in your home directory needs no administrator privileges.
System packages, a root-owned approval helper, and its system keyring require
administrator privileges. The examples use `sudo` for those operations;
omit it when already in a root session. You do not need to install `sudo`
to remove Tirith. See [installation privileges](install-privileges.md) for
the requirements of each distribution channel.

## Remove shell hook

Before deleting the binary, review and remove Tirith-owned startup blocks:

```sh
tirith setup shell --shell zsh --remove --dry-run
tirith setup shell --shell zsh --remove
```

Select the shell you configured (`bash`, `zsh`, `fish`, `nushell`, `powershell`
or `pwsh`). The shared resolver accounts for custom shell roots. Managed removal
preserves manually added lines and unrelated settings; remove your own
`tirith init` line separately. The paths below are common defaults, not a list
that overrides `ZDOTDIR`, XDG paths or the actual PowerShell profile:


| Shell | Config file |
|-------|-------------|
| zsh | `~/.zshrc` |
| bash | `~/.bashrc` |
| fish | `~/.config/fish/config.fish` |
| PowerShell | `$PROFILE` |
| Nushell | `$nu.config-path` |

Open a fresh terminal after removal so the old loaded hook is no longer active.
Stop any Tirith service you started before deleting its executable or state.

## Remove AI-agent integrations

Before removing the binary, remove the Tirith-owned hook, plugin, MCP, or
gateway entry from every host configured with `tirith setup`. Setup preserves
unrelated host settings and may create a sibling backup when it changes an
existing file; do not delete an entire shared host configuration directory.

There is not yet a universal `tirith setup --uninstall` operation because the
19 hosts use different ownership and merge contracts. Use the
[agent integration matrix](../mcp/clients/mcp-only-agents.md) to locate the
exact user/project artifacts for Claude Code, Cline, Codex, GitHub Copilot CLI,
Continue, Cursor, fx, Gemini CLI, Grok Build, Kiro, OMP, OpenClaw, OpenCode,
OpenHands, Pi CLI, Prime Agent, Roo Code, VS Code, and Windsurf. Restart the
host after removing its Tirith entry, then run `tirith doctor` while Tirith is
still installed to check for any remaining effective integration.

## Remove binary

### Homebrew
```sh
brew uninstall tirith
```

### npm
```sh
npm uninstall -g tirith
```

### Cargo
```sh
cargo uninstall tirith
```

### Scoop (Windows)
```powershell
scoop uninstall tirith
```

### Chocolatey (Windows)
```powershell
choco uninstall tirith
```

### AUR (Arch Linux)
```sh
pacman -Rns tirith
# or: yay -Rns tirith
# or: paru -Rns tirith
```

### Debian / Ubuntu (.deb)
```sh
sudo dpkg -r tirith
```

### Fedora / RHEL / CentOS (.rpm)
```sh
sudo dnf remove tirith
# or for older systems: sudo yum remove tirith
```

### Shell script install
```sh
rm ~/.local/bin/tirith
```

If you enabled the optional package-approval helper, remove it from an
administrator session after all installations using it have been removed:

```sh
sudo rm -f /usr/local/libexec/tirith-package-approval-authority
sudo rm -f /usr/local/libexec/tirith-package-approval-authority.tirith-previous
sudo rm -f /usr/local/libexec/tirith-package-approval-authority.tirith-previous.absent
```

### Nix
If installed via `nix profile install`:
```sh
nix profile remove github:sheeki03/tirith
```
Note: `nix run` doesn't install anything permanently.

### Docker
```sh
docker rmi ghcr.io/sheeki03/tirith
```

### asdf
```sh
asdf uninstall tirith
asdf plugin remove tirith
```

### Oh-My-Zsh plugin
Remove `tirith` from the plugins list in `~/.zshrc`, then:
```sh
rm -rf ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/tirith
```

### Manual
Delete the `tirith` binary from your PATH. On x86_64 Linux, also remove the
matching root-owned helper if it was installed manually:

```sh
sudo rm -f /usr/local/libexec/tirith-package-approval-authority
sudo rm -f /usr/local/libexec/tirith-package-approval-authority.tirith-previous
sudo rm -f /usr/local/libexec/tirith-package-approval-authority.tirith-previous.absent
```

## Remove data

Uninstalling the binary does not delete policy, exceptions, history, private
operation journals, support bundles or retained recovery files. Review and
export anything you need before deletion; deleting recovery state removes its
status/retry/undo information. Close services and remove integrations first.

Linux and macOS use XDG locations. With no overrides, the directories are:

```sh
rm -rf ~/.config/tirith       # policy, exceptions and user settings
rm -rf ~/.local/share/tirith  # audit log, receipts and materialized hooks
rm -rf ~/.local/state/tirith  # operation/recovery state and support bundles
rm -rf ~/.cache/tirith        # cached remote policy
```

If `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME` or `XDG_CACHE_HOME` is set, review the
corresponding `tirith` subdirectory there instead. The current macOS CLI does
not use `~/Library/Application Support/tirith` or `~/Library/Preferences/tirith`
as these default stores. A separately configured audit log, downloaded bundle,
export or binary rollback sidecar also remains at its chosen location; inspect
those paths rather than deleting a shared parent directory.

On Windows, config and data use the Tirith directory under `%APPDATA%`. State
uses `%USERPROFILE%\.local\state\tirith`, or the `tirith` subdirectory under
`XDG_STATE_HOME` when configured. The remote-policy cache uses
`%USERPROFILE%\.cache\tirith`, or the `tirith` subdirectory under
`XDG_CACHE_HOME` when configured. `%LOCALAPPDATA%\tirith` can also contain the
user installation; remove it only after reviewing the installation and paths.

```powershell
Remove-Item -Recurse "$env:APPDATA\tirith"
Remove-Item -Recurse "$env:USERPROFILE\.local\state\tirith"
Remove-Item -Recurse "$env:USERPROFILE\.cache\tirith"
```

Only after all installations using the shared native package-approval authority
are gone, remove its system keyring from an administrator session:

```sh
sudo rm -rf /etc/tirith/package-approval
```

Administrator privileges are only needed for protected system paths. Removing
user-owned data does not require sudo.
