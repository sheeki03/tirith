# Uninstall

Removing files in your home directory needs no administrator privileges.
System packages, a root-owned approval helper, and its system keyring require
administrator privileges. The examples use `sudo` for those operations;
omit it when already in a root session. You do not need to install `sudo`
to remove Tirith. See [installation privileges](install-privileges.md) for
the requirements of each distribution channel.

## Remove shell hook

Remove the `tirith init` hook line from your shell config:

| Shell | Config file |
|-------|-------------|
| zsh | `~/.zshrc` |
| bash | `~/.bashrc` |
| fish | `~/.config/fish/config.fish` |
| PowerShell | `$PROFILE` |

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

tirith stores data in XDG-compliant directories:

```sh
# Remove config (policy, allowlist, blocklist)
rm -rf ~/.config/tirith

# Remove data (audit log, receipts, materialized hooks, last_trigger)
rm -rf ~/.local/share/tirith

# Optional: remove native package-approval keys after all Tirith installs are gone
sudo rm -rf /etc/tirith/package-approval
```

On macOS:
```sh
rm -rf ~/Library/Application\ Support/tirith
rm -rf ~/Library/Preferences/tirith
```

On Windows:
```powershell
Remove-Item -Recurse "$env:LOCALAPPDATA\tirith"
Remove-Item -Recurse "$env:APPDATA\tirith"
```
