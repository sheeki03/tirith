# Uninstall

## Remove shell hook

Remove the `eval "$(tirith init)"` line from your shell config:

| Shell | Config file |
|-------|-------------|
| zsh | `~/.zshrc` |
| bash | `~/.bashrc` |
| fish | `~/.config/fish/config.fish` |
| PowerShell | `$PROFILE` |

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
Delete the `tirith` binary from your PATH.

## Remove data

tirith stores data in XDG-compliant directories:

```sh
# Remove config (policy, allowlist, blocklist)
rm -rf ~/.config/tirith

# Remove data (audit log, receipts, materialized hooks, last_trigger)
rm -rf ~/.local/share/tirith
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
