/// Shell hook assets embedded at compile time.
/// These are written to the user data dir on first `tirith init`.
///
/// Assets live under `crates/tirith/assets/` so they are included in the
/// crate tarball and `cargo install` / `cargo publish` work correctly.
pub const TIRITH_SH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/shell/tirith.sh"
));
pub const ZSH_HOOK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/shell/lib/zsh-hook.zsh"
));
pub const BASH_HOOK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/shell/lib/bash-hook.bash"
));
pub const FISH_HOOK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/shell/lib/fish-hook.fish"
));
pub const POWERSHELL_HOOK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/shell/lib/powershell-hook.ps1"
));

// Setup hooks embedded at compile time.
pub const TIRITH_CHECK_PY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/hooks/tirith-check.py"
));
pub const CURSOR_HOOK_SH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/hooks/cursor-hook.sh"
));
pub const VSCODE_HOOK_SH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/hooks/vscode-hook.sh"
));
pub const WINDSURF_HOOK_SH: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/hooks/windsurf-hook.sh"
));
pub const ZSHENV_GUARD: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/hooks/zshenv-guard.zsh"
));
pub const GEMINI_HOOK_PY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/hooks/tirith-security-guard-gemini.py"
));
pub const TIRITH_GUARD_TS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/hooks/tirith-guard.ts"
));
pub const GATEWAY_YAML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/configs/tirith-gateway.yaml"
));
#[allow(dead_code)]
pub const NUSHELL_HOOK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/shell/lib/nushell-hook.nu"
));
