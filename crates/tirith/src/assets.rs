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
