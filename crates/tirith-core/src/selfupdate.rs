//! Self-verification and self-update support (`tirith verify-self`,
//! `tirith update`, `tirith version --provenance`).
//!
//! Effect-free, testable core: install-method detection, version parsing, and
//! the verification data types. The networked / fs-mutating parts (download,
//! atomic swap, rollback) and the CLI surface live in `tirith::cli::selfupdate`.
//!
//! Per `v*` tag, `release.yml` publishes per-target archives
//! (`tirith-<target>.tar.gz`, `.zip` on Windows), a `sha256sum` `checksums.txt`
//! over the ARCHIVES, and a cosign keyless (Sigstore) signature over it (identity
//! `github.com/sheeki03/tirith`, issuer `token.actions.githubusercontent.com`).
//!
//! Two honesty guarantees follow:
//!   1. The checksum is over the ARCHIVE, not the bare binary. So "verify the
//!      running binary" means: re-download this version+target's archive, confirm
//!      it matches `checksums.txt`, then confirm the extracted binary is
//!      byte-identical to the running one.
//!   2. cosign keyless verification needs the `cosign` binary (Rekor/Fulcio);
//!      tirith has no in-process Sigstore. Without `cosign` on `PATH`, signature
//!      verification is honestly *unavailable*, never reported as "verified".

use std::path::{Path, PathBuf};

/// How this tirith binary appears to have been installed. Conservative: when in
/// doubt report [`InstallMethod::Unknown`] rather than guess, since a wrong guess
/// could let `tirith update` clobber a package-manager-managed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallMethod {
    /// `install.sh` tarball or a hand-placed standalone binary. The ONLY method
    /// tirith may self-update or roll back (tirith owns the file).
    SelfManaged,
    /// Homebrew — path under a Cellar/prefix.
    Homebrew,
    /// `cargo install tirith` — path under a Cargo install root.
    Cargo,
    /// npm `-g` — path under a `node_modules` tree.
    Npm,
    /// Scoop (Windows) — path under `scoop\apps`.
    Scoop,
    /// AUR / pacman — a system path owned by pacman.
    Aur,
    /// Debian/Ubuntu `.deb` (`apt`, `dpkg`).
    Apt,
    /// RPM (`dnf`, `yum`, `rpm`).
    Dnf,
    /// Undetermined. Treated as package-managed for safety: `update` only advises.
    Unknown,
}

impl InstallMethod {
    /// Stable lowercase token for JSON output and tests.
    pub fn as_str(&self) -> &'static str {
        match self {
            InstallMethod::SelfManaged => "self-managed",
            InstallMethod::Homebrew => "homebrew",
            InstallMethod::Cargo => "cargo",
            InstallMethod::Npm => "npm",
            InstallMethod::Scoop => "scoop",
            InstallMethod::Aur => "aur",
            InstallMethod::Apt => "apt",
            InstallMethod::Dnf => "dnf",
            InstallMethod::Unknown => "unknown",
        }
    }

    /// Whether tirith may replace its own binary in place. True ONLY for
    /// [`InstallMethod::SelfManaged`]; every other method (incl. `Unknown`) is
    /// managed elsewhere, so self-modifying would desync its package database.
    pub fn is_self_replaceable(&self) -> bool {
        matches!(self, InstallMethod::SelfManaged)
    }

    /// The command to upgrade a package-managed install, or `None` for
    /// self-managed (tirith handles it) or unknown (no honest recommendation).
    pub fn upgrade_command(&self) -> Option<&'static str> {
        match self {
            InstallMethod::Homebrew => Some("brew upgrade tirith"),
            InstallMethod::Cargo => Some("cargo install tirith --force"),
            InstallMethod::Npm => Some("npm install -g tirith@latest"),
            InstallMethod::Scoop => Some("scoop update tirith"),
            InstallMethod::Aur => {
                Some("update via your AUR helper, e.g. `yay -S tirith` or `paru -S tirith`")
            }
            InstallMethod::Apt => {
                // Not in the Debian/Ubuntu archives; the .deb is a GitHub release
                // artifact, so `apt upgrade` won't find it.
                Some("download the latest tirith_*.deb from the GitHub releases page and `sudo dpkg -i` it")
            }
            InstallMethod::Dnf => {
                Some("download the latest tirith-*.rpm from the GitHub releases page and `sudo rpm -U` it")
            }
            InstallMethod::SelfManaged | InstallMethod::Unknown => None,
        }
    }
}

/// Detect the install method from the canonicalized path of the running binary.
/// The caller passes the already-resolved absolute path (symlink/npm-wrapper
/// resolution is `cli::resolve_effective_tirith_target`'s job), so this is a pure,
/// unit-testable path-shape classifier.
pub fn detect_install_method(canonical_path: &Path) -> InstallMethod {
    // Whole-segment checks over the FULL resolved path (each package manager has
    // a recognizable layout). Split on BOTH `/` and `\` regardless of host OS, so
    // a Windows Scoop path classified on Unix isn't one opaque `Component`.
    let path_lower = canonical_path.to_string_lossy().to_lowercase();
    let components: Vec<&str> = path_lower
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .collect();

    let has = |needle: &str| components.contains(&needle);

    // npm: anywhere under a `node_modules` tree.
    if has("node_modules") {
        return InstallMethod::Npm;
    }

    // Scoop (Windows): match the `scoop` + `apps` pair so an unrelated "apps"
    // dir doesn't trip it.
    if has("scoop") && has("apps") {
        return InstallMethod::Scoop;
    }

    // Homebrew: the Cellar, or an opt/bin under a `homebrew`/`linuxbrew` prefix.
    if has("cellar")
        || path_lower.contains("/homebrew/")
        || path_lower.contains("/linuxbrew/")
        || path_lower.contains("\\homebrew\\")
    {
        return InstallMethod::Homebrew;
    }

    // Cargo: the `.cargo` component is the reliable marker (`cargo install`
    // always lands in `bin`; `registry`/`git` subtrees are build artifacts).
    if has(".cargo") {
        return InstallMethod::Cargo;
    }

    // System package managers (Linux): both .deb and RPM install to `/usr/bin`,
    // so the path alone can't tell apt from dnf. Return `Unknown` (already
    // non-self-replaceable); the CLI refines apt-vs-dnf via `detect_system_pm`.
    if path_lower.starts_with("/usr/bin/")
        || path_lower.starts_with("/usr/local/bin/")
        || path_lower.starts_with("/bin/")
    {
        return InstallMethod::Unknown;
    }

    // `~/.local/bin` is the install.sh default (user-writable, hand-dropped
    // binaries too) → self-managed.
    if path_lower.contains("/.local/bin/") {
        return InstallMethod::SelfManaged;
    }

    // Anything else: unknown (non-replaceable).
    InstallMethod::Unknown
}

/// Refine a system-path [`InstallMethod::Unknown`] into `Apt` vs `Dnf` from an
/// `/etc/os-release` `ID`/`ID_LIKE` token list (passed in so it's testable
/// without reading `/etc`). Non-`Unknown` methods and unrecognized OS families
/// are returned unchanged.
pub fn refine_system_pm(method: InstallMethod, os_release_ids: &[String]) -> InstallMethod {
    if method != InstallMethod::Unknown {
        return method;
    }
    let is = |id: &str| os_release_ids.iter().any(|x| x == id);
    if is("debian") || is("ubuntu") || is("linuxmint") || is("pop") || is("raspbian") {
        return InstallMethod::Apt;
    }
    if is("fedora")
        || is("rhel")
        || is("centos")
        || is("rocky")
        || is("almalinux")
        || is("opensuse")
    {
        return InstallMethod::Dnf;
    }
    InstallMethod::Unknown
}

/// The target triple this binary was built for, as used in release archive names.
/// `None` for a platform tirith publishes no artifact for.
pub fn release_target_triple() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        _ => None,
    }
}

/// Release archive file name for a target triple (`.zip` on Windows, else `.tar.gz`).
pub fn release_archive_name(target: &str) -> String {
    if target.contains("windows") {
        format!("tirith-{target}.zip")
    } else {
        format!("tirith-{target}.tar.gz")
    }
}

/// A parsed `MAJOR.MINOR.PATCH` version. Pre-release / build metadata are not
/// used by tirith releases and intentionally not modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl SemVer {
    /// Parse `MAJOR.MINOR.PATCH` (tolerating a leading `v` and whitespace).
    /// Strict: `None` for anything else, so an unparseable version is never
    /// silently treated as older or newer.
    pub fn parse(s: &str) -> Option<SemVer> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        // Reject pre-release / build-metadata rather than parse a partial prefix.
        if s.contains('-') || s.contains('+') {
            return None;
        }
        let mut parts = s.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None; // too many components
        }
        Some(SemVer {
            major,
            minor,
            patch,
        })
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Verification outcome for the running binary or a downloaded candidate.
/// Variants are ordered weakest → strongest; never report stronger than the
/// evidence supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// SHA-256 matched signed `checksums.txt` AND the cosign signature verified
    /// against the expected Sigstore identity.
    VerifiedSigned,
    /// SHA-256 matched `checksums.txt` but the cosign signature could not be
    /// checked (`cosign` not installed) — proves the bytes, not the release.
    VerifiedChecksumOnly,
    /// Verification could not run (offline, dev build, unknown install, …).
    /// `reason` says why. An honest "unknown", not a failure.
    Unverified { reason: String },
    /// Verification ran and FAILED (checksum mismatch, bad signature, identity
    /// mismatch). A hard failure that must abort an update.
    Failed { reason: String },
}

impl VerificationStatus {
    /// Stable token for JSON output.
    pub fn token(&self) -> &'static str {
        match self {
            VerificationStatus::VerifiedSigned => "verified-signed",
            VerificationStatus::VerifiedChecksumOnly => "verified-checksum-only",
            VerificationStatus::Unverified { .. } => "unverified",
            VerificationStatus::Failed { .. } => "failed",
        }
    }

    /// Positive integrity (bytes match the published checksum): signed and
    /// checksum-only count; unverified and failed do not.
    pub fn is_integrity_ok(&self) -> bool {
        matches!(
            self,
            VerificationStatus::VerifiedSigned | VerificationStatus::VerifiedChecksumOnly
        )
    }

    /// Only a hard `Failed` blocks an update; `Unverified` is surfaced but the
    /// block decision is the CLI's. Exposed for testing the contract.
    pub fn is_hard_failure(&self) -> bool {
        matches!(self, VerificationStatus::Failed { .. })
    }
}

/// Provenance of the running binary, for `tirith version --provenance` and the
/// basis of `tirith verify-self`.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// Compile-time crate version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Absolute path of the running executable (best-effort).
    pub binary_path: Option<PathBuf>,
    /// Lowercase-hex SHA-256 of the running executable's bytes.
    pub binary_sha256: Option<String>,
    pub install_method: InstallMethod,
    /// Release target triple, or `None` for an unpublished platform.
    pub target: Option<String>,
    /// Looks like a local dev/debug build (see [`looks_like_dev_build`]).
    pub dev_build: bool,
    /// The binary's path could NOT be fully resolved (symlink/npm-wrapper/shim
    /// canonicalization failed) and the unresolved path was used. The
    /// install-method classification is then from a possibly-wrong path, so
    /// consumers should note lower confidence.
    pub path_resolution_failed: bool,
}

/// Heuristic: does the running binary look like a local dev build (which cannot
/// be verified against a release checksum, so `verify-self` says so honestly)?
///
/// `debug_assertions` is passed in (CLI passes `cfg!(debug_assertions)`) so the
/// function stays testable.
pub fn looks_like_dev_build(binary_path: Option<&Path>, debug_assertions: bool) -> bool {
    if debug_assertions {
        return true;
    }
    // A release-profile binary inside a Cargo `target/` is a checkout artifact,
    // not an install. F24: require `target` IMMEDIATELY followed by `release`/
    // `debug` (or a triple then the profile) — matching the two components
    // independently would misclassify a real install under `…/target/bin/release/`.
    if let Some(p) = binary_path {
        let comps: Vec<&std::ffi::OsStr> = p
            .components()
            .filter_map(|c| match c {
                std::path::Component::Normal(s) => Some(s),
                _ => None,
            })
            .collect();
        let is_profile = |s: &std::ffi::OsStr| {
            s == std::ffi::OsStr::new("release") || s == std::ffi::OsStr::new("debug")
        };
        let looks_like_triple = |s: &std::ffi::OsStr| {
            // A Rust target triple: contains `-`, no path-ish chars.
            s.to_str()
                .map(|t| t.contains('-') && !t.contains(' ') && !t.contains('.'))
                .unwrap_or(false)
        };
        for (i, c) in comps.iter().enumerate() {
            if *c != std::ffi::OsStr::new("target") {
                continue;
            }
            // `target/release` | `target/debug`.
            if comps.get(i + 1).is_some_and(|n| is_profile(n)) {
                return true;
            }
            // `target/<triple>/release` | `target/<triple>/debug`.
            if comps.get(i + 1).is_some_and(|n| looks_like_triple(n))
                && comps.get(i + 2).is_some_and(|n| is_profile(n))
            {
                return true;
            }
        }
    }
    false
}

/// Parse a `sha256sum` `checksums.txt` (`<hex>  <name>`) and return the
/// lowercase digest for `archive_name`, if any. `Err` if the same archive is
/// listed more than once with conflicting digests (tampered — never pick one).
pub fn checksum_for(checksums_txt: &str, archive_name: &str) -> Result<Option<String>, String> {
    let mut found: Option<String> = None;
    for line in checksums_txt.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        // <digest> = first whitespace-delimited token; name = the remainder with
        // one leading separator (` ` or `*`) stripped.
        let mut it = line.splitn(2, char::is_whitespace);
        let digest = match it.next() {
            Some(d) if !d.is_empty() => d,
            _ => continue,
        };
        let rest = match it.next() {
            Some(r) => r,
            None => continue,
        };
        // `rest` may start with a space (text mode) or `*` (binary mode); strip
        // a single leading marker.
        let name = rest
            .strip_prefix(' ')
            .or_else(|| rest.strip_prefix('*'))
            .unwrap_or(rest)
            .trim();
        if name != archive_name {
            continue;
        }
        let digest_l = digest.to_lowercase();
        if !is_hex_sha256(&digest_l) {
            return Err(format!(
                "checksums.txt entry for {archive_name} is not a valid SHA-256 digest"
            ));
        }
        if let Some(prev) = &found {
            if *prev != digest_l {
                return Err(format!(
                    "checksums.txt lists {archive_name} more than once with conflicting digests"
                ));
            }
            // Identical duplicate — tolerate (a conflicting one already errored).
        }
        found = Some(digest_l);
    }
    Ok(found)
}

/// True for a 64-char lowercase hex string (a SHA-256 digest).
fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Case-insensitive, whitespace-tolerant hex-digest equality. NOT constant-time,
/// which is fine: both digests are public values (a release archive's SHA-256 vs
/// a public `checksums.txt`), so timing leaks nothing.
pub fn digest_eq(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detect_npm_install() {
        let p = PathBuf::from(
            "/Users/alice/.nvm/versions/node/v20/lib/node_modules/@sheeki03/tirith-darwin-arm64/bin/tirith",
        );
        assert_eq!(detect_install_method(&p), InstallMethod::Npm);
    }

    #[test]
    fn detect_homebrew_cellar_install() {
        let p = PathBuf::from("/opt/homebrew/Cellar/tirith/0.3.1/bin/tirith");
        assert_eq!(detect_install_method(&p), InstallMethod::Homebrew);
    }

    #[test]
    fn detect_homebrew_linuxbrew_install() {
        let p = PathBuf::from("/home/linuxbrew/.linuxbrew/bin/tirith");
        assert_eq!(detect_install_method(&p), InstallMethod::Homebrew);
    }

    #[test]
    fn detect_cargo_install() {
        let p = PathBuf::from("/Users/alice/.cargo/bin/tirith");
        assert_eq!(detect_install_method(&p), InstallMethod::Cargo);
    }

    #[test]
    fn detect_scoop_install() {
        let p = PathBuf::from("C:\\Users\\alice\\scoop\\apps\\tirith\\current\\tirith.exe");
        assert_eq!(detect_install_method(&p), InstallMethod::Scoop);
    }

    #[test]
    fn detect_self_managed_local_bin() {
        let p = PathBuf::from("/Users/alice/.local/bin/tirith");
        assert_eq!(detect_install_method(&p), InstallMethod::SelfManaged);
    }

    #[test]
    fn detect_system_path_is_unknown_not_self_managed() {
        // A /usr/bin binary is package-managed; must NOT be self-managed (else
        // `update` could clobber it).
        let p = PathBuf::from("/usr/bin/tirith");
        let m = detect_install_method(&p);
        assert_eq!(m, InstallMethod::Unknown);
        assert!(!m.is_self_replaceable());
    }

    #[test]
    fn detect_unrecognized_path_is_unknown() {
        let p = PathBuf::from("/opt/weird/place/tirith");
        assert_eq!(detect_install_method(&p), InstallMethod::Unknown);
    }

    #[test]
    fn only_self_managed_is_replaceable() {
        assert!(InstallMethod::SelfManaged.is_self_replaceable());
        for m in [
            InstallMethod::Homebrew,
            InstallMethod::Cargo,
            InstallMethod::Npm,
            InstallMethod::Scoop,
            InstallMethod::Aur,
            InstallMethod::Apt,
            InstallMethod::Dnf,
            InstallMethod::Unknown,
        ] {
            assert!(
                !m.is_self_replaceable(),
                "{} must not be self-replaceable",
                m.as_str()
            );
        }
    }

    #[test]
    fn package_methods_have_upgrade_commands() {
        assert_eq!(
            InstallMethod::Homebrew.upgrade_command(),
            Some("brew upgrade tirith")
        );
        assert!(InstallMethod::Cargo
            .upgrade_command()
            .unwrap()
            .contains("cargo install"));
        assert!(InstallMethod::Npm
            .upgrade_command()
            .unwrap()
            .contains("npm install"));
        assert!(InstallMethod::Scoop
            .upgrade_command()
            .unwrap()
            .contains("scoop"));
        assert!(InstallMethod::Aur.upgrade_command().is_some());
        assert!(InstallMethod::Apt.upgrade_command().is_some());
        assert!(InstallMethod::Dnf.upgrade_command().is_some());
        // Self-managed and unknown have no PM command.
        assert_eq!(InstallMethod::SelfManaged.upgrade_command(), None);
        assert_eq!(InstallMethod::Unknown.upgrade_command(), None);
    }

    #[test]
    fn refine_system_pm_debian_family() {
        let m = refine_system_pm(
            InstallMethod::Unknown,
            &["ubuntu".to_string(), "debian".to_string()],
        );
        assert_eq!(m, InstallMethod::Apt);
    }

    #[test]
    fn refine_system_pm_fedora_family() {
        let m = refine_system_pm(InstallMethod::Unknown, &["fedora".to_string()]);
        assert_eq!(m, InstallMethod::Dnf);
    }

    #[test]
    fn refine_system_pm_never_downgrades_confident_method() {
        // A confident Homebrew detection survives refinement even if os-release
        // looks like Debian.
        let m = refine_system_pm(InstallMethod::Homebrew, &["debian".to_string()]);
        assert_eq!(m, InstallMethod::Homebrew);
    }

    #[test]
    fn refine_system_pm_unknown_os_stays_unknown() {
        let m = refine_system_pm(InstallMethod::Unknown, &["plan9".to_string()]);
        assert_eq!(m, InstallMethod::Unknown);
    }

    #[test]
    fn semver_parses_plain_and_v_prefixed() {
        assert_eq!(
            SemVer::parse("0.3.1"),
            Some(SemVer {
                major: 0,
                minor: 3,
                patch: 1
            })
        );
        assert_eq!(
            SemVer::parse("v1.2.3"),
            Some(SemVer {
                major: 1,
                minor: 2,
                patch: 3
            })
        );
        assert_eq!(SemVer::parse("  v2.0.0 "), SemVer::parse("2.0.0"));
    }

    #[test]
    fn semver_rejects_malformed() {
        assert_eq!(SemVer::parse(""), None);
        assert_eq!(SemVer::parse("1.2"), None);
        assert_eq!(SemVer::parse("1.2.3.4"), None);
        assert_eq!(SemVer::parse("1.2.x"), None);
        assert_eq!(SemVer::parse("latest"), None);
        // Pre-release / build metadata rejected, not partially parsed.
        assert_eq!(SemVer::parse("1.2.3-rc1"), None);
        assert_eq!(SemVer::parse("1.2.3+build"), None);
    }

    #[test]
    fn semver_orders_correctly() {
        let a = SemVer::parse("0.3.1").unwrap();
        let b = SemVer::parse("0.3.2").unwrap();
        let c = SemVer::parse("0.4.0").unwrap();
        let d = SemVer::parse("1.0.0").unwrap();
        assert!(a < b);
        assert!(b < c);
        assert!(c < d);
        assert!(a < d);
        assert_eq!(a, SemVer::parse("v0.3.1").unwrap());
    }

    #[test]
    fn release_archive_name_picks_extension_by_os() {
        assert_eq!(
            release_archive_name("x86_64-unknown-linux-gnu"),
            "tirith-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            release_archive_name("aarch64-apple-darwin"),
            "tirith-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            release_archive_name("x86_64-pc-windows-msvc"),
            "tirith-x86_64-pc-windows-msvc.zip"
        );
    }

    #[test]
    fn dev_build_true_when_debug_assertions() {
        assert!(looks_like_dev_build(None, true));
    }

    #[test]
    fn dev_build_true_for_release_artifact_in_target_dir() {
        let p = PathBuf::from("/home/alice/src/tirith/target/release/tirith");
        assert!(looks_like_dev_build(Some(&p), false));
        let p2 =
            PathBuf::from("/home/alice/src/tirith/target/x86_64-unknown-linux-gnu/release/tirith");
        assert!(looks_like_dev_build(Some(&p2), false));
    }

    #[test]
    fn dev_build_false_for_installed_release_binary() {
        let p = PathBuf::from("/Users/alice/.local/bin/tirith");
        assert!(!looks_like_dev_build(Some(&p), false));
        let p2 = PathBuf::from("/opt/homebrew/Cellar/tirith/0.3.1/bin/tirith");
        assert!(!looks_like_dev_build(Some(&p2), false));
    }

    #[test]
    fn dev_build_false_when_target_and_release_are_not_adjacent() {
        // F24: a path with `target` and `release` components that are NOT
        // adjacent must not be a dev build (the marker is the Cargo layout, not
        // the words). Here `target` is followed by `bin`.
        let p = PathBuf::from("/opt/target/bin/release/tirith");
        assert!(
            !looks_like_dev_build(Some(&p), false),
            "non-adjacent target/release components must not be a dev build"
        );
        let p2 = PathBuf::from("/home/bob/target-archive/old/release-notes/tirith");
        assert!(!looks_like_dev_build(Some(&p2), false));
        let p3 = PathBuf::from("/home/target/release-team/tirith/bin/tirith");
        assert!(!looks_like_dev_build(Some(&p3), false));
    }

    #[test]
    fn dev_build_true_only_for_adjacent_cargo_layout() {
        // F24: both genuine Cargo layouts (`target/release` and
        // `target/<triple>/release`) must still be detected.
        let plain = PathBuf::from("/home/alice/src/tirith/target/release/tirith");
        assert!(looks_like_dev_build(Some(&plain), false));
        let plain_debug = PathBuf::from("/home/alice/src/tirith/target/debug/tirith");
        assert!(looks_like_dev_build(Some(&plain_debug), false));
        let triple =
            PathBuf::from("/home/alice/src/tirith/target/aarch64-apple-darwin/release/tirith");
        assert!(looks_like_dev_build(Some(&triple), false));
    }

    #[test]
    fn checksum_for_extracts_matching_entry() {
        let txt = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tirith-x86_64-unknown-linux-gnu.tar.gz
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  tirith-aarch64-apple-darwin.tar.gz
";
        assert_eq!(
            checksum_for(txt, "tirith-aarch64-apple-darwin.tar.gz").unwrap(),
            Some("b".repeat(64))
        );
        assert_eq!(
            checksum_for(txt, "tirith-x86_64-unknown-linux-gnu.tar.gz").unwrap(),
            Some("a".repeat(64))
        );
    }

    #[test]
    fn checksum_for_missing_entry_is_none() {
        let txt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tirith-x86_64-unknown-linux-gnu.tar.gz\n";
        assert_eq!(checksum_for(txt, "tirith-nonexistent.zip").unwrap(), None);
    }

    #[test]
    fn checksum_for_rejects_conflicting_duplicates() {
        // Same archive, different digests = tampered/malformed → must error.
        let txt = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  tirith-x86_64-apple-darwin.tar.gz
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  tirith-x86_64-apple-darwin.tar.gz
";
        assert!(checksum_for(txt, "tirith-x86_64-apple-darwin.tar.gz").is_err());
    }

    #[test]
    fn checksum_for_tolerates_identical_duplicate() {
        let txt = "\
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  tirith-x86_64-apple-darwin.tar.gz
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  tirith-x86_64-apple-darwin.tar.gz
";
        assert_eq!(
            checksum_for(txt, "tirith-x86_64-apple-darwin.tar.gz").unwrap(),
            Some("c".repeat(64))
        );
    }

    #[test]
    fn checksum_for_rejects_non_hex_digest() {
        let txt = "not-a-valid-hex-digest-not-a-valid-hex-digest-not-a-valid-xxxxxxx  tirith-x86_64-apple-darwin.tar.gz\n";
        assert!(checksum_for(txt, "tirith-x86_64-apple-darwin.tar.gz").is_err());
    }

    #[test]
    fn checksum_for_tolerates_binary_mode_star_separator() {
        // sha256sum binary mode prefixes the name with `*`.
        let txt = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd *tirith-x86_64-apple-darwin.tar.gz\n";
        assert_eq!(
            checksum_for(txt, "tirith-x86_64-apple-darwin.tar.gz").unwrap(),
            Some("d".repeat(64))
        );
    }

    #[test]
    fn verification_status_integrity_and_failure_flags() {
        assert!(VerificationStatus::VerifiedSigned.is_integrity_ok());
        assert!(VerificationStatus::VerifiedChecksumOnly.is_integrity_ok());
        assert!(!VerificationStatus::Unverified {
            reason: "offline".into()
        }
        .is_integrity_ok());
        assert!(!VerificationStatus::Failed {
            reason: "mismatch".into()
        }
        .is_integrity_ok());

        assert!(VerificationStatus::Failed { reason: "x".into() }.is_hard_failure());
        assert!(!VerificationStatus::Unverified { reason: "x".into() }.is_hard_failure());
        assert!(!VerificationStatus::VerifiedSigned.is_hard_failure());
    }

    #[test]
    fn verification_status_tokens_are_stable() {
        assert_eq!(
            VerificationStatus::VerifiedSigned.token(),
            "verified-signed"
        );
        assert_eq!(
            VerificationStatus::VerifiedChecksumOnly.token(),
            "verified-checksum-only"
        );
        assert_eq!(
            VerificationStatus::Unverified {
                reason: String::new()
            }
            .token(),
            "unverified"
        );
        assert_eq!(
            VerificationStatus::Failed {
                reason: String::new()
            }
            .token(),
            "failed"
        );
    }

    #[test]
    fn digest_eq_is_case_insensitive_and_strict() {
        assert!(digest_eq("ABCDEF", "abcdef"));
        assert!(digest_eq("  abcdef  ", "abcdef"));
        assert!(!digest_eq("abcdef", "abcde"));
        assert!(!digest_eq("abcdef", "abcde0"));
    }
}
