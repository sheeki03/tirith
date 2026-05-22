//! Self-verification and self-update support (`tirith verify-self`,
//! `tirith update`, `tirith version --provenance`).
//!
//! This module holds the *effect-free, testable* core: install-method
//! detection, version parsing, and the data types describing what tirith was
//! able to verify about its own binary. The networked / filesystem-mutating
//! parts (download, atomic swap, rollback) and the entire CLI surface live in
//! `tirith::cli::selfupdate`.
//!
//! ## What the release pipeline actually produces
//!
//! `.github/workflows/release.yml` publishes, per `v*` tag:
//!
//!   * per-target archives `tirith-<target>.tar.gz` (`.zip` on Windows),
//!     each containing the `tirith` binary plus completions and the man page;
//!   * `checksums.txt` — `sha256sum` output over the **archive files**;
//!   * `checksums.txt.sig` + `checksums.txt.pem` — a cosign *keyless*
//!     (Sigstore) signature over `checksums.txt`, with signing identity
//!     `github.com/sheeki03/tirith` and OIDC issuer
//!     `https://token.actions.githubusercontent.com`.
//!
//! Two consequences drive this module's honesty guarantees:
//!
//!   1. The checksum is over the **archive**, not the bare binary. The
//!      installed binary's own SHA-256 does not appear anywhere in a release.
//!      So "verify the running binary" must mean: re-download the archive for
//!      this exact version+target, confirm the archive matches `checksums.txt`,
//!      then confirm the binary extracted from that archive is byte-identical
//!      to the running binary.
//!   2. cosign keyless verification needs the `cosign` binary (it talks to
//!      Rekor/Fulcio). tirith has no in-process Sigstore implementation, so
//!      signature verification is only possible when `cosign` is on `PATH`.
//!      When it is absent, signature verification is honestly *unavailable* —
//!      never silently reported as "verified".

use std::path::{Path, PathBuf};

/// How this tirith binary appears to have been installed. Detection is
/// best-effort and deliberately conservative: when in doubt we report
/// [`InstallMethod::Unknown`] rather than guess, because a wrong guess here
/// could lead `tirith update` to clobber a package-manager-managed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallMethod {
    /// The `install.sh` tarball install, or a hand-placed standalone binary.
    /// This is the ONLY method tirith may self-update or roll back, because
    /// tirith owns the file and no package manager tracks it.
    SelfManaged,
    /// Homebrew (`brew install`). Path lives under a Homebrew Cellar/prefix.
    Homebrew,
    /// `cargo install tirith`. Path lives under a Cargo install root
    /// (`$CARGO_HOME/bin` or `~/.cargo/bin`).
    Cargo,
    /// npm (`npm install -g tirith`). Path lives under a `node_modules` tree.
    Npm,
    /// Scoop (Windows). Path lives under a `scoop\apps` tree.
    Scoop,
    /// Arch User Repository / pacman. Binary is a system path owned by pacman.
    Aur,
    /// A Debian/Ubuntu `.deb` install (`apt`, `dpkg`).
    Apt,
    /// An RPM install (`dnf`, `yum`, `rpm`).
    Dnf,
    /// Could not be determined. Treated like a package-managed install for
    /// safety: `tirith update` will NOT self-modify, it will only advise.
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

    /// Whether tirith may safely replace its own binary in place for this
    /// install method. True ONLY for [`InstallMethod::SelfManaged`]: every
    /// other method (including `Unknown`) is managed by something else, and
    /// self-modifying it would desync the package manager's database, break
    /// its own upgrade path, or get reverted on the next `brew upgrade`.
    pub fn is_self_replaceable(&self) -> bool {
        matches!(self, InstallMethod::SelfManaged)
    }

    /// The exact command the user should run to upgrade a package-managed
    /// install, or `None` for a self-managed install (tirith handles it) or an
    /// unknown install (no command can be recommended honestly).
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
                // tirith is not in the official Debian/Ubuntu archives; the
                // .deb is a GitHub release artifact, so `apt upgrade` will not
                // find it. Be honest about that.
                Some("download the latest tirith_*.deb from the GitHub releases page and `sudo dpkg -i` it")
            }
            InstallMethod::Dnf => {
                Some("download the latest tirith-*.rpm from the GitHub releases page and `sudo rpm -U` it")
            }
            InstallMethod::SelfManaged | InstallMethod::Unknown => None,
        }
    }
}

/// Detect the install method from the *canonicalized* path of the running
/// binary. The caller passes the already-resolved absolute path (resolving
/// symlinks / npm wrappers is done by `cli::resolve_effective_tirith_target`),
/// so this function is a pure path-shape classifier and is fully unit-testable.
///
/// The path is matched case-insensitively on Windows-style components only
/// where it matters (Scoop); everything else uses exact component matching.
pub fn detect_install_method(canonical_path: &Path) -> InstallMethod {
    // Lowercased path segments, for whole-segment checks. We look at the
    // *whole* resolved path, not just the parent dir, because package managers
    // each have a recognizable directory layout.
    //
    // The string is split on BOTH separators (`/` and `\`) regardless of the
    // host OS: a Windows Scoop path classified on a Unix host (e.g. in a unit
    // test, or a path read from a file) would otherwise be a single opaque
    // `Component` and the segment checks would all miss. Splitting the raw
    // string makes the classifier host-OS-independent.
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

    // Scoop (Windows): `…\scoop\apps\tirith\…`. Match the `scoop` + `apps`
    // pair so an unrelated dir literally named "apps" does not trip it.
    if has("scoop") && has("apps") {
        return InstallMethod::Scoop;
    }

    // Homebrew: the Cellar, or an opt/bin under a `homebrew` or `linuxbrew`
    // prefix. `/opt/homebrew/...`, `/usr/local/Cellar/...`,
    // `/home/linuxbrew/.linuxbrew/...`.
    if has("cellar")
        || path_lower.contains("/homebrew/")
        || path_lower.contains("/linuxbrew/")
        || path_lower.contains("\\homebrew\\")
    {
        return InstallMethod::Homebrew;
    }

    // Cargo: `$CARGO_HOME/bin/tirith` or `~/.cargo/bin/tirith`. The `.cargo`
    // component is the reliable marker; `registry`/`git` subtrees are build
    // artifacts, not installs, but `cargo install` always lands in `bin`.
    if has(".cargo") {
        return InstallMethod::Cargo;
    }

    // System package managers (Linux): a `.deb` from cargo-deb installs the
    // binary to `/usr/bin/tirith`; the RPM spec installs to `/usr/bin` too.
    // We cannot tell `apt` from `dnf` from the path alone — both use
    // `/usr/bin` — so this branch is only reached as a hint and the caller
    // refines it with `os-release` / a package-database probe. From the path
    // alone we can only say "a system path we must not self-modify".
    //
    // Returning `Unknown` here (rather than guessing `Apt`) is the safe
    // choice: `Unknown` is already treated as non-self-replaceable, and the
    // CLI layer does the real apt-vs-dnf disambiguation with `detect_system_pm`.
    if path_lower.starts_with("/usr/bin/")
        || path_lower.starts_with("/usr/local/bin/")
        || path_lower.starts_with("/bin/")
    {
        return InstallMethod::Unknown;
    }

    // A binary under the user's `~/.local/bin` (the install.sh default) — or
    // anywhere else not recognized above — is treated as self-managed: that is
    // exactly where `install.sh` places it, and a hand-dropped standalone
    // binary lives in user-writable space too. This is the install.sh path.
    if path_lower.contains("/.local/bin/") {
        return InstallMethod::SelfManaged;
    }

    // Anything else: be honest. We do not know. `Unknown` is non-replaceable.
    InstallMethod::Unknown
}

/// Refine a [`InstallMethod::Unknown`] coming from a system-path binary into
/// `Apt` vs `Dnf` using an `/etc/os-release`-style ID list. `os_release_ids`
/// is the set of lowercased tokens from the `ID` and `ID_LIKE` fields
/// (e.g. `["ubuntu", "debian"]` or `["fedora", "rhel"]`). Passed in so the
/// function is testable without reading `/etc`.
///
/// Returns the original method unchanged if it is not `Unknown` (a confidently
/// detected method is never downgraded) or if the OS family is unrecognized.
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

/// The target triple this binary was built for, as used in release archive
/// names (`tirith-<target>.tar.gz`). Built from `std::env::consts` so it is
/// correct for the running binary without a build script.
///
/// Returns `None` for a platform tirith does not publish a release artifact
/// for (so the caller can honestly say "no release artifact for this target").
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

/// The release archive file name for a given target triple. Windows ships a
/// `.zip`; every other target ships a `.tar.gz`.
pub fn release_archive_name(target: &str) -> String {
    if target.contains("windows") {
        format!("tirith-{target}.zip")
    } else {
        format!("tirith-{target}.tar.gz")
    }
}

/// A parsed semantic version (`MAJOR.MINOR.PATCH`), enough for tirith's own
/// release comparison. Pre-release / build metadata are not used by tirith
/// releases, so they are intentionally not modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemVer {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl SemVer {
    /// Parse `MAJOR.MINOR.PATCH`, tolerating a leading `v` and surrounding
    /// whitespace. Returns `None` for anything not in that exact shape — a
    /// strict parser is correct here, because a version we cannot parse must
    /// not be silently treated as "older" or "newer".
    pub fn parse(s: &str) -> Option<SemVer> {
        let s = s.trim();
        let s = s.strip_prefix('v').unwrap_or(s);
        // Reject pre-release / build-metadata forms explicitly rather than
        // parsing a partial prefix of them.
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

/// The verification outcome for the running binary or for a downloaded
/// candidate. The variants are ordered weakest → strongest in
/// confidence; never report a stronger variant than the evidence supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Full provenance verified: the artifact's SHA-256 matched the signed
    /// `checksums.txt`, AND the cosign signature over `checksums.txt` verified
    /// against the expected Sigstore identity.
    VerifiedSigned,
    /// The artifact's SHA-256 matched `checksums.txt`, but the cosign
    /// signature could not be checked — `cosign` is not installed. The
    /// checksum match still proves the bytes are what that release published,
    /// but not (cryptographically, here) that the release itself is genuine.
    VerifiedChecksumOnly,
    /// Verification could not be performed at all. `reason` says why
    /// (offline, a dev build with no matching release, an unknown install,
    /// the running version is not a published release, …). This is NOT a
    /// failure verdict — it is an honest "unknown".
    Unverified { reason: String },
    /// Verification ran and FAILED: a checksum mismatch, a signature that did
    /// not verify, or a signing identity that did not match. `reason` carries
    /// the detail. This is a hard failure and must abort an update.
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

    /// Whether this status represents a *positive* verification of integrity
    /// (the bytes match the published checksum). Both signed and
    /// checksum-only count; unverified and failed do not.
    pub fn is_integrity_ok(&self) -> bool {
        matches!(
            self,
            VerificationStatus::VerifiedSigned | VerificationStatus::VerifiedChecksumOnly
        )
    }

    /// Whether an update may proceed given this status when `--verify` was
    /// requested. Only a hard `Failed` blocks; an honest `Unverified` is
    /// surfaced to the user but the *decision* to block on it is the CLI's
    /// (it does, for `--verify`). Exposed for testing the contract.
    pub fn is_hard_failure(&self) -> bool {
        matches!(self, VerificationStatus::Failed { .. })
    }
}

/// Provenance of the running binary, for `tirith version --provenance` and as
/// the basis of `tirith verify-self`.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// Compile-time crate version (`CARGO_PKG_VERSION`).
    pub version: String,
    /// Absolute path of the running executable (best-effort).
    pub binary_path: Option<PathBuf>,
    /// SHA-256 of the running executable's own bytes, lowercase hex.
    pub binary_sha256: Option<String>,
    /// Detected install method.
    pub install_method: InstallMethod,
    /// Release target triple, or `None` for an unpublished platform.
    pub target: Option<String>,
    /// `true` when this looks like a local dev/debug build rather than a
    /// release binary (see [`looks_like_dev_build`]).
    pub dev_build: bool,
    /// `true` when the running binary's path could NOT be fully resolved
    /// (symlink / npm-wrapper / shim canonicalization failed) and the
    /// unresolved path was used as a fallback. The install-method
    /// classification — and therefore any "is this a self-managed install"
    /// decision — is then made from a possibly-wrong path, so consumers
    /// (`version --provenance`, `verify-self`) should note lower confidence.
    pub path_resolution_failed: bool,
}

/// Heuristic: does the running binary look like a local dev build rather than
/// an installed release? A dev build cannot be verified against any release
/// checksum, so `verify-self` must say so honestly instead of failing.
///
/// `binary_path` is the canonicalized executable path; `debug_assertions` is
/// whether the binary was compiled without optimizations (passed in so the
/// function stays testable — the CLI passes `cfg!(debug_assertions)`).
pub fn looks_like_dev_build(binary_path: Option<&Path>, debug_assertions: bool) -> bool {
    if debug_assertions {
        return true;
    }
    // A release-profile binary sitting inside a Cargo `target/` directory is
    // a `cargo build --release` artifact from a checkout, not an install.
    //
    // The Cargo layout is `target/release/tirith` or, with `--target`,
    // `target/<triple>/release/tirith`. In BOTH layouts the `target`
    // component is immediately followed by either `release`/`debug` (the
    // profile dir) or the target triple. Matching a bare `target` component
    // anywhere AND a bare `release`/`debug` component anywhere — independently
    // — is too loose: a perfectly normal install under, say,
    // `…/target/bin/release/tirith` would misclassify as a dev build. Require
    // the `target` component to be IMMEDIATELY followed by `release` or
    // `debug` (covering `target/release/...`) — the cross-compiled
    // `target/<triple>/release/...` is handled by also accepting a triple
    // component between them.
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
            // A Rust target triple (`x86_64-unknown-linux-gnu`,
            // `aarch64-apple-darwin`, …): contains `-`, no path-ish chars.
            s.to_str()
                .map(|t| t.contains('-') && !t.contains(' ') && !t.contains('.'))
                .unwrap_or(false)
        };
        for (i, c) in comps.iter().enumerate() {
            if *c != std::ffi::OsStr::new("target") {
                continue;
            }
            // `target/release` or `target/debug`.
            if comps.get(i + 1).is_some_and(|n| is_profile(n)) {
                return true;
            }
            // `target/<triple>/release` or `target/<triple>/debug`.
            if comps.get(i + 1).is_some_and(|n| looks_like_triple(n))
                && comps.get(i + 2).is_some_and(|n| is_profile(n))
            {
                return true;
            }
        }
    }
    false
}

/// Parse a GNU-coreutils `checksums.txt` (`sha256sum` output: `<hex>  <name>`)
/// and return the lowercase hex digest recorded for `archive_name`, if any.
///
/// `sha256sum` separates the digest from the name with **two** spaces (the
/// second being the "text mode" indicator); a single space after the digest
/// is also tolerated. Returns `Err` if the file lists the same archive name
/// more than once (a malformed or tampered checksum file — never silently
/// pick one).
pub fn checksum_for(checksums_txt: &str, archive_name: &str) -> Result<Option<String>, String> {
    let mut found: Option<String> = None;
    for line in checksums_txt.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            continue;
        }
        // Split into <digest> <rest>. The digest is the first whitespace-
        // delimited token; the name is the remainder with one leading
        // separator char (` ` or `*`) stripped.
        let mut it = line.splitn(2, char::is_whitespace);
        let digest = match it.next() {
            Some(d) if !d.is_empty() => d,
            _ => continue,
        };
        let rest = match it.next() {
            Some(r) => r,
            None => continue,
        };
        // `rest` begins with one extra space (text mode) or `*` (binary
        // mode), or is the name directly. Strip a single leading marker.
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
            // Identical duplicate line — tolerate, but a conflicting one above
            // already errored.
        }
        found = Some(digest_l);
    }
    Ok(found)
}

/// True for a 64-char lowercase hex string (a SHA-256 digest).
fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Case-insensitive, whitespace-tolerant equality for two hex digests.
///
/// This is NOT a constant-time comparison: it trims, lowercases, and uses a
/// plain `String` equality that short-circuits. That is fine here — the
/// digests being compared (a SHA-256 of a release archive against the digest
/// in a public `checksums.txt`) are public values, so comparison timing leaks
/// nothing. The trim/lowercase normalization just makes a digest copied with
/// stray whitespace or mixed case still compare equal.
pub fn digest_eq(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // --- install-method detection -----------------------------------------

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
        // A /usr/bin binary is package-managed (deb/rpm). It must NOT be
        // classified self-managed — that would let `update` clobber it.
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
        // Self-managed and unknown deliberately have no PM command.
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
        // A confidently-detected Homebrew install must survive refinement
        // even if os-release looks like Debian.
        let m = refine_system_pm(InstallMethod::Homebrew, &["debian".to_string()]);
        assert_eq!(m, InstallMethod::Homebrew);
    }

    #[test]
    fn refine_system_pm_unknown_os_stays_unknown() {
        let m = refine_system_pm(InstallMethod::Unknown, &["plan9".to_string()]);
        assert_eq!(m, InstallMethod::Unknown);
    }

    // --- version parsing --------------------------------------------------

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
        // Pre-release / build metadata are rejected, not partially parsed.
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

    // --- release target / archive naming ----------------------------------

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

    // --- dev-build heuristic ----------------------------------------------

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
        // F24: a real install whose path merely happens to contain a `target`
        // component AND, separately, a `release` component must NOT be
        // misclassified as a dev build. Here `target` is followed by `bin`,
        // not by `release`/`debug`, so the Cargo `target/release` layout does
        // not actually appear.
        let p = PathBuf::from("/opt/target/bin/release/tirith");
        assert!(
            !looks_like_dev_build(Some(&p), false),
            "non-adjacent target/release components must not be a dev build"
        );
        // A user literally installing into `~/.local/share/target/release`
        // would be unusual, but the marker is the Cargo layout, not the words.
        let p2 = PathBuf::from("/home/bob/target-archive/old/release-notes/tirith");
        assert!(!looks_like_dev_build(Some(&p2), false));
        // A home dir named with a leading `target` segment, binary in bin/.
        let p3 = PathBuf::from("/home/target/release-team/tirith/bin/tirith");
        assert!(!looks_like_dev_build(Some(&p3), false));
    }

    #[test]
    fn dev_build_true_only_for_adjacent_cargo_layout() {
        // F24: the two genuine Cargo layouts — `target/release` and the
        // cross-compiled `target/<triple>/release` — must still be detected.
        let plain = PathBuf::from("/home/alice/src/tirith/target/release/tirith");
        assert!(looks_like_dev_build(Some(&plain), false));
        let plain_debug = PathBuf::from("/home/alice/src/tirith/target/debug/tirith");
        assert!(looks_like_dev_build(Some(&plain_debug), false));
        let triple =
            PathBuf::from("/home/alice/src/tirith/target/aarch64-apple-darwin/release/tirith");
        assert!(looks_like_dev_build(Some(&triple), false));
    }

    // --- checksums.txt parsing --------------------------------------------

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
        // The SAME archive listed twice with DIFFERENT digests is a tampered
        // or malformed file — must error, never silently pick one.
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
        // GNU sha256sum binary mode prefixes the name with `*`.
        let txt = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd *tirith-x86_64-apple-darwin.tar.gz\n";
        assert_eq!(
            checksum_for(txt, "tirith-x86_64-apple-darwin.tar.gz").unwrap(),
            Some("d".repeat(64))
        );
    }

    // --- verification-status contract -------------------------------------

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
