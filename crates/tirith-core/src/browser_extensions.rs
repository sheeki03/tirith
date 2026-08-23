//! C16: read-only integrity audit of installed Chromium-family extensions.
//!
//! `tirith browser audit` answers one question: are the extensions loaded into
//! this browser profile the same ones that were there last time, byte for byte.
//! It is explicit, one-shot, and read-only. It never removes, quarantines, or
//! watches anything.
//!
//! # The privacy boundary is the point of this module
//!
//! A security tool that reads a user's browsing history to check their
//! extensions has done more harm than the extensions it audits. So the read set
//! is closed, enumerated here, and enforced in one place
//! ([`open_audit_file`]).
//!
//! READ:
//!
//! - `<user-data>/<profile>/Extensions/<id>/<version>/**`: every regular file,
//!   for the sorted-tree digest. `manifest.json` is additionally parsed.
//! - `<profile>/Preferences` and `<profile>/Secure Preferences`, restricted to
//!   [`PREFERENCES_ALLOWED_FIELDS`] beneath `extensions.settings.<id>`, and only
//!   for extension ids already discovered on disk. Install class genuinely lives
//!   there and nowhere else; see [`read_install_classes`] for why nothing else
//!   can escape that read.
//!
//! NEVER READ:
//!
//! - `Cookies`, `History`, `Login Data`, `Web Data`, `Local Storage/leveldb`,
//!   `IndexedDB/`, `Local Extension Settings/`, `Sync Extension Settings/`, any
//!   wallet database, any seed material.
//! - `<user-data>/Local State`. Chrome keeps the human profile names there under
//!   `profile.info_cache.<dir>.{name,user_name,gaia_id}`, and `user_name` is the
//!   signed-in Google account email. Profile identity in this module is
//!   therefore the profile DIRECTORY NAME and nothing else. That is a deliberate
//!   capability reduction: the audit cannot tell an operator which human a
//!   profile belongs to, and it should not be able to.
//! - Preferences as a document. The three fields in
//!   [`PREFERENCES_ALLOWED_FIELDS`] are converted to typed values inside
//!   [`read_install_classes`]; no `serde_json::Value` from that file crosses its
//!   return boundary.
//!
//! Every open is additionally gated, in [`open_audit_file`], on TWO independent
//! predicates:
//!
//! - [`crate::sensitive_assets::classify_path`] returning `None`, the shared
//!   catalogue's own statement that a path is not a credential store, a wallet
//!   store, or wallet extension storage. It is reused rather than re-hand-rolled
//!   because it already carves the extension SOURCE tree out of sensitivity.
//! - No path component naming one of [`NEVER_READ_PROFILE_STORES`]. The
//!   catalogue does NOT cover the list above on its own: it calls a browser
//!   storage root sensitive only when a hardcoded WALLET extension id is also in
//!   the path, so a plain `Cookies`, `History`, or `Local Storage/leveldb` path
//!   falls straight through it. The lexical list is what makes the NEVER READ
//!   set above a statement about this module rather than about which extension
//!   ids happen to be catalogued.
//!
//! Neither predicate can see a HARD link, which is not a symlink and carries no
//! distinguishing name, so a regular file inside an extension tree with more
//! than one link is refused outright ([`RejectionReason::HardLink`]) rather than
//! hashed: the same bytes are reachable under a name the walk never selected.
//!
//! # Risk and drift are different questions
//!
//! [`PermissionRisk`] says how much authority an extension holds.
//! [`ExtensionDrift`] says what changed since the baseline. A wallet extension
//! legitimately holding `<all_urls>` is not the same event as a wallet extension
//! whose bytes changed without its version changing, and an operator has to be
//! able to tell them apart. Nothing in this module lets a risk level create a
//! drift entry or a drift entry raise a risk level.
//!
//! Wallet extension ids are FIXTURES for labelling only, read from the shared
//! [`crate::sensitive_assets::SENSITIVE_PATH_DEFINITIONS`] catalogue. They are
//! never a trust anchor: a matching id changes no digest, no risk level, and no
//! drift verdict. Enterprise and developer installs are likewise classified, not
//! condemned.
//!
//! # Two hashing decisions, written down
//!
//! `_metadata/computed_hashes.json` and `_metadata/verified_contents.json` are
//! Chrome's own integrity records. They are INCLUDED in the tree digest. A
//! version directory is content-immutable once installed (Chrome writes a new
//! `<version>_<ordinal>` directory on update), so a `_metadata` rewrite inside a
//! fixed version directory is itself a tamper signal. Excluding them to avoid
//! churn would drop that signal for churn that does not occur.
//!
//! Chrome keeps several `<version>_<ordinal>` directories side by side during an
//! update. Treating "the" version as one value would produce phantom drift on
//! every browser update, so [`ExtensionRecord::version_directories`] records all
//! of them and [`ExtensionRecord::version_directory`] records which one was
//! audited: the highest parsed `(version tuple, ordinal)`.
//!
//! Both are carried into the baseline and compared, and that is load-bearing in
//! two directions. Only the SELECTED directory is hashed, so a second complete
//! tree dropped beside it changes no digest and is visible only as a change to
//! the SET ([`ExtensionDrift::VersionDirectorySetChange`]). And because the
//! immutability above holds, a declared version that moves while its directory
//! does not is an in-place rewrite that no real update can produce, reported as
//! [`ExtensionDrift::VersionDirectoryReused`] with both digests: the ordinary
//! digest comparison is skipped once a version moves, so without it one extra
//! line in `manifest.json` hid the byte change entirely.
//!
//! # Coverage is honest or it is nothing
//!
//! Any unreadable file, locked directory, symlink, name collision, oversize
//! file, or exhausted budget makes the enclosing result
//! [`AuditCoverage::Partial`] and sets [`TreeDigest::complete`] to false. A
//! partial digest is never emitted as if it were complete, and a partial audit
//! is never reported as a confident clean result.
//!
//! Honest coverage is only worth anything if the COMPARISON can see it, so:
//!
//! - a gap directly beneath `Extensions/<id>/` (a refused sibling version
//!   directory, an entry that is not a version directory, a name that cannot be
//!   recorded) sets [`ExtensionRecord::enumeration_complete`] false, which the
//!   baseline carries and [`compute_drift`] turns into
//!   [`ExtensionDrift::IntegrityNotComparable`]. Recorded one level up it
//!   degraded the profile while the extension still claimed to be complete, and
//!   drift is computed from the extension;
//! - an extension that cannot be audited at all is still REPORTED, with
//!   `coverage: partial` and empty facts, because an id that vanishes from the
//!   inventory produces no drift entry and a newly installed one would therefore
//!   be invisible;
//! - a `--baseline` run whose report is partial exits 1 even with no drift
//!   entries, because a verify run that could not verify must not print a clean
//!   comparison it did not make.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization as _;

use crate::scan::CoverageGapKind;
use crate::util::{HashOutcome, OpenRegularError};

/// Schema version of the audit report and the baseline document. Bumped when a
/// field is added or its meaning changes.
pub const BROWSER_AUDIT_SCHEMA: u32 = 2;

/// Version of the HASHING rules (tree digest and surface hash). Bumped
/// independently of [`BROWSER_AUDIT_SCHEMA`] whenever a digest computed by an
/// older build would no longer reproduce, so a stale baseline reports one
/// [`ExtensionDrift::SchemaUpgradeRequired`] instead of phantom drift on every
/// extension.
pub const BROWSER_BASELINE_FORMAT_VERSION: u32 = 1;

/// Stable discriminator so a reader can tell this document from any other
/// receipt sharing a directory.
pub const BROWSER_BASELINE_TYPE: &str = "browser_extension_baseline";

/// Maximum bytes of an extension `manifest.json`. A real manifest is tens of
/// KiB; this is the same "tighter than the generic hot-path ceiling, with the
/// number written down" discipline [`crate::mcp_lock::MCP_CONFIG_MAX_SIZE`]
/// applies to MCP configs.
pub const MAX_MANIFEST_BYTES: u64 = 1_048_576;

/// Maximum bytes of a Chromium `Preferences` / `Secure Preferences` document
/// that will be parsed for install class. A long-lived profile's Preferences
/// reaches a few MiB; beyond this ceiling install class degrades to
/// [`InstallClass::Unknown`] rather than becoming a parse DoS.
pub const MAX_PREFERENCES_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum bytes of any single file folded into a tree digest. Bundled JS and
/// wasm routinely reach a few MiB; a larger member becomes a
/// [`CoverageGapKind::HashBudgetExceeded`] gap instead of an unbounded read.
pub const MAX_EXTENSION_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// The ONLY `Preferences` fields any part of this module reads, each beneath
/// `extensions.settings.<id>` for an id already discovered on disk.
///
/// Named as a public constant so a reviewer can diff the claim against the code
/// and a test can assert the audit output carries nothing else.
pub const PREFERENCES_ALLOWED_FIELDS: &[&str] =
    &["location", "from_webstore", "was_installed_by_default"];

/// The profile-relative store paths this audit must never open, as a LEXICAL
/// deny list checked in [`open_audit_file`] on top of
/// [`crate::sensitive_assets::classify_path`].
///
/// The catalogue gate is not sufficient on its own and the module used to claim
/// it was: `classify_path` returns `Some` for a browser storage root only when a
/// hardcoded WALLET extension id also appears in the path
/// (`sensitive_assets::classify_path_for_flavor`), so a plain `Cookies`,
/// `History`, `Login Data`, or `Local Storage/leveldb` path falls through it.
/// This list is the statement that does not depend on which extension ids happen
/// to be catalogued, so the two gates are genuinely independent.
///
/// Matched on path COMPONENTS, so `<profile>/Network/Cookies` and
/// `<profile>/Cookies` are both refused and a file merely named `history.js`
/// inside an extension tree is not.
pub const NEVER_READ_PROFILE_STORES: &[&str] = &[
    "Cookies",
    "Cookies-journal",
    "History",
    "History-journal",
    "Login Data",
    "Login Data For Account",
    "Web Data",
    "Local State",
    "Local Storage",
    "Session Storage",
    "IndexedDB",
    "Local Extension Settings",
    "Sync Extension Settings",
    "Managed Extension Settings",
    "Extension State",
    "databases",
    "Service Worker",
    "Affiliation Database",
    "Trust Tokens",
    "Safe Browsing Cookies",
];

/// The `Preferences`-family file names this module opens, in precedence order.
/// Chromium keeps `extensions.settings` in `Preferences`; Chrome-branded builds
/// move it into the protected `Secure Preferences`. Both are read through the
/// same three-field extraction; neither is read as a document.
pub const PREFERENCES_FILE_NAMES: &[&str] = &["Preferences", "Secure Preferences"];

/// Ceilings for one audit run. The per-extension ceilings bound a hostile
/// extension; the per-RUN ceilings bound `--browser all`, which multiplies four
/// browsers by N profiles and would otherwise be a surface the per-extension
/// caps do not cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditBudget {
    pub max_files_per_extension: usize,
    pub max_bytes_per_extension: u64,
    pub max_file_bytes: u64,
    pub max_total_files: usize,
    pub max_total_bytes: u64,
    pub max_depth: usize,
    pub max_extensions_per_profile: usize,
    pub max_profiles_per_browser: usize,
}

impl Default for AuditBudget {
    fn default() -> Self {
        Self {
            // Measured against the fixture trees and the shape of shipped
            // extensions: a large one is a few thousand files and tens of MiB.
            max_files_per_extension: 20_000,
            max_bytes_per_extension: 512 * 1024 * 1024,
            max_file_bytes: MAX_EXTENSION_FILE_BYTES,
            max_total_files: 200_000,
            max_total_bytes: 4 * 1024 * 1024 * 1024,
            max_depth: 32,
            max_extensions_per_profile: 512,
            max_profiles_per_browser: 64,
        }
    }
}

/// The remaining run-wide budget. Threaded through every walk so `--browser all`
/// is bounded in TOTAL, not merely per browser: four browsers times N profiles
/// would otherwise be a surface the per-extension ceilings do not cover.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditProgress {
    files_used: usize,
    bytes_used: u64,
}

impl AuditProgress {
    /// A fresh run-wide budget.
    pub fn new() -> Self {
        Self::default()
    }

    /// Files hashed so far across the whole run.
    pub fn files_used(&self) -> usize {
        self.files_used
    }

    /// Bytes hashed so far across the whole run.
    pub fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    fn exhausted(&self, budget: &AuditBudget) -> bool {
        self.files_used >= budget.max_total_files || self.bytes_used >= budget.max_total_bytes
    }
}

/// A Chromium-family browser this audit understands. Firefox and XPI are out of
/// scope for C16 and are refused explicitly at the CLI boundary rather than
/// reported as an empty clean inventory.
///
/// Deliberately distinct from the CLI's own `cli::browser::Browser`: that type
/// resolves `NativeMessagingHosts` directories, has several exhaustive matches,
/// and lives in a crate this one cannot depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Chrome,
    Chromium,
    Brave,
    Edge,
}

/// A Chromium release channel. Kept separate from the installation edition:
/// Chrome Beta installed natively and a stable Chromium Flatpak are different
/// roots even when both happen to expose a `Default` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserChannel {
    Stable,
    Beta,
    Dev,
    Canary,
    Nightly,
    /// The operator supplied `--profile`, so no discovered channel is claimed.
    Explicit,
}

impl BrowserChannel {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Dev => "dev",
            Self::Canary => "canary",
            Self::Nightly => "nightly",
            Self::Explicit => "explicit",
        }
    }
}

/// Which packaging layout owns a browser root. This is a categorical edition,
/// never an absolute path, so it is safe to carry into reports and receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserRootEdition {
    Native,
    Snap,
    Flatpak,
    /// The operator supplied `--profile`, so no packaging claim is made.
    Explicit,
}

impl BrowserRootEdition {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Snap => "snap",
            Self::Flatpak => "flatpak",
            Self::Explicit => "explicit",
        }
    }
}

/// Stable, privacy-preserving identity of one catalogued user-data root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BrowserRootIdentity {
    pub family: BrowserFamily,
    pub channel: BrowserChannel,
    pub edition: BrowserRootEdition,
}

impl BrowserRootIdentity {
    fn explicit(family: BrowserFamily) -> Self {
        Self {
            family,
            channel: BrowserChannel::Explicit,
            edition: BrowserRootEdition::Explicit,
        }
    }
}

/// Stable identity of one profile within one browser root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BrowserProfileIdentity {
    pub root: BrowserRootIdentity,
    pub profile_directory: String,
}

/// Stable identity of one extension within one profile.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BrowserExtensionIdentity {
    pub profile: BrowserProfileIdentity,
    pub extension_id: String,
}

impl BrowserFamily {
    /// Every family, in report order.
    pub const ALL: [Self; 4] = [Self::Chrome, Self::Chromium, Self::Brave, Self::Edge];

    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Chromium => "chromium",
            Self::Brave => "brave",
            Self::Edge => "edge",
        }
    }
}

/// The host whose user-data layout applies. Taken as a parameter rather than
/// read from `cfg!` inside the resolver so all three layouts stay testable on
/// any machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostPlatform {
    #[serde(rename = "macos")]
    MacOs,
    Linux,
    Windows,
}

impl HostPlatform {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }
}

/// The platform this build runs on, or `None` on a host with no known Chromium
/// user-data layout (a BSD, say). `None` makes discovery report
/// [`BrowserStatus::PlatformUnsupported`] rather than silently finding nothing.
pub fn host_platform() -> Option<HostPlatform> {
    if cfg!(target_os = "macos") {
        Some(HostPlatform::MacOs)
    } else if cfg!(target_os = "linux") {
        Some(HostPlatform::Linux)
    } else if cfg!(target_os = "windows") {
        Some(HostPlatform::Windows)
    } else {
        None
    }
}

/// One catalogued home-relative Chromium user-data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrowserRootSpec {
    pub identity: BrowserRootIdentity,
    pub relative_path: &'static str,
}

const CHROME_MAC_ROOTS: &[&str] = &[
    "Library/Application Support/Google/Chrome",
    "Library/Application Support/Google/Chrome Beta",
    "Library/Application Support/Google/Chrome Dev",
    "Library/Application Support/Google/Chrome Canary",
];
const CHROME_LINUX_ROOTS: &[&str] = &[
    ".config/google-chrome",
    ".config/google-chrome-beta",
    ".config/google-chrome-unstable",
];
const CHROME_WINDOWS_ROOTS: &[&str] = &[
    "AppData/Local/Google/Chrome/User Data",
    "AppData/Local/Google/Chrome Beta/User Data",
    "AppData/Local/Google/Chrome Dev/User Data",
    "AppData/Local/Google/Chrome SxS/User Data",
];
const CHROMIUM_MAC_ROOTS: &[&str] = &["Library/Application Support/Chromium"];
const CHROMIUM_LINUX_ROOTS: &[&str] = &[
    ".config/chromium",
    "snap/chromium/common/chromium",
    ".var/app/org.chromium.Chromium/config/chromium",
];
const CHROMIUM_WINDOWS_ROOTS: &[&str] = &["AppData/Local/Chromium/User Data"];
const BRAVE_MAC_ROOTS: &[&str] = &[
    "Library/Application Support/BraveSoftware/Brave-Browser",
    "Library/Application Support/BraveSoftware/Brave-Browser-Beta",
    "Library/Application Support/BraveSoftware/Brave-Browser-Nightly",
];
const BRAVE_LINUX_ROOTS: &[&str] = &[
    ".config/BraveSoftware/Brave-Browser",
    ".config/BraveSoftware/Brave-Browser-Beta",
    ".config/BraveSoftware/Brave-Browser-Nightly",
    ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
];
const BRAVE_WINDOWS_ROOTS: &[&str] = &[
    "AppData/Local/BraveSoftware/Brave-Browser/User Data",
    "AppData/Local/BraveSoftware/Brave-Browser-Beta/User Data",
    "AppData/Local/BraveSoftware/Brave-Browser-Nightly/User Data",
];
const EDGE_MAC_ROOTS: &[&str] = &[
    "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Microsoft Edge Beta",
    "Library/Application Support/Microsoft Edge Dev",
    "Library/Application Support/Microsoft Edge Canary",
];
const EDGE_LINUX_ROOTS: &[&str] = &[
    ".config/microsoft-edge",
    ".config/microsoft-edge-beta",
    ".config/microsoft-edge-dev",
];
const EDGE_WINDOWS_ROOTS: &[&str] = &[
    "AppData/Local/Microsoft/Edge/User Data",
    "AppData/Local/Microsoft/Edge Beta/User Data",
    "AppData/Local/Microsoft/Edge Dev/User Data",
    "AppData/Local/Microsoft/Edge SxS/User Data",
];

/// Home-relative Chromium user-data directories, in probe order.
///
/// This is the audit's OWN table rather than
/// [`crate::sensitive_assets::CAPSULE_BROWSER_DATA_ROOTS`], because the two
/// answer different questions: that constant is the capsule DENY set (what a
/// contained child may never reach) and it covers Firefox, which this audit does
/// not. Edge entries were added to both; see the C16 note in `sensitive_assets`.
pub fn user_data_relative_roots(
    family: BrowserFamily,
    platform: HostPlatform,
) -> &'static [&'static str] {
    match (family, platform) {
        (BrowserFamily::Chrome, HostPlatform::MacOs) => CHROME_MAC_ROOTS,
        (BrowserFamily::Chrome, HostPlatform::Linux) => CHROME_LINUX_ROOTS,
        (BrowserFamily::Chrome, HostPlatform::Windows) => CHROME_WINDOWS_ROOTS,
        (BrowserFamily::Chromium, HostPlatform::MacOs) => CHROMIUM_MAC_ROOTS,
        (BrowserFamily::Chromium, HostPlatform::Linux) => CHROMIUM_LINUX_ROOTS,
        (BrowserFamily::Chromium, HostPlatform::Windows) => CHROMIUM_WINDOWS_ROOTS,
        (BrowserFamily::Brave, HostPlatform::MacOs) => BRAVE_MAC_ROOTS,
        (BrowserFamily::Brave, HostPlatform::Linux) => BRAVE_LINUX_ROOTS,
        (BrowserFamily::Brave, HostPlatform::Windows) => BRAVE_WINDOWS_ROOTS,
        (BrowserFamily::Edge, HostPlatform::MacOs) => EDGE_MAC_ROOTS,
        (BrowserFamily::Edge, HostPlatform::Linux) => EDGE_LINUX_ROOTS,
        (BrowserFamily::Edge, HostPlatform::Windows) => EDGE_WINDOWS_ROOTS,
    }
}

/// Complete root catalogue with channel and packaging identity. The path table
/// above remains the single source of path spellings; this function adds the
/// same-length identity table and debug-asserts the two cannot silently drift.
pub fn browser_root_specs(family: BrowserFamily, platform: HostPlatform) -> Vec<BrowserRootSpec> {
    use BrowserChannel::{Beta, Canary, Dev, Nightly, Stable};
    use BrowserRootEdition::{Flatpak, Native, Snap};

    let identities: &[(BrowserChannel, BrowserRootEdition)] = match (family, platform) {
        (BrowserFamily::Chrome, HostPlatform::MacOs) => &[
            (Stable, Native),
            (Beta, Native),
            (Dev, Native),
            (Canary, Native),
        ],
        (BrowserFamily::Chrome, HostPlatform::Linux) => {
            &[(Stable, Native), (Beta, Native), (Dev, Native)]
        }
        (BrowserFamily::Chrome, HostPlatform::Windows) => &[
            (Stable, Native),
            (Beta, Native),
            (Dev, Native),
            (Canary, Native),
        ],
        (BrowserFamily::Chromium, HostPlatform::MacOs) => &[(Stable, Native)],
        (BrowserFamily::Chromium, HostPlatform::Linux) => {
            &[(Stable, Native), (Stable, Snap), (Stable, Flatpak)]
        }
        (BrowserFamily::Chromium, HostPlatform::Windows) => &[(Stable, Native)],
        (BrowserFamily::Brave, HostPlatform::MacOs) => {
            &[(Stable, Native), (Beta, Native), (Nightly, Native)]
        }
        (BrowserFamily::Brave, HostPlatform::Linux) => &[
            (Stable, Native),
            (Beta, Native),
            (Nightly, Native),
            (Stable, Flatpak),
        ],
        (BrowserFamily::Brave, HostPlatform::Windows) => {
            &[(Stable, Native), (Beta, Native), (Nightly, Native)]
        }
        (BrowserFamily::Edge, HostPlatform::MacOs) => &[
            (Stable, Native),
            (Beta, Native),
            (Dev, Native),
            (Canary, Native),
        ],
        (BrowserFamily::Edge, HostPlatform::Linux) => {
            &[(Stable, Native), (Beta, Native), (Dev, Native)]
        }
        (BrowserFamily::Edge, HostPlatform::Windows) => &[
            (Stable, Native),
            (Beta, Native),
            (Dev, Native),
            (Canary, Native),
        ],
    };
    let paths = user_data_relative_roots(family, platform);
    debug_assert_eq!(paths.len(), identities.len());
    paths
        .iter()
        .zip(identities)
        .map(|(relative_path, (channel, edition))| BrowserRootSpec {
            identity: BrowserRootIdentity {
                family,
                channel: *channel,
                edition: *edition,
            },
            relative_path,
        })
        .collect()
}

/// What shape of profile a directory name declares. Chromium profile directories
/// are named structurally, which is the whole reason this audit can report
/// profile identity without reading `Local State`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    /// `Default`.
    Default,
    /// `Profile <n>`.
    Numbered,
    /// `Guest Profile`.
    Guest,
    /// `System Profile`.
    System,
    /// An operator-named directory reached through `--profile`. Never produced
    /// by discovery.
    Explicit,
}

impl ProfileKind {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Numbered => "numbered",
            Self::Guest => "guest",
            Self::System => "system",
            Self::Explicit => "explicit",
        }
    }
}

/// Classify a `<user-data>` child by NAME ONLY. Returns `None` for any directory
/// that is not a Chromium profile (`Crashpad`, `ShaderCache`, ...), so discovery
/// never walks something it has not recognized.
pub fn classify_profile_directory(name: &str) -> Option<ProfileKind> {
    match name {
        "Default" => Some(ProfileKind::Default),
        "Guest Profile" => Some(ProfileKind::Guest),
        "System Profile" => Some(ProfileKind::System),
        _ => {
            let rest = name.strip_prefix("Profile ")?;
            if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                Some(ProfileKind::Numbered)
            } else {
                None
            }
        }
    }
}

/// How the extension got onto the machine, as Chromium itself recorded it.
///
/// Classification, never a verdict: an enterprise force-install and a developer
/// unpacked load are both perfectly ordinary, and neither raises risk here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallClass {
    /// Installed through the browser's own web store.
    #[serde(rename = "webstore")]
    WebStore,
    /// Installed by something outside the browser: an external-preferences drop,
    /// a Windows registry key, or an external download.
    Sideloaded,
    /// Force-installed or recommended by an administrative policy.
    EnterprisePolicy,
    /// Loaded unpacked, or supplied on the command line. The developer path.
    DeveloperUnpacked,
    /// Shipped as part of the browser itself.
    BrowserComponent,
    /// No `Preferences` record was readable for this id. Always paired with
    /// [`AuditCoverage::Partial`]; never guessed from the tree.
    Unknown,
}

impl InstallClass {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::WebStore => "webstore",
            Self::Sideloaded => "sideloaded",
            Self::EnterprisePolicy => "enterprise_policy",
            Self::DeveloperUnpacked => "developer_unpacked",
            Self::BrowserComponent => "browser_component",
            Self::Unknown => "unknown",
        }
    }
}

/// Where an [`InstallClass`] came from, so `unknown` is never mistaken for a
/// classification that was actually performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallClassSource {
    /// A `Preferences`-family file was parsed and the three allowed fields read.
    Preferences,
    /// No `Preferences`-family file was readable, parseable, or within the size
    /// ceiling. Every install class in this profile is `unknown`.
    Unavailable,
}

impl InstallClassSource {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Preferences => "preferences",
            Self::Unavailable => "unavailable",
        }
    }
}

/// What the extension tree itself says about where its bytes came from. Derived
/// from the PRESENCE of Chrome's own integrity records, never from their
/// contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceClass {
    /// `_metadata/verified_contents.json` is present: the browser holds a
    /// store-signed content manifest for this version.
    StoreSigned,
    /// `_metadata/computed_hashes.json` only: the browser computed its own
    /// hashes at install time, with no store signature alongside them.
    ComputedHashesOnly,
    /// No `_metadata` records at all, which is what an unpacked tree looks like.
    Unrecorded,
}

impl ProvenanceClass {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::StoreSigned => "store_signed",
            Self::ComputedHashesOnly => "computed_hashes_only",
            Self::Unrecorded => "unrecorded",
        }
    }
}

/// The background execution surface an extension declares.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackgroundKind {
    /// No `background` key.
    #[default]
    None,
    /// MV2 `background.page`.
    Page,
    /// MV2 `background.scripts`.
    Scripts,
    /// MV3 `background.service_worker`.
    ServiceWorker,
}

/// Everything the manifest declares that can RUN. Compared field by field
/// against a baseline to produce [`ExtensionDrift::ExecutionSurfaceChange`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSurfaces {
    pub background: BackgroundKind,
    /// Number of `content_scripts` entries.
    pub content_script_count: usize,
    /// Sorted, de-duplicated `content_scripts[].matches` patterns.
    pub content_script_matches: Vec<String>,
    /// `nativeMessaging` is held as a permission.
    pub native_messaging: bool,
    /// `externally_connectable` is declared.
    pub externally_connectable: bool,
    /// Sorted, de-duplicated `externally_connectable.matches` patterns.
    pub externally_connectable_matches: Vec<String>,
    /// `externally_connectable.ids` entries, sorted and de-duplicated.
    pub externally_connectable_ids: Vec<String>,
    /// Number of `web_accessible_resources` entries.
    pub web_accessible_resource_count: usize,
    /// Number of `declarative_net_request.rule_resources` entries.
    pub declarative_net_request_rulesets: usize,
    /// A `devtools_page` is declared.
    pub devtools_page: bool,
    /// Sorted `chrome_url_overrides` keys.
    pub chrome_url_overrides: Vec<String>,
    /// Number of `sandbox.pages` entries.
    pub sandbox_page_count: usize,
    /// A `content_security_policy` is declared.
    pub content_security_policy: bool,
}

/// How much authority an extension holds. Independent of drift, always.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Nothing on the reviewed list.
    #[default]
    Ordinary,
    /// Holds at least one high-authority capability, but not all-hosts access.
    Elevated,
    /// Can read or rewrite every site the user visits.
    Broad,
}

impl RiskLevel {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Elevated => "elevated",
            Self::Broad => "broad",
        }
    }
}

/// One reviewed reason an extension's authority is worth an operator's
/// attention. A typed enum rather than free text so the reason set is closed and
/// nothing attacker-controlled reaches a durable artifact through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionRiskReason {
    /// A host pattern that matches every site.
    AllHosts,
    /// The `debugger` permission: full DevTools protocol control of any tab.
    Debugger,
    /// The `nativeMessaging` permission: can talk to a local native binary.
    NativeMessaging,
    /// MV2 `webRequestBlocking`: can rewrite or cancel any request.
    WebRequestBlocking,
    /// `proxy`: can redirect all traffic.
    Proxy,
    /// `cookies`: can read session cookies for its host scopes.
    Cookies,
    /// `history` or `browsingData`.
    BrowsingHistory,
    /// `management`: can enumerate and disable other extensions.
    Management,
    /// `downloads`: can write files to the download directory.
    Downloads,
    /// `scripting` or MV2 `tabs`-plus-host script injection.
    Scripting,
    /// `privacy` or `contentSettings`: can change browser security settings.
    BrowserSettings,
    /// `clipboardRead`.
    ClipboardRead,
}

impl PermissionRiskReason {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::AllHosts => "all_hosts",
            Self::Debugger => "debugger",
            Self::NativeMessaging => "native_messaging",
            Self::WebRequestBlocking => "web_request_blocking",
            Self::Proxy => "proxy",
            Self::Cookies => "cookies",
            Self::BrowsingHistory => "browsing_history",
            Self::Management => "management",
            Self::Downloads => "downloads",
            Self::Scripting => "scripting",
            Self::BrowserSettings => "browser_settings",
            Self::ClipboardRead => "clipboard_read",
        }
    }
}

/// The permission-risk assessment. Reported ALONGSIDE drift and never folded
/// into it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRisk {
    pub level: RiskLevel,
    pub reasons: Vec<PermissionRiskReason>,
}

/// Why one path was refused.
///
/// Wire shape follows [`crate::mcp_lock::RejectedReason`]: `kind` names the
/// variant in `snake_case` and every extra field is a `u64`/`usize`/`bool`, so a
/// rejection can never echo file content or an OS error string into a durable
/// artifact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RejectionReason {
    /// The entry is a symlink. Refused without opening the target.
    Symlink,
    /// The entry exists but is not a regular file or directory.
    NotRegularFile,
    /// The canonical form escapes the profile root.
    OutsideProfile,
    /// A directory beneath `Extensions/` whose name is not a Chromium extension
    /// id (exactly 32 letters `a`-`p`).
    NotAnExtensionId,
    /// Two sibling names fold to the same NFKC + lowercase key, so a
    /// case-insensitive or normalizing filesystem cannot tell them apart. Both
    /// siblings are refused; never a silent last-wins overwrite.
    NameCollision,
    /// A name that is not valid UTF-8 and therefore cannot be recorded or
    /// compared.
    NonUtf8Name,
    /// The file is larger than the applicable ceiling.
    Oversize { size_bytes: u64 },
    /// The file or directory could not be read.
    Unreadable { permission_denied: bool },
    /// `manifest.json` is absent from the audited version directory.
    MissingManifest,
    /// `manifest.json` is not parseable JSON, or is not UTF-8.
    MalformedManifest,
    /// `manifest.json` declares the same key twice. Different readers resolve
    /// that differently, so no exact surface can be derived from it.
    DuplicateJsonKey,
    /// The extension directory holds no version subdirectory.
    NoVersionDirectory,
    /// The tree is deeper than the depth ceiling.
    DepthExceeded,
    /// A per-extension or run-wide budget was reached before the walk finished.
    BudgetExhausted,
    /// The path is classified sensitive by the shared asset catalogue, or it
    /// names one of the profile stores in [`NEVER_READ_PROFILE_STORES`], so this
    /// audit refuses to open it. Defence in depth behind the structural read
    /// set; see the module documentation.
    SensitivePath,
    /// A regular file inside an extension tree with more than one link. The same
    /// content is reachable under a name the walk never saw, so hashing it would
    /// fold a file the read set never selected into the digest.
    HardLink,
    /// An entry directly beneath `Extensions/<id>/` that is not a version
    /// directory, so it is outside the audited read set and nothing about it can
    /// be stated.
    UnexpectedEntry,
    /// The per-extension ceiling on RECORDED rejections and gaps was reached, so
    /// individual paths past this point are not named. Coverage is already
    /// partial when this appears.
    RecordLimitReached,
}

/// One refused path plus the reason. `path` is always relative to the enclosing
/// profile directory, so a durable baseline never carries a home layout or an
/// account name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RejectedEntry {
    pub path: String,
    pub reason: RejectionReason,
}

/// One thing that could have mattered and was not covered. Reuses the scan
/// engine's [`CoverageGapKind`] vocabulary rather than inventing a parallel one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCoverageGap {
    /// Profile-relative scope the gap applies to.
    pub scope: String,
    pub kind: CoverageGapKind,
}

/// Deterministic gap ordering. Hand-rolled because [`CoverageGapKind`] is a
/// shared scan-engine type with no `Ord`, and widening it for this module would
/// change a frozen contract surface for cosmetics.
fn sort_gaps(gaps: &mut Vec<AuditCoverageGap>) {
    gaps.sort_by(|a, b| {
        (a.scope.as_str(), a.kind.as_str()).cmp(&(b.scope.as_str(), b.kind.as_str()))
    });
    gaps.dedup();
}

/// Whether a result covers everything it claims to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCoverage {
    /// Every selected path was enumerated, opened, and hashed.
    Complete,
    /// At least one path was refused, unreadable, or dropped by a budget. Never
    /// a confident clean result.
    Partial,
}

impl AuditCoverage {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }

    /// Degrade to [`AuditCoverage::Partial`] when `partial` holds. Coverage only
    /// ever moves one way.
    fn degrade(&mut self, partial: bool) {
        if partial {
            *self = AuditCoverage::Partial;
        }
    }
}

/// A deterministic sorted-tree digest. `complete` false means the digest covers
/// less than the whole tree and must not be read as an integrity statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeDigest {
    pub digest: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub complete: bool,
}

/// One audited extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionRecord {
    /// Full durable identity. The legacy `id` field remains for consumers that
    /// only render one profile, but comparisons use this structured value.
    pub identity: BrowserExtensionIdentity,
    pub id: String,
    /// `manifest.json`'s `name`, display-sanitized and truncated. Attacker
    /// controlled, so it is never used for matching, only for reading.
    pub name: String,
    /// `manifest.json`'s `version`, verbatim.
    pub version: String,
    /// The version directory that was audited.
    pub version_directory: String,
    /// Every version directory present, sorted. More than one is normal during
    /// a browser update and is not drift.
    pub version_directories: Vec<String>,
    /// `manifest_version`, verbatim. MV2 and MV3 both parse.
    pub manifest_version: u64,
    pub install_class: InstallClass,
    pub provenance: ProvenanceClass,
    /// Non-host permission strings, sorted and de-duplicated.
    pub permissions: Vec<String>,
    /// Optional (user-grantable) non-host permissions, sorted.
    pub optional_permissions: Vec<String>,
    /// Host match patterns, sorted. MV2 mixes these into `permissions`; they are
    /// split apart here so an MV2-to-MV3 move is not reported as an expansion.
    pub host_permissions: Vec<String>,
    /// Optional host match patterns, sorted.
    pub optional_host_permissions: Vec<String>,
    pub surfaces: ExecutionSurfaces,
    /// Permission RISK. Never an input to drift.
    pub risk: PermissionRisk,
    pub tree: TreeDigest,
    /// sha256 over the canonical JSON of the declared surface (manifest version,
    /// permissions, hosts, execution surfaces, install class, provenance), so a
    /// whitespace-only or key-reorder rewrite of `manifest.json` is not drift
    /// while a real surface change is.
    pub surface_hash: String,
    /// The id matches a wallet extension id in the shared sensitive-asset
    /// catalogue. A LABEL for the operator, never a trust anchor: it changes no
    /// digest, no risk level, and no drift verdict.
    pub wallet_fixture_match: bool,
    pub coverage: AuditCoverage,
    /// Whether everything directly beneath `Extensions/<id>/` was enumerated:
    /// no unreadable entry, no refused sibling version directory, no name that
    /// could not be recorded, and nothing present that is not a version
    /// directory.
    ///
    /// Distinct from [`TreeDigest::complete`], which speaks only for the ONE
    /// version directory that was walked. Both are carried into the baseline,
    /// because a gap on either side means a later run cannot honestly call the
    /// comparison clean.
    pub enumeration_complete: bool,
    pub rejected: Vec<RejectedEntry>,
    pub gaps: Vec<AuditCoverageGap>,
}

/// One audited profile. Identity is the DIRECTORY NAME; see the module note on
/// `Local State`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRecord {
    /// Root + profile directory. Two `Default` profiles in different channels
    /// are therefore distinct without recording either absolute path.
    pub identity: BrowserProfileIdentity,
    pub profile_directory: String,
    pub profile_kind: ProfileKind,
    pub install_class_source: InstallClassSource,
    pub extensions: Vec<ExtensionRecord>,
    pub coverage: AuditCoverage,
    pub rejected: Vec<RejectedEntry>,
    pub gaps: Vec<AuditCoverageGap>,
}

/// Why a browser produced no profiles, when it produced none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserStatus {
    /// A user-data directory was found and enumerated.
    Audited,
    /// No user-data directory exists for this browser on this host. An explicit
    /// statement, not an empty clean inventory.
    UserDataNotFound,
    /// The user-data directory exists but could not be enumerated (locked by a
    /// running browser, or permission denied).
    UserDataUnreadable,
    /// This host has no known Chromium user-data layout.
    PlatformUnsupported,
    /// The operator's home directory could not be resolved.
    HomeUnresolved,
}

impl BrowserStatus {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::Audited => "audited",
            Self::UserDataNotFound => "user_data_not_found",
            Self::UserDataUnreadable => "user_data_unreadable",
            Self::PlatformUnsupported => "platform_unsupported",
            Self::HomeUnresolved => "home_unresolved",
        }
    }
}

/// Outcome of probing one catalogued root. Missing roots are ordinary (the
/// channel is not installed); an inaccessible root has one matching
/// [`BrowserRootGap`] and makes coverage partial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserRootStatus {
    Audited,
    NotFound,
    Inaccessible,
    /// The OS reported the same stable filesystem identity for an earlier
    /// root, so it was not audited a second time.
    Duplicate,
}

impl BrowserRootStatus {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::Audited => "audited",
            Self::NotFound => "not_found",
            Self::Inaccessible => "inaccessible",
            Self::Duplicate => "duplicate",
        }
    }
}

/// One root probe, without its host path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserRootRecord {
    pub identity: BrowserRootIdentity,
    pub status: BrowserRootStatus,
}

/// One and only one gap for a catalogued root that existed but could not be
/// enumerated. The root identity replaces an absolute-path scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserRootGap {
    pub root: BrowserRootIdentity,
    pub kind: CoverageGapKind,
}

/// One browser's result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserRecord {
    pub browser: BrowserFamily,
    pub status: BrowserStatus,
    pub roots: Vec<BrowserRootRecord>,
    pub profiles: Vec<ProfileRecord>,
    pub coverage: AuditCoverage,
    pub root_gaps: Vec<BrowserRootGap>,
}

/// The whole audit. Carries no absolute path anywhere: browsers are named by
/// family, profiles by directory name, and every rejected path is
/// profile-relative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserAuditReport {
    pub schema: u32,
    pub format_version: u32,
    pub platform: Option<HostPlatform>,
    pub browsers: Vec<BrowserRecord>,
    pub coverage: AuditCoverage,
    /// True when a run-wide budget stopped the walk. Always paired with
    /// [`AuditCoverage::Partial`].
    pub budget_exhausted: bool,
}

impl BrowserAuditReport {
    /// Every extension in the report, in baseline order.
    pub fn entries(&self) -> Vec<BaselineEntry> {
        let mut entries = Vec::new();
        for browser in &self.browsers {
            for profile in &browser.profiles {
                for extension in &profile.extensions {
                    entries.push(BaselineEntry::from_record(extension));
                }
            }
        }
        entries.sort_by_key(|entry| entry.sort_key());
        entries
    }

    /// Total extension count across every profile.
    pub fn extension_count(&self) -> usize {
        self.browsers
            .iter()
            .flat_map(|browser| browser.profiles.iter())
            .map(|profile| profile.extensions.len())
            .sum()
    }
}

/// What to audit.
#[derive(Debug, Clone)]
pub struct AuditRequest {
    /// The families to walk, in report order.
    pub families: Vec<BrowserFamily>,
    /// An operator-named single profile directory. When set, discovery is
    /// skipped and `families` must hold exactly one family, which is used only
    /// as the label.
    pub explicit_profile: Option<PathBuf>,
    pub budget: AuditBudget,
}

impl AuditRequest {
    /// Every supported family, default budget, discovery from the home
    /// directory.
    pub fn all() -> Self {
        Self {
            families: BrowserFamily::ALL.to_vec(),
            explicit_profile: None,
            budget: AuditBudget::default(),
        }
    }
}

/// Run the audit.
pub fn audit(request: &AuditRequest) -> BrowserAuditReport {
    let platform = host_platform();
    let mut state = AuditProgress::new();
    let mut browsers = Vec::new();
    let mut coverage = AuditCoverage::Complete;

    if let Some(profile_path) = request.explicit_profile.as_deref() {
        let family = request
            .families
            .first()
            .copied()
            .unwrap_or(BrowserFamily::Chrome);
        let record = audit_explicit_profile(family, profile_path, &request.budget, &mut state);
        coverage.degrade(record.coverage == AuditCoverage::Partial);
        browsers.push(record);
        let exhausted = state.exhausted(&request.budget);
        coverage.degrade(exhausted);
        return BrowserAuditReport {
            schema: BROWSER_AUDIT_SCHEMA,
            format_version: BROWSER_BASELINE_FORMAT_VERSION,
            platform,
            browsers,
            coverage,
            budget_exhausted: exhausted,
        };
    }

    for family in &request.families {
        let record = audit_discovered_browser(*family, platform, &request.budget, &mut state);
        coverage.degrade(record.coverage == AuditCoverage::Partial);
        browsers.push(record);
    }

    let exhausted = state.exhausted(&request.budget);
    coverage.degrade(exhausted);
    BrowserAuditReport {
        schema: BROWSER_AUDIT_SCHEMA,
        format_version: BROWSER_BASELINE_FORMAT_VERSION,
        platform,
        browsers,
        coverage,
        budget_exhausted: exhausted,
    }
}

fn audit_discovered_browser(
    family: BrowserFamily,
    platform: Option<HostPlatform>,
    budget: &AuditBudget,
    state: &mut AuditProgress,
) -> BrowserRecord {
    let Some(platform) = platform else {
        return BrowserRecord {
            browser: family,
            status: BrowserStatus::PlatformUnsupported,
            roots: Vec::new(),
            profiles: Vec::new(),
            coverage: AuditCoverage::Partial,
            root_gaps: Vec::new(),
        };
    };
    let Some(home) = home::home_dir() else {
        return BrowserRecord {
            browser: family,
            status: BrowserStatus::HomeUnresolved,
            roots: Vec::new(),
            profiles: Vec::new(),
            coverage: AuditCoverage::Partial,
            root_gaps: Vec::new(),
        };
    };
    let candidates: Vec<(BrowserRootIdentity, PathBuf)> = browser_root_specs(family, platform)
        .into_iter()
        .map(|spec| (spec.identity, home.join(spec.relative_path)))
        .collect();
    audit_browser_candidates(family, &candidates, budget, state)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct StableDirectoryIdentity(u64, u64);

#[cfg(unix)]
fn stable_directory_identity(metadata: &std::fs::Metadata) -> Option<StableDirectoryIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    Some(StableDirectoryIdentity(metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn stable_directory_identity(_metadata: &std::fs::Metadata) -> Option<StableDirectoryIdentity> {
    // Do not substitute a canonical path, case-folded spelling, timestamps, or
    // another forgeable/unstable proxy. Without a stable OS file identity this
    // platform deliberately audits both catalog entries.
    None
}

/// Audit every catalogued candidate. Missing channels are ordinary; every root
/// that exists but cannot be enumerated contributes exactly one root gap and
/// does not stop later channels from being audited.
fn audit_browser_candidates(
    family: BrowserFamily,
    candidates: &[(BrowserRootIdentity, PathBuf)],
    budget: &AuditBudget,
    state: &mut AuditProgress,
) -> BrowserRecord {
    let mut roots = Vec::with_capacity(candidates.len());
    let mut root_gaps = Vec::new();
    let mut profiles = Vec::new();
    let mut saw_existing = false;
    let mut audited_any = false;
    let mut coverage = AuditCoverage::Complete;
    let mut stable_identities = BTreeSet::new();

    for (identity, path) in candidates {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                saw_existing = true;
                coverage = AuditCoverage::Partial;
                roots.push(BrowserRootRecord {
                    identity: *identity,
                    status: BrowserRootStatus::Inaccessible,
                });
                root_gaps.push(BrowserRootGap {
                    root: *identity,
                    kind: CoverageGapKind::EnumerationFailed,
                });
                continue;
            }
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                roots.push(BrowserRootRecord {
                    identity: *identity,
                    status: BrowserRootStatus::NotFound,
                });
                continue;
            }
            Err(_) => {
                saw_existing = true;
                coverage = AuditCoverage::Partial;
                roots.push(BrowserRootRecord {
                    identity: *identity,
                    status: BrowserRootStatus::Inaccessible,
                });
                root_gaps.push(BrowserRootGap {
                    root: *identity,
                    kind: CoverageGapKind::EnumerationFailed,
                });
                continue;
            }
        };
        saw_existing = true;

        if let Some(stable) = stable_directory_identity(&metadata) {
            if !stable_identities.insert(stable) {
                roots.push(BrowserRootRecord {
                    identity: *identity,
                    status: BrowserRootStatus::Duplicate,
                });
                continue;
            }
        }

        let remaining_profiles = budget
            .max_profiles_per_browser
            .saturating_sub(profiles.len());
        let result = audit_user_data_root(*identity, path, budget, state, remaining_profiles);
        audited_any |= result.status == BrowserStatus::Audited;
        coverage.degrade(result.coverage == AuditCoverage::Partial);
        profiles.extend(result.profiles);
        roots.extend(result.roots);
        root_gaps.extend(result.root_gaps);
    }

    BrowserRecord {
        browser: family,
        status: if audited_any {
            BrowserStatus::Audited
        } else if saw_existing {
            BrowserStatus::UserDataUnreadable
        } else {
            BrowserStatus::UserDataNotFound
        },
        roots,
        profiles,
        coverage,
        root_gaps,
    }
}

/// Audit one user-data directory. Public so multi-profile enumeration is
/// testable against a synthetic tree without a real browser installation.
pub fn audit_user_data_dir(
    family: BrowserFamily,
    user_data: &Path,
    budget: &AuditBudget,
    state: &mut AuditProgress,
) -> BrowserRecord {
    audit_user_data_root(
        BrowserRootIdentity::explicit(family),
        user_data,
        budget,
        state,
        budget.max_profiles_per_browser,
    )
}

fn audit_user_data_root(
    root_identity: BrowserRootIdentity,
    user_data: &Path,
    budget: &AuditBudget,
    state: &mut AuditProgress,
    max_profiles: usize,
) -> BrowserRecord {
    let family = root_identity.family;
    let entries = match std::fs::read_dir(user_data) {
        Ok(entries) => entries,
        Err(_) => {
            return BrowserRecord {
                browser: family,
                status: BrowserStatus::UserDataUnreadable,
                roots: vec![BrowserRootRecord {
                    identity: root_identity,
                    status: BrowserRootStatus::Inaccessible,
                }],
                profiles: Vec::new(),
                coverage: AuditCoverage::Partial,
                root_gaps: vec![BrowserRootGap {
                    root: root_identity,
                    kind: CoverageGapKind::EnumerationFailed,
                }],
            }
        }
    };

    let mut names: Vec<(String, ProfileKind)> = Vec::new();
    let mut enumeration_failed = false;
    for entry in entries {
        let Ok(entry) = entry else {
            enumeration_failed = true;
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(kind) = classify_profile_directory(&name) else {
            continue;
        };
        // lstat, so a symlinked profile directory is never descended into.
        match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) if metadata.is_dir() => names.push((name, kind)),
            Ok(_) => {}
            Err(_) => enumeration_failed = true,
        }
    }
    names.sort_by(|a, b| a.0.cmp(&b.0));
    let truncated = names.len() > max_profiles;
    names.truncate(max_profiles);

    let mut coverage = AuditCoverage::Complete;
    coverage.degrade(enumeration_failed || truncated);
    let mut profiles = Vec::new();
    for (name, kind) in names {
        let profile_identity = BrowserProfileIdentity {
            root: root_identity,
            profile_directory: name.clone(),
        };
        let profile = audit_profile_dir(
            &user_data.join(&name),
            &profile_identity,
            kind,
            budget,
            state,
        );
        coverage.degrade(profile.coverage == AuditCoverage::Partial);
        profiles.push(profile);
    }

    let root_gaps = enumeration_failed
        .then_some(BrowserRootGap {
            root: root_identity,
            kind: CoverageGapKind::EnumerationFailed,
        })
        .into_iter()
        .collect();

    BrowserRecord {
        browser: family,
        status: BrowserStatus::Audited,
        roots: vec![BrowserRootRecord {
            identity: root_identity,
            status: if enumeration_failed {
                BrowserRootStatus::Inaccessible
            } else {
                BrowserRootStatus::Audited
            },
        }],
        profiles,
        coverage,
        root_gaps,
    }
}

fn audit_explicit_profile(
    family: BrowserFamily,
    profile_path: &Path,
    budget: &AuditBudget,
    state: &mut AuditProgress,
) -> BrowserRecord {
    let name = profile_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("profile")
        .to_string();
    match std::fs::symlink_metadata(profile_path) {
        Ok(metadata) if metadata.is_dir() => {}
        _ => {
            return BrowserRecord {
                browser: family,
                status: BrowserStatus::UserDataUnreadable,
                roots: vec![BrowserRootRecord {
                    identity: BrowserRootIdentity::explicit(family),
                    status: BrowserRootStatus::Inaccessible,
                }],
                profiles: Vec::new(),
                coverage: AuditCoverage::Partial,
                root_gaps: vec![BrowserRootGap {
                    root: BrowserRootIdentity::explicit(family),
                    kind: CoverageGapKind::EnumerationFailed,
                }],
            }
        }
    }
    let profile_identity = BrowserProfileIdentity {
        root: BrowserRootIdentity::explicit(family),
        profile_directory: name,
    };
    let profile = audit_profile_dir(
        profile_path,
        &profile_identity,
        ProfileKind::Explicit,
        budget,
        state,
    );
    let coverage = profile.coverage;
    BrowserRecord {
        browser: family,
        status: BrowserStatus::Audited,
        roots: vec![BrowserRootRecord {
            identity: BrowserRootIdentity::explicit(family),
            status: BrowserRootStatus::Audited,
        }],
        profiles: vec![profile],
        coverage,
        root_gaps: Vec::new(),
    }
}

/// Audit one profile directory: enumerate `Extensions/`, hash each selected
/// version tree, then resolve install classes from the bounded `Preferences`
/// read.
fn audit_profile_dir(
    profile: &Path,
    identity: &BrowserProfileIdentity,
    kind: ProfileKind,
    budget: &AuditBudget,
    state: &mut AuditProgress,
) -> ProfileRecord {
    let mut rejected: Vec<RejectedEntry> = Vec::new();
    let mut gaps: Vec<AuditCoverageGap> = Vec::new();
    let mut coverage = AuditCoverage::Complete;

    let extensions_root = profile.join("Extensions");
    let ids = match enumerate_extension_ids(&extensions_root, &mut rejected) {
        ExtensionEnumeration::Listed(ids) => ids,
        // A profile with no `Extensions/` directory has no extensions. That is an
        // ordinary state for a fresh profile, not a coverage gap.
        ExtensionEnumeration::Absent => Vec::new(),
        ExtensionEnumeration::Failed(reason) => {
            rejected.push(RejectedEntry {
                path: "Extensions".to_string(),
                reason,
            });
            gaps.push(AuditCoverageGap {
                scope: "Extensions".to_string(),
                kind: CoverageGapKind::EnumerationFailed,
            });
            Vec::new()
        }
    };

    let truncated = ids.len() > budget.max_extensions_per_profile;
    let mut ids = ids;
    if truncated {
        ids.truncate(budget.max_extensions_per_profile);
        gaps.push(AuditCoverageGap {
            scope: "Extensions".to_string(),
            kind: CoverageGapKind::EntryCountCapped,
        });
        coverage = AuditCoverage::Partial;
    }

    let id_set: BTreeSet<String> = ids.iter().cloned().collect();
    let install = read_install_classes(profile, &id_set);

    let mut extensions = Vec::new();
    for id in ids {
        let install_class = install
            .classes
            .get(&id)
            .copied()
            .unwrap_or(InstallClass::Unknown);
        let audited = audit_extension(
            profile,
            &extensions_root,
            identity,
            &id,
            install_class,
            install.source,
            budget,
            state,
        );
        coverage.degrade(audited.coverage == AuditCoverage::Partial);
        extensions.push(audited);
    }
    extensions.sort_by(|a, b| a.id.cmp(&b.id));
    rejected.sort();
    rejected.dedup();
    sort_gaps(&mut gaps);
    coverage.degrade(!rejected.is_empty() || !gaps.is_empty());

    ProfileRecord {
        identity: identity.clone(),
        profile_directory: identity.profile_directory.clone(),
        profile_kind: kind,
        install_class_source: install.source,
        extensions,
        coverage,
        rejected,
        gaps,
    }
}

/// The three distinguishable outcomes of listing `Extensions/`. An ABSENT
/// directory and an UNREADABLE one are different facts and must not collapse:
/// the first is a profile with no extensions, the second is a coverage gap.
enum ExtensionEnumeration {
    Listed(Vec<String>),
    Absent,
    Failed(RejectionReason),
}

/// Enumerate `Extensions/<id>` directories, refusing symlinks, non-id names, and
/// sibling names that fold together.
fn enumerate_extension_ids(
    extensions_root: &Path,
    rejected: &mut Vec<RejectedEntry>,
) -> ExtensionEnumeration {
    // `Extensions` itself is lstat'd before it is listed. Every level BELOW it
    // was already guarded, but the root of the walk was not, so a symlinked
    // `Extensions` was followed silently: the audit hashed a tree outside the
    // profile, reported `coverage: complete`, and recorded no rejection at all.
    match std::fs::symlink_metadata(extensions_root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return ExtensionEnumeration::Failed(RejectionReason::Symlink)
        }
        Ok(metadata) if !metadata.is_dir() => {
            return ExtensionEnumeration::Failed(RejectionReason::NotRegularFile)
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ExtensionEnumeration::Absent
        }
        Err(error) => {
            return ExtensionEnumeration::Failed(RejectionReason::Unreadable {
                permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
            })
        }
    }
    let entries = match std::fs::read_dir(extensions_root) {
        Ok(entries) => entries,
        Err(error) => {
            return match error.kind() {
                std::io::ErrorKind::NotFound => ExtensionEnumeration::Absent,
                std::io::ErrorKind::PermissionDenied => {
                    ExtensionEnumeration::Failed(RejectionReason::Unreadable {
                        permission_denied: true,
                    })
                }
                _ => ExtensionEnumeration::Failed(RejectionReason::Unreadable {
                    permission_denied: false,
                }),
            }
        }
    };

    let mut candidates: Vec<String> = Vec::new();
    for entry in entries {
        let Ok(entry) = entry else {
            push_bounded_rejection(
                rejected,
                "Extensions",
                "Extensions".to_string(),
                RejectionReason::Unreadable {
                    permission_denied: false,
                },
            );
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            push_bounded_rejection(
                rejected,
                "Extensions",
                "Extensions/<non-utf8>".to_string(),
                RejectionReason::NonUtf8Name,
            );
            continue;
        };
        let relative = format!("Extensions/{name}");
        match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                push_bounded_rejection(rejected, "Extensions", relative, RejectionReason::Symlink);
                continue;
            }
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                push_bounded_rejection(
                    rejected,
                    "Extensions",
                    relative,
                    RejectionReason::NotRegularFile,
                );
                continue;
            }
            Err(error) => {
                push_bounded_rejection(
                    rejected,
                    "Extensions",
                    relative,
                    RejectionReason::Unreadable {
                        permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
                    },
                );
                continue;
            }
        }
        if !is_extension_id(&name) {
            push_bounded_rejection(
                rejected,
                "Extensions",
                relative,
                RejectionReason::NotAnExtensionId,
            );
            continue;
        }
        candidates.push(name);
    }

    let colliding = colliding_names(&candidates);
    let mut accepted = Vec::new();
    for name in candidates {
        if colliding.contains(&fold_key(&name)) {
            push_bounded_rejection(
                rejected,
                "Extensions",
                format!("Extensions/{name}"),
                RejectionReason::NameCollision,
            );
            continue;
        }
        accepted.push(name);
    }
    accepted.sort();
    ExtensionEnumeration::Listed(accepted)
}

/// `true` when `id` is a well-formed Chromium extension id: exactly 32 letters
/// `a`-`p`. Mirrors the CLI's `cli::browser::is_valid_extension_id`; kept here
/// because core cannot depend on the CLI crate.
pub fn is_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// NFKC + lowercase fold of a directory entry name. Two siblings sharing a fold
/// key are indistinguishable on a case-insensitive or normalizing filesystem, so
/// neither may be walked.
fn fold_key(name: &str) -> String {
    name.nfkc().collect::<String>().to_lowercase()
}

/// Fold keys that appear more than once in `names`.
fn colliding_names(names: &[String]) -> BTreeSet<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for name in names {
        *seen.entry(fold_key(name)).or_insert(0) += 1;
    }
    seen.into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(key, _)| key)
        .collect()
}

/// The bounded install-class lookup for one profile.
struct InstallClassLookup {
    classes: BTreeMap<String, InstallClass>,
    source: InstallClassSource,
}

/// Read install classes for `ids` from the profile's `Preferences`-family files.
///
/// This is the one place in the product that opens a Chromium preferences
/// document, and the reason the privacy claim in the module documentation holds
/// is STRUCTURAL, not a matter of discipline: the return type is a
/// `BTreeMap<String, InstallClass>` over a fieldless enum. No `serde_json::Value`
/// parsed here can cross this function's boundary, whatever a future edit inside
/// it does, so nothing outside [`PREFERENCES_ALLOWED_FIELDS`] can reach the
/// report, the human output, or a durable baseline.
///
/// Only ids already discovered on disk are looked up, so an extension recorded
/// in preferences but absent from the tree is never even named.
fn read_install_classes(profile: &Path, ids: &BTreeSet<String>) -> InstallClassLookup {
    let mut classes: BTreeMap<String, InstallClass> = BTreeMap::new();
    let mut source = InstallClassSource::Unavailable;
    if ids.is_empty() {
        return InstallClassLookup { classes, source };
    }

    for file_name in PREFERENCES_FILE_NAMES {
        let path = profile.join(file_name);
        let Ok(bytes) = open_audit_read(&path, MAX_PREFERENCES_BYTES) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let Ok(document) = crate::mcp_lock::parse_json_no_duplicates(&text) else {
            continue;
        };
        let Some(settings) = document
            .get("extensions")
            .and_then(|value| value.get("settings"))
            .and_then(|value| value.as_object())
        else {
            continue;
        };
        source = InstallClassSource::Preferences;
        for id in ids {
            if classes.contains_key(id) {
                continue;
            }
            let Some(entry) = settings.get(id).and_then(|value| value.as_object()) else {
                continue;
            };
            // The three allowed fields, converted to typed values here and
            // nowhere else.
            let location = entry.get("location").and_then(|value| value.as_u64());
            let from_webstore = entry
                .get("from_webstore")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            let installed_by_default = entry
                .get("was_installed_by_default")
                .and_then(|value| value.as_bool())
                .unwrap_or(false);
            classes.insert(
                id.clone(),
                classify_install(location, from_webstore, installed_by_default),
            );
        }
    }

    InstallClassLookup { classes, source }
}

/// Map Chromium's `Extension::Location` ordinal plus the two boolean flags onto
/// an [`InstallClass`].
///
/// The ordinals are Chromium's own `mojom::ManifestLocation` values; an
/// unrecognized ordinal degrades to [`InstallClass::Unknown`] rather than being
/// guessed into a class.
fn classify_install(
    location: Option<u64>,
    from_webstore: bool,
    installed_by_default: bool,
) -> InstallClass {
    match location {
        // INTERNAL: installed by the browser itself. The webstore flag is what
        // separates a store install from a browser-bundled default.
        Some(1) => {
            if from_webstore {
                InstallClass::WebStore
            } else if installed_by_default {
                InstallClass::BrowserComponent
            } else {
                InstallClass::Sideloaded
            }
        }
        // EXTERNAL_PREF, EXTERNAL_REGISTRY, EXTERNAL_PREF_DOWNLOAD.
        Some(2) | Some(3) | Some(6) => InstallClass::Sideloaded,
        // UNPACKED, COMMAND_LINE.
        Some(4) | Some(8) => InstallClass::DeveloperUnpacked,
        // COMPONENT, EXTERNAL_COMPONENT.
        Some(5) | Some(10) => InstallClass::BrowserComponent,
        // EXTERNAL_POLICY_DOWNLOAD, EXTERNAL_POLICY.
        Some(7) | Some(9) => InstallClass::EnterprisePolicy,
        _ => InstallClass::Unknown,
    }
}

/// Audit one extension id.
///
/// Always returns a record. An extension whose `manifest.json` cannot be parsed,
/// whose directory cannot be listed, or that holds no version directory is
/// REPORTED as unauditable rather than dropped, because an id present on disk is
/// a fact about the profile and dropping it is what let a newly installed
/// extension produce `drift: []` and exit 0.
#[allow(clippy::too_many_arguments)]
fn audit_extension(
    profile_root: &Path,
    extensions_root: &Path,
    profile_identity: &BrowserProfileIdentity,
    id: &str,
    install_class: InstallClass,
    install_source: InstallClassSource,
    budget: &AuditBudget,
    state: &mut AuditProgress,
) -> ExtensionRecord {
    let extension_dir = extensions_root.join(id);
    let mut local_rejected: Vec<RejectedEntry> = Vec::new();
    let mut local_gaps: Vec<AuditCoverageGap> = Vec::new();
    // Every path beneath `Extensions/<id>/` that could not be enumerated, or is
    // not a version directory, lands HERE rather than in the caller's profile
    // level lists. A rejection recorded one level up leaves the surviving
    // ExtensionRecord saying `coverage: complete`, and drift is computed from the
    // record, so the gap would never reach a verify run.
    let mut enumeration_complete = true;
    let mut version_dirs: Vec<String> = Vec::new();
    let scope = format!("Extensions/{id}");

    let entries = match std::fs::read_dir(&extension_dir) {
        Ok(entries) => entries,
        Err(error) => {
            local_rejected.push(RejectedEntry {
                path: scope.clone(),
                reason: RejectionReason::Unreadable {
                    permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
                },
            });
            local_gaps.push(AuditCoverageGap {
                scope: scope.clone(),
                kind: CoverageGapKind::EnumerationFailed,
            });
            return unaudited_record(
                profile_identity,
                id,
                install_class,
                Vec::new(),
                local_rejected,
                local_gaps,
            );
        }
    };
    for entry in entries {
        // A mid-readdir failure hides an unknown set of names; the other two
        // enumerators in this module record exactly this, and so does this one.
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                push_bounded_rejection(
                    &mut local_rejected,
                    &scope,
                    scope.clone(),
                    RejectionReason::Unreadable {
                        permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
                    },
                );
                enumeration_complete = false;
                continue;
            }
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            push_bounded_rejection(
                &mut local_rejected,
                &scope,
                format!("{scope}/<non-utf8>"),
                RejectionReason::NonUtf8Name,
            );
            enumeration_complete = false;
            continue;
        };
        let relative = format!("Extensions/{id}/{name}");
        match std::fs::symlink_metadata(entry.path()) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                push_bounded_rejection(
                    &mut local_rejected,
                    &scope,
                    relative,
                    RejectionReason::Symlink,
                );
                enumeration_complete = false;
            }
            Ok(metadata) if metadata.is_dir() => {
                if version_dirs.len() >= MAX_VERSION_DIRECTORIES {
                    enumeration_complete = false;
                } else {
                    version_dirs.push(name);
                }
            }
            // Anything else directly beneath `Extensions/<id>/` is outside the
            // audited read set: a stray payload dropped there is never hashed,
            // so the honest report is that it was seen and not covered.
            Ok(_) => {
                push_bounded_rejection(
                    &mut local_rejected,
                    &scope,
                    relative,
                    RejectionReason::UnexpectedEntry,
                );
                enumeration_complete = false;
            }
            Err(error) => {
                push_bounded_rejection(
                    &mut local_rejected,
                    &scope,
                    relative,
                    RejectionReason::Unreadable {
                        permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
                    },
                );
                enumeration_complete = false;
            }
        }
    }
    version_dirs.sort();
    let colliding = colliding_names(&version_dirs);
    if !colliding.is_empty() {
        for name in &version_dirs {
            if colliding.contains(&fold_key(name)) {
                push_bounded_rejection(
                    &mut local_rejected,
                    &scope,
                    format!("{scope}/{name}"),
                    RejectionReason::NameCollision,
                );
            }
        }
        version_dirs.retain(|name| !colliding.contains(&fold_key(name)));
        enumeration_complete = false;
    }
    if version_dirs.is_empty() {
        local_rejected.push(RejectedEntry {
            path: scope,
            reason: RejectionReason::NoVersionDirectory,
        });
        return unaudited_record(
            profile_identity,
            id,
            install_class,
            version_dirs,
            local_rejected,
            local_gaps,
        );
    }
    let selected = select_version_directory(&version_dirs);
    let version_dir = extension_dir.join(&selected);

    // Anchored on the PROFILE root, not on `extension_dir`. Anchoring on a path
    // derived from the same walk cannot detect an escape: with `Extensions`
    // itself a symlink, `extension_dir` resolves through it too and the check
    // compares the escape against itself. The profile is the trust root the
    // operator named, and RejectionReason::OutsideProfile has always said so.
    if !crate::util::canonical_within(&version_dir, profile_root) {
        local_rejected.push(RejectedEntry {
            path: format!("Extensions/{id}/{selected}"),
            reason: RejectionReason::OutsideProfile,
        });
        return unaudited_record(
            profile_identity,
            id,
            install_class,
            version_dirs,
            local_rejected,
            local_gaps,
        );
    }

    let relative_root = format!("Extensions/{id}/{selected}");
    let capability = match crate::util::dirfd::DirCapability::open_root(&version_dir) {
        Ok(capability) => capability,
        Err(error) => {
            local_rejected.push(RejectedEntry {
                path: relative_root.clone(),
                reason: child_error_reason(&error),
            });
            local_gaps.push(AuditCoverageGap {
                scope: relative_root,
                kind: CoverageGapKind::EnumerationFailed,
            });
            return unaudited_record(
                profile_identity,
                id,
                install_class,
                version_dirs,
                local_rejected,
                local_gaps,
            );
        }
    };

    let manifest = match read_manifest(&capability) {
        Ok(value) => value,
        Err(reason) => {
            local_rejected.push(RejectedEntry {
                path: format!("{relative_root}/manifest.json"),
                reason,
            });
            local_gaps.push(AuditCoverageGap {
                scope: relative_root,
                kind: CoverageGapKind::Unreadable,
            });
            return unaudited_record(
                profile_identity,
                id,
                install_class,
                version_dirs,
                local_rejected,
                local_gaps,
            );
        }
    };

    let walk = walk_tree(
        capability,
        &relative_root,
        budget,
        state,
        &mut local_rejected,
        &mut local_gaps,
    );

    let facts = ManifestFacts::from_value(&manifest);
    let provenance = walk.provenance;
    let surfaces = facts.surfaces;
    let risk = assess_risk(&facts.permissions, &facts.host_permissions, &surfaces);
    let surface_hash = compute_surface_hash(&SurfaceHashInput {
        manifest_version: facts.manifest_version,
        permissions: &facts.permissions,
        optional_permissions: &facts.optional_permissions,
        host_permissions: &facts.host_permissions,
        optional_host_permissions: &facts.optional_host_permissions,
        surfaces: &surfaces,
        install_class,
        provenance,
    });

    let mut coverage = AuditCoverage::Complete;
    coverage.degrade(!walk.complete);
    coverage.degrade(!enumeration_complete);
    coverage.degrade(!local_rejected.is_empty() || !local_gaps.is_empty());
    coverage.degrade(install_source == InstallClassSource::Unavailable);
    coverage.degrade(install_class == InstallClass::Unknown);

    local_rejected.sort();
    local_rejected.dedup();
    sort_gaps(&mut local_gaps);

    ExtensionRecord {
        identity: BrowserExtensionIdentity {
            profile: profile_identity.clone(),
            extension_id: id.to_string(),
        },
        id: id.to_string(),
        name: facts.name,
        version: facts.version,
        version_directory: selected,
        version_directories: version_dirs,
        manifest_version: facts.manifest_version,
        install_class,
        provenance,
        permissions: facts.permissions,
        optional_permissions: facts.optional_permissions,
        host_permissions: facts.host_permissions,
        optional_host_permissions: facts.optional_host_permissions,
        surfaces,
        risk,
        tree: TreeDigest {
            digest: walk.digest,
            file_count: walk.file_count,
            total_bytes: walk.total_bytes,
            complete: walk.complete,
        },
        surface_hash,
        wallet_fixture_match: is_wallet_fixture_id(id),
        coverage,
        enumeration_complete,
        rejected: local_rejected,
        gaps: local_gaps,
    }
}

/// An extension that is PRESENT on disk and could not be audited.
///
/// Returning nothing at all was the wrong answer: an attacker who installs a new
/// high-privilege extension whose `manifest.json` a strict parser refuses (a
/// repeated key, say, which Chromium itself accepts) made the extension vanish
/// from the inventory, so a `--baseline` run reported `drift: []` and exited 0
/// over a profile that had just gained it. An unauditable extension is a fact
/// about the profile, and this is that fact.
fn unaudited_record(
    profile_identity: &BrowserProfileIdentity,
    id: &str,
    install_class: InstallClass,
    version_directories: Vec<String>,
    mut rejected: Vec<RejectedEntry>,
    mut gaps: Vec<AuditCoverageGap>,
) -> ExtensionRecord {
    rejected.sort();
    rejected.dedup();
    sort_gaps(&mut gaps);
    let surfaces = ExecutionSurfaces::default();
    let surface_hash = compute_surface_hash(&SurfaceHashInput {
        manifest_version: 0,
        permissions: &[],
        optional_permissions: &[],
        host_permissions: &[],
        optional_host_permissions: &[],
        surfaces: &surfaces,
        install_class,
        provenance: ProvenanceClass::Unrecorded,
    });
    ExtensionRecord {
        identity: BrowserExtensionIdentity {
            profile: profile_identity.clone(),
            extension_id: id.to_string(),
        },
        id: id.to_string(),
        name: String::new(),
        version: String::new(),
        version_directory: String::new(),
        version_directories,
        manifest_version: 0,
        install_class,
        provenance: ProvenanceClass::Unrecorded,
        permissions: Vec::new(),
        optional_permissions: Vec::new(),
        host_permissions: Vec::new(),
        optional_host_permissions: Vec::new(),
        surfaces,
        risk: PermissionRisk::default(),
        tree: TreeDigest {
            digest: String::new(),
            file_count: 0,
            total_bytes: 0,
            complete: false,
        },
        surface_hash,
        wallet_fixture_match: is_wallet_fixture_id(id),
        coverage: AuditCoverage::Partial,
        enumeration_complete: false,
        rejected,
        gaps,
    }
}

/// Pick the version directory to audit: the highest `(numeric version tuple,
/// ordinal)`, falling back to byte order for a name that does not parse. The
/// choice is recorded in [`ExtensionRecord::version_directory`] so it is never
/// implicit.
fn select_version_directory(names: &[String]) -> String {
    names
        .iter()
        .max_by(|a, b| version_sort_key(a).cmp(&version_sort_key(b)))
        .cloned()
        .unwrap_or_default()
}

/// `<version>_<ordinal>` split into comparable parts. A name that does not parse
/// sorts below every parsed name, and ties break on the raw string so the choice
/// stays deterministic.
fn version_sort_key(name: &str) -> (Vec<u64>, u64, String) {
    let (version, ordinal) = match name.rsplit_once('_') {
        Some((version, ordinal)) if ordinal.bytes().all(|b| b.is_ascii_digit()) => {
            (version, ordinal.parse::<u64>().unwrap_or(0))
        }
        _ => (name, 0),
    };
    let parts: Vec<u64> = version
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect();
    (parts, ordinal, name.to_string())
}

/// `true` when `id` appears as a wallet extension id in the shared
/// sensitive-asset catalogue. A LABEL, never a trust anchor.
pub fn is_wallet_fixture_id(id: &str) -> bool {
    crate::sensitive_assets::SENSITIVE_PATH_DEFINITIONS
        .iter()
        .any(|definition| {
            definition.match_mode
                == crate::sensitive_assets::SensitivePathMatchMode::BrowserExtensionId
                && definition.match_root == id
        })
}

/// Maximum rejections, and separately maximum coverage gaps, RECORDED for one
/// extension tree.
///
/// Without a ceiling the report grows linearly with an attacker-chosen file
/// count: an extension directory of 300 000 empty files costs its author a few
/// KiB and drives the auditor to hundreds of MiB of resident memory and tens of
/// MiB of JSON, because every entry past a budget used to push its own rejection
/// AND its own gap. Coverage is already partial once anything is refused, so the
/// paths past this point add no verdict, only volume.
const MAX_RECORDED_TREE_ENTRIES: usize = 256;

/// Maximum entries read from ONE directory of an extension tree in one listing.
/// Enforced during the read, so a hostile directory cannot make the walker
/// allocate an unbounded listing before any cap applies.
const MAX_TREE_ENTRIES_PER_DIRECTORY: usize = 65_536;

/// Maximum version directories recorded for one extension. Real Chrome keeps a
/// handful during an update; a directory holding more is a hostile shape, and
/// the list is carried into the baseline, so it is capped rather than allowed to
/// grow with an attacker-chosen entry count.
const MAX_VERSION_DIRECTORIES: usize = 256;

/// Push a rejection, stopping at [`MAX_RECORDED_TREE_ENTRIES`] and recording one
/// truncation marker instead.
///
/// Used at the enumeration sites ABOVE the tree walk, which face the same
/// pressure the walk does: entries directly beneath `Extensions/` and
/// `Extensions/<id>/` are attacker-chosen and cost nothing to create, so one
/// rejection each is one report entry each.
fn push_bounded_rejection(
    rejected: &mut Vec<RejectedEntry>,
    scope: &str,
    path: String,
    reason: RejectionReason,
) {
    if rejected.len() < MAX_RECORDED_TREE_ENTRIES {
        rejected.push(RejectedEntry { path, reason });
        return;
    }
    let marker = RejectedEntry {
        path: scope.to_string(),
        reason: RejectionReason::RecordLimitReached,
    };
    if !rejected.contains(&marker) {
        rejected.push(marker);
    }
}

/// Bounded recorder for one tree's rejections and gaps. Past the ceiling it
/// records a single [`RejectionReason::RecordLimitReached`] marker and drops the
/// rest, so the report stays bounded while still saying that it was truncated.
struct BoundedRecord<'a> {
    rejected: &'a mut Vec<RejectedEntry>,
    gaps: &'a mut Vec<AuditCoverageGap>,
    scope: String,
    marked: bool,
}

impl<'a> BoundedRecord<'a> {
    fn new(
        rejected: &'a mut Vec<RejectedEntry>,
        gaps: &'a mut Vec<AuditCoverageGap>,
        scope: &str,
    ) -> Self {
        Self {
            rejected,
            gaps,
            scope: scope.to_string(),
            marked: false,
        }
    }

    fn reject(&mut self, path: String, reason: RejectionReason) {
        if self.rejected.len() >= MAX_RECORDED_TREE_ENTRIES {
            self.mark_limit();
            return;
        }
        self.rejected.push(RejectedEntry { path, reason });
    }

    fn gap(&mut self, scope: String, kind: CoverageGapKind) {
        if self.gaps.len() >= MAX_RECORDED_TREE_ENTRIES {
            self.mark_limit();
            return;
        }
        self.gaps.push(AuditCoverageGap { scope, kind });
    }

    fn mark_limit(&mut self) {
        if self.marked {
            return;
        }
        self.marked = true;
        self.rejected.push(RejectedEntry {
            path: self.scope.clone(),
            reason: RejectionReason::RecordLimitReached,
        });
        self.gaps.push(AuditCoverageGap {
            scope: self.scope.clone(),
            kind: CoverageGapKind::EntryCountCapped,
        });
    }
}

/// The result of walking one extension version tree.
struct WalkResult {
    digest: String,
    file_count: usize,
    total_bytes: u64,
    complete: bool,
    provenance: ProvenanceClass,
}

/// Name a refused directory descent. The refusal already happened; this only
/// decides which reason to report.
fn child_error_reason(error: &crate::util::dirfd::ChildError) -> RejectionReason {
    match error {
        crate::util::dirfd::ChildError::Symlink => RejectionReason::Symlink,
        crate::util::dirfd::ChildError::NotADirectory
        | crate::util::dirfd::ChildError::UnsafeName => RejectionReason::NotRegularFile,
        crate::util::dirfd::ChildError::Io(error) => RejectionReason::Unreadable {
            permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
        },
    }
}

/// Walk the tree behind `root`, hashing every regular file, and fold the sorted
/// `(relative path, file digest)` pairs into one tree digest.
///
/// Determinism does not depend on readdir order: the pairs are collected first
/// and sorted by relative path before any folding.
///
/// # Why the walk holds descriptors rather than paths
///
/// Every directory is entered once through
/// [`crate::util::dirfd::DirCapability::open_child_directory`], which is an
/// `openat` with `O_NOFOLLOW | O_DIRECTORY` against the RETAINED parent
/// descriptor, and the descriptor is what the walk keeps. A path-based walk
/// `lstat`s a child, pushes it, and later re-opens it BY NAME; because the stack
/// is LIFO, a directory can wait there for the whole sibling subtree, which
/// makes the check-to-use window seconds wide. An attacker who swaps that
/// directory for a symlink inside the window gets the walker to enumerate and
/// HASH files outside the extension tree, and the sensitive-asset gate does not
/// save it because that gate sees the APPARENT path. Holding the descriptor
/// removes the second resolution, so the window does not exist.
fn walk_tree(
    root: crate::util::dirfd::DirCapability,
    relative_root: &str,
    budget: &AuditBudget,
    state: &mut AuditProgress,
    rejected: &mut Vec<RejectedEntry>,
    gaps: &mut Vec<AuditCoverageGap>,
) -> WalkResult {
    let mut record = BoundedRecord::new(rejected, gaps, relative_root);
    let mut files: Vec<(String, String)> = Vec::new();
    let mut complete = true;
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    let mut has_computed_hashes = false;
    let mut has_verified_contents = false;

    // (directory capability, relative-to-root prefix, depth)
    let mut stack: Vec<(crate::util::dirfd::DirCapability, String, usize)> =
        vec![(root, String::new(), 0)];
    'walk: while let Some((directory, prefix, depth)) = stack.pop() {
        if depth > budget.max_depth {
            record.reject(
                join_relative(relative_root, &prefix),
                RejectionReason::DepthExceeded,
            );
            complete = false;
            continue;
        }
        let (entries, listing_truncated) =
            match directory.read_entries(MAX_TREE_ENTRIES_PER_DIRECTORY) {
                Ok(listing) => listing,
                Err(error) => {
                    record.reject(
                        join_relative(relative_root, &prefix),
                        RejectionReason::Unreadable {
                            permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
                        },
                    );
                    record.gap(
                        join_relative(relative_root, &prefix),
                        CoverageGapKind::EnumerationFailed,
                    );
                    complete = false;
                    continue;
                }
            };
        if listing_truncated {
            record.gap(
                join_relative(relative_root, &prefix),
                CoverageGapKind::EntryCountCapped,
            );
            complete = false;
        }

        let names: Vec<String> = entries
            .iter()
            .filter_map(|entry| entry.name.clone())
            .collect();
        let colliding = colliding_names(&names);

        for entry in entries {
            let Some(name) = entry.name else {
                record.reject(
                    join_relative(relative_root, &prefix),
                    RejectionReason::NonUtf8Name,
                );
                complete = false;
                continue;
            };
            let child_relative = join_relative(&prefix, &name);
            if colliding.contains(&fold_key(&name)) {
                record.reject(
                    join_relative(relative_root, &child_relative),
                    RejectionReason::NameCollision,
                );
                complete = false;
                continue;
            }
            match entry.kind {
                crate::util::dirfd::EntryKind::Symlink => {
                    // Refused WITHOUT resolving or opening the target, so a link
                    // out of the tree cannot pull foreign bytes into the digest.
                    record.reject(
                        join_relative(relative_root, &child_relative),
                        RejectionReason::Symlink,
                    );
                    complete = false;
                }
                crate::util::dirfd::EntryKind::Directory => {
                    match directory.open_child_directory(&name) {
                        Ok(child) => stack.push((child, child_relative, depth + 1)),
                        Err(error) => {
                            record.reject(
                                join_relative(relative_root, &child_relative),
                                child_error_reason(&error),
                            );
                            record.gap(
                                join_relative(relative_root, &child_relative),
                                CoverageGapKind::EnumerationFailed,
                            );
                            complete = false;
                        }
                    }
                }
                crate::util::dirfd::EntryKind::Other => {
                    record.reject(
                        join_relative(relative_root, &child_relative),
                        RejectionReason::NotRegularFile,
                    );
                    complete = false;
                }
                crate::util::dirfd::EntryKind::RegularFile => {
                    if child_relative == "_metadata/computed_hashes.json" {
                        has_computed_hashes = true;
                    }
                    if child_relative == "_metadata/verified_contents.json" {
                        has_verified_contents = true;
                    }

                    if file_count >= budget.max_files_per_extension
                        || total_bytes >= budget.max_bytes_per_extension
                        || state.exhausted(budget)
                    {
                        // Stop the WALK, not just the hashing. Continuing to
                        // enumerate cannot add a hashed byte, and recording one
                        // rejection per remaining entry is how an attacker turns
                        // a cheap directory of empty files into an unbounded
                        // report.
                        record.reject(relative_root.to_string(), RejectionReason::BudgetExhausted);
                        record.gap(
                            relative_root.to_string(),
                            if total_bytes >= budget.max_bytes_per_extension
                                || state.bytes_used >= budget.max_total_bytes
                            {
                                CoverageGapKind::TotalBytesCapped
                            } else {
                                CoverageGapKind::EntryCountCapped
                            },
                        );
                        complete = false;
                        break 'walk;
                    }

                    let apparent = directory.path().join(&name);
                    match hash_tree_file(&directory, &name, &apparent, budget.max_file_bytes) {
                        Ok((digest, size)) => {
                            files.push((child_relative, digest));
                            file_count += 1;
                            total_bytes = total_bytes.saturating_add(size);
                            state.files_used += 1;
                            state.bytes_used = state.bytes_used.saturating_add(size);
                        }
                        Err(FileHashError::Rejected(reason)) => {
                            let kind = match reason {
                                RejectionReason::Oversize { .. } => CoverageGapKind::Oversized,
                                _ => CoverageGapKind::Unreadable,
                            };
                            record.reject(join_relative(relative_root, &child_relative), reason);
                            record.gap(join_relative(relative_root, &child_relative), kind);
                            complete = false;
                        }
                        Err(FileHashError::BudgetExceeded) => {
                            record.gap(
                                join_relative(relative_root, &child_relative),
                                CoverageGapKind::HashBudgetExceeded,
                            );
                            complete = false;
                        }
                    }
                }
            }
        }
    }

    files.sort();
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    // Version-tagged so a later change to the folding rules is a
    // SchemaUpgradeRequired drift rather than a silent digest change.
    hasher.update(format!("tirith-browser-tree-v{BROWSER_BASELINE_FORMAT_VERSION}\n").as_bytes());
    for (path, digest) in &files {
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(digest.as_bytes());
        hasher.update(b"\n");
    }
    let digest = hex::encode(hasher.finalize());

    WalkResult {
        digest,
        file_count,
        total_bytes,
        complete,
        provenance: if has_verified_contents {
            ProvenanceClass::StoreSigned
        } else if has_computed_hashes {
            ProvenanceClass::ComputedHashesOnly
        } else {
            ProvenanceClass::Unrecorded
        },
    }
}

fn join_relative(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else if name.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

enum FileHashError {
    Rejected(RejectionReason),
    BudgetExceeded,
}

/// Open one tree file through the RETAINED directory descriptor and stream its
/// SHA-256, returning `(digest, size)`.
///
/// The same three gates [`open_audit_file`] applies, plus one this position
/// needs and a path-based open cannot express: a regular file with more than one
/// link is refused. A hard link is invisible to every symlink guard in this
/// module (`symlink_metadata` calls it a regular file and `classify_path` sees
/// only the name it was given), so without this check a link planted at
/// `Extensions/<id>/<version>/data.bin` pointing at the profile's cookie jar
/// would be read in full and folded into the digest.
fn hash_tree_file(
    directory: &crate::util::dirfd::DirCapability,
    name: &str,
    apparent: &Path,
    budget: u64,
) -> Result<(String, u64), FileHashError> {
    if let Some(reason) = refuse_sensitive_path(apparent) {
        return Err(FileHashError::Rejected(reason));
    }
    let file = directory
        .open_child_file(name, budget)
        .map_err(|error| FileHashError::Rejected(open_error_reason(error, apparent)))?;
    if crate::util::dirfd::hard_link_count(&file).is_some_and(|links| links > 1) {
        return Err(FileHashError::Rejected(RejectionReason::HardLink));
    }
    let size = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
    match crate::util::sha256_from_handle(file, budget) {
        Ok(HashOutcome::Digest(digest)) => Ok((digest, size)),
        Ok(HashOutcome::BudgetExceeded) => Err(FileHashError::BudgetExceeded),
        Err(error) => Err(FileHashError::Rejected(RejectionReason::Unreadable {
            permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
        })),
    }
}

/// Map an open failure onto the rejection the report records.
fn open_error_reason(error: OpenRegularError, path: &Path) -> RejectionReason {
    match error {
        OpenRegularError::NotFound => RejectionReason::Unreadable {
            permission_denied: false,
        },
        OpenRegularError::NotRegularFile => RejectionReason::NotRegularFile,
        OpenRegularError::TooLarge => RejectionReason::Oversize {
            size_bytes: std::fs::symlink_metadata(path)
                .map(|metadata| metadata.len())
                .unwrap_or(0),
        },
        OpenRegularError::Io(error) => RejectionReason::Unreadable {
            permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
        },
    }
}

/// `Some(RejectionReason::SensitivePath)` when `path` is one this audit must
/// never open, from EITHER of the two independent gates.
///
/// The two are independent on purpose. The catalogue gate knows about credential
/// stores and wallet storage anywhere on the machine but, for a browser profile,
/// only fires when a hardcoded wallet extension id is also present in the path.
/// The lexical gate knows nothing about wallets and refuses the profile stores
/// by name, so neither gate's blind spot is the other's.
fn refuse_sensitive_path(path: &Path) -> Option<RejectionReason> {
    if crate::sensitive_assets::classify_path(&path.to_string_lossy()).is_some() {
        return Some(RejectionReason::SensitivePath);
    }
    let names_a_profile_store = path.components().any(|component| {
        let component = component.as_os_str().to_string_lossy();
        NEVER_READ_PROFILE_STORES
            .iter()
            .any(|store| component.eq_ignore_ascii_case(store))
    });
    names_a_profile_store.then_some(RejectionReason::SensitivePath)
}

/// THE read gate. Every byte this module reads passes through here.
///
/// Three independent guarantees:
///
/// 1. [`crate::sensitive_assets::classify_path`] must return `None`. That is the
///    shared catalogue's statement that the path is not a credential store, a
///    wallet store, or browser extension STORAGE, and it is the same predicate
///    the capsule deny set is built from. It is deliberately conservative: an
///    extension shipping a file named `wallet.dat` is refused and becomes a
///    coverage gap, which is the right way round.
/// 2. No component may name one of [`NEVER_READ_PROFILE_STORES`]. The catalogue
///    gate alone does NOT cover those: it requires a wallet extension id in the
///    path before it will call a browser storage root sensitive, so a plain
///    cookie jar walks straight through it.
/// 3. [`crate::util::open_read_no_follow_capped`] refuses a symlinked final
///    component, refuses anything that is not a regular file, and refuses a file
///    over `cap` bytes, all after `fstat`ing the OPEN descriptor.
pub fn open_audit_file(path: &Path, cap: u64) -> Result<std::fs::File, RejectionReason> {
    if let Some(reason) = refuse_sensitive_path(path) {
        return Err(reason);
    }
    crate::util::open_read_no_follow_capped(path, cap)
        .map_err(|error| open_error_reason(error, path))
}

/// Bounded read of one file through a RETAINED directory descriptor, so the
/// component is not re-resolved after the directory was opened.
fn read_through_capability(
    directory: &crate::util::dirfd::DirCapability,
    name: &str,
    cap: u64,
) -> Result<Vec<u8>, RejectionReason> {
    let apparent = directory.path().join(name);
    if let Some(reason) = refuse_sensitive_path(&apparent) {
        return Err(reason);
    }
    let file = directory
        .open_child_file(name, cap)
        .map_err(|error| open_error_reason(error, &apparent))?;
    read_capped(file, cap)
}

/// Bounded read through [`open_audit_file`].
fn open_audit_read(path: &Path, cap: u64) -> Result<Vec<u8>, RejectionReason> {
    let file = open_audit_file(path, cap)?;
    read_capped(file, cap)
}

/// Read at most `cap` bytes, refusing a file that GREW past the ceiling between
/// the post-open `fstat` and the read.
fn read_capped(file: std::fs::File, cap: u64) -> Result<Vec<u8>, RejectionReason> {
    use std::io::Read as _;
    let mut buffer = Vec::new();
    file.take(cap.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|error| RejectionReason::Unreadable {
            permission_denied: error.kind() == std::io::ErrorKind::PermissionDenied,
        })?;
    if buffer.len() as u64 > cap {
        return Err(RejectionReason::Oversize {
            size_bytes: buffer.len() as u64,
        });
    }
    Ok(buffer)
}

/// Read and strictly parse `manifest.json`.
///
/// `manifest.json` is attacker-controlled, so it goes through
/// [`crate::mcp_lock::parse_json_no_duplicates`] rather than `serde_json`'s
/// last-wins duplicate collapse: a manifest that declares `"permissions"` twice
/// must not let tirith audit a different object than the browser loads.
fn read_manifest(
    directory: &crate::util::dirfd::DirCapability,
) -> Result<serde_json::Value, RejectionReason> {
    let path = directory.path().join("manifest.json");
    let bytes = match read_through_capability(directory, "manifest.json", MAX_MANIFEST_BYTES) {
        Ok(bytes) => bytes,
        Err(RejectionReason::Unreadable {
            permission_denied: false,
        }) if !path.exists() => return Err(RejectionReason::MissingManifest),
        Err(reason) => return Err(reason),
    };
    let text = String::from_utf8(bytes).map_err(|_| RejectionReason::MalformedManifest)?;
    match crate::mcp_lock::parse_json_no_duplicates(&text) {
        Ok(value) if value.is_object() => Ok(value),
        Ok(_) => Err(RejectionReason::MalformedManifest),
        Err(crate::mcp_lock::StrictJsonError::DuplicateObjectKey) => {
            Err(RejectionReason::DuplicateJsonKey)
        }
        Err(_) => Err(RejectionReason::MalformedManifest),
    }
}

/// The declared surface, extracted from a parsed manifest.
struct ManifestFacts {
    name: String,
    version: String,
    manifest_version: u64,
    permissions: Vec<String>,
    optional_permissions: Vec<String>,
    host_permissions: Vec<String>,
    optional_host_permissions: Vec<String>,
    surfaces: ExecutionSurfaces,
}

/// Maximum recorded entries per manifest list, so a manifest declaring a hundred
/// thousand match patterns cannot inflate a baseline without bound.
const MAX_MANIFEST_LIST_ENTRIES: usize = 512;

/// Maximum recorded bytes of any single manifest-derived string.
const MAX_MANIFEST_STRING_BYTES: usize = 256;

impl ManifestFacts {
    fn from_value(manifest: &serde_json::Value) -> Self {
        let manifest_version = manifest
            .get("manifest_version")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);

        let declared = string_list(manifest.get("permissions"));
        let (permissions, mut host_permissions) = split_host_patterns(declared);
        host_permissions.extend(string_list(manifest.get("host_permissions")));
        let declared_optional = string_list(manifest.get("optional_permissions"));
        let (optional_permissions, mut optional_host_permissions) =
            split_host_patterns(declared_optional);
        optional_host_permissions.extend(string_list(manifest.get("optional_host_permissions")));

        let surfaces = ExecutionSurfaces {
            background: background_kind(manifest),
            content_script_count: manifest
                .get("content_scripts")
                .and_then(|value| value.as_array())
                .map(|array| array.len())
                .unwrap_or(0),
            content_script_matches: content_script_matches(manifest),
            native_messaging: permissions.iter().any(|name| name == "nativeMessaging"),
            externally_connectable: manifest.get("externally_connectable").is_some(),
            externally_connectable_matches: sorted_unique(string_list(
                manifest
                    .get("externally_connectable")
                    .and_then(|value| value.get("matches")),
            )),
            externally_connectable_ids: sorted_unique(string_list(
                manifest
                    .get("externally_connectable")
                    .and_then(|value| value.get("ids")),
            )),
            web_accessible_resource_count: manifest
                .get("web_accessible_resources")
                .and_then(|value| value.as_array())
                .map(|array| array.len())
                .unwrap_or(0),
            declarative_net_request_rulesets: manifest
                .get("declarative_net_request")
                .and_then(|value| value.get("rule_resources"))
                .and_then(|value| value.as_array())
                .map(|array| array.len())
                .unwrap_or(0),
            devtools_page: manifest.get("devtools_page").is_some(),
            chrome_url_overrides: manifest
                .get("chrome_url_overrides")
                .and_then(|value| value.as_object())
                .map(|object| {
                    let mut keys: Vec<String> = object
                        .keys()
                        .take(MAX_MANIFEST_LIST_ENTRIES)
                        .map(|key| bounded_string(key))
                        .collect();
                    keys.sort();
                    keys
                })
                .unwrap_or_default(),
            sandbox_page_count: manifest
                .get("sandbox")
                .and_then(|value| value.get("pages"))
                .and_then(|value| value.as_array())
                .map(|array| array.len())
                .unwrap_or(0),
            content_security_policy: manifest.get("content_security_policy").is_some(),
        };

        Self {
            name: manifest
                .get("name")
                .and_then(|value| value.as_str())
                .map(bounded_string)
                .unwrap_or_default(),
            version: manifest
                .get("version")
                .and_then(|value| value.as_str())
                .map(bounded_string)
                .unwrap_or_default(),
            manifest_version,
            permissions: sorted_unique(permissions),
            optional_permissions: sorted_unique(optional_permissions),
            host_permissions: sorted_unique(host_permissions),
            optional_host_permissions: sorted_unique(optional_host_permissions),
            surfaces,
        }
    }
}

/// Display-sanitize and truncate a manifest-derived string. Manifest text is
/// attacker-controlled and reaches both a terminal and a durable baseline, so it
/// is stripped of terminal-control and deceptive Unicode before either.
fn bounded_string(value: &str) -> String {
    crate::util::truncate_bytes(
        &crate::mcp::output_filter::sanitize_for_display(value),
        MAX_MANIFEST_STRING_BYTES,
    )
}

fn string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(|value| value.as_array())
        .map(|array| {
            array
                .iter()
                .filter_map(|item| item.as_str())
                .take(MAX_MANIFEST_LIST_ENTRIES)
                .map(bounded_string)
                .collect()
        })
        .unwrap_or_default()
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

/// `true` when a permission string is a host match pattern rather than an API
/// permission. MV2 puts both in one list; splitting them keeps an MV2-to-MV3
/// migration from reading as a permission reduction plus a host expansion.
fn is_host_pattern(value: &str) -> bool {
    value == "<all_urls>"
        || value.contains("://")
        || value.starts_with("*.")
        || value.starts_with("file:")
}

fn split_host_patterns(values: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut api = Vec::new();
    let mut hosts = Vec::new();
    for value in values {
        if is_host_pattern(&value) {
            hosts.push(value);
        } else {
            api.push(value);
        }
    }
    (api, hosts)
}

fn background_kind(manifest: &serde_json::Value) -> BackgroundKind {
    let Some(background) = manifest.get("background") else {
        return BackgroundKind::None;
    };
    if background.get("service_worker").is_some() {
        BackgroundKind::ServiceWorker
    } else if background.get("scripts").is_some() {
        BackgroundKind::Scripts
    } else if background.get("page").is_some() {
        BackgroundKind::Page
    } else {
        BackgroundKind::None
    }
}

fn content_script_matches(manifest: &serde_json::Value) -> Vec<String> {
    let Some(entries) = manifest
        .get("content_scripts")
        .and_then(|value| value.as_array())
    else {
        return Vec::new();
    };
    let mut matches = Vec::new();
    for entry in entries.iter().take(MAX_MANIFEST_LIST_ENTRIES) {
        matches.extend(string_list(entry.get("matches")));
    }
    matches.truncate(MAX_MANIFEST_LIST_ENTRIES);
    sorted_unique(matches)
}

/// `true` for a host pattern that reaches every site.
fn is_all_hosts(pattern: &str) -> bool {
    matches!(
        pattern,
        "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" | "*://*/"
    )
}

/// Assess permission RISK. Never consulted by drift.
fn assess_risk(
    permissions: &[String],
    host_permissions: &[String],
    surfaces: &ExecutionSurfaces,
) -> PermissionRisk {
    let mut reasons = BTreeSet::new();
    if host_permissions.iter().any(|pattern| is_all_hosts(pattern))
        || surfaces
            .content_script_matches
            .iter()
            .any(|pattern| is_all_hosts(pattern))
    {
        reasons.insert(PermissionRiskReason::AllHosts);
    }
    for permission in permissions {
        let reason = match permission.as_str() {
            "debugger" => Some(PermissionRiskReason::Debugger),
            "nativeMessaging" => Some(PermissionRiskReason::NativeMessaging),
            "webRequestBlocking" => Some(PermissionRiskReason::WebRequestBlocking),
            "proxy" => Some(PermissionRiskReason::Proxy),
            "cookies" => Some(PermissionRiskReason::Cookies),
            "history" | "browsingData" => Some(PermissionRiskReason::BrowsingHistory),
            "management" => Some(PermissionRiskReason::Management),
            "downloads" => Some(PermissionRiskReason::Downloads),
            "scripting" => Some(PermissionRiskReason::Scripting),
            "privacy" | "contentSettings" => Some(PermissionRiskReason::BrowserSettings),
            "clipboardRead" => Some(PermissionRiskReason::ClipboardRead),
            _ => None,
        };
        if let Some(reason) = reason {
            reasons.insert(reason);
        }
    }
    let level = if reasons.contains(&PermissionRiskReason::AllHosts) {
        RiskLevel::Broad
    } else if reasons.is_empty() {
        RiskLevel::Ordinary
    } else {
        RiskLevel::Elevated
    };
    PermissionRisk {
        level,
        reasons: reasons.into_iter().collect(),
    }
}

struct SurfaceHashInput<'a> {
    manifest_version: u64,
    permissions: &'a [String],
    optional_permissions: &'a [String],
    host_permissions: &'a [String],
    optional_host_permissions: &'a [String],
    surfaces: &'a ExecutionSurfaces,
    install_class: InstallClass,
    provenance: ProvenanceClass,
}

/// sha256 over the canonical JSON of the declared surface, through
/// [`crate::mcp_lock::canonical_json`] so key order and whitespace in the
/// manifest cannot register as a change.
fn compute_surface_hash(input: &SurfaceHashInput<'_>) -> String {
    let value = serde_json::json!({
        "manifest_version": input.manifest_version,
        "permissions": input.permissions,
        "optional_permissions": input.optional_permissions,
        "host_permissions": input.host_permissions,
        "optional_host_permissions": input.optional_host_permissions,
        "surfaces": input.surfaces,
        "install_class": input.install_class.token(),
        "provenance": input.provenance.token(),
    });
    crate::command_card::sha256_hex(crate::mcp_lock::canonical_json(&value).as_bytes())
}

// ---------------------------------------------------------------------------
// Baseline document
// ---------------------------------------------------------------------------

/// One extension as a baseline records it. Deliberately narrower than
/// [`ExtensionRecord`]: risk, coverage gaps, and rejections are the CURRENT
/// run's observations, not facts to compare against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Schema-v2 identity. The flat fields below remain for additive wire
    /// compatibility, but matching and sorting use this full value.
    pub identity: BrowserExtensionIdentity,
    pub browser: BrowserFamily,
    pub profile_directory: String,
    pub extension_id: String,
    pub version: String,
    /// The version directory that was audited. Recorded because a genuine
    /// Chrome update writes a NEW `<version>_<ordinal>` directory; a declared
    /// version that moves while the directory does not is an in-place rewrite,
    /// which is a state a real update cannot produce.
    pub version_directory: String,
    /// Every version directory present, sorted. Recorded so a second tree
    /// appearing beside the audited one is drift: only the selected directory is
    /// hashed, so without this the set of trees present under an id could change
    /// freely and the comparison would still call the profile in sync.
    pub version_directories: Vec<String>,
    pub manifest_version: u64,
    pub install_class: InstallClass,
    pub provenance: ProvenanceClass,
    pub permissions: Vec<String>,
    pub optional_permissions: Vec<String>,
    pub host_permissions: Vec<String>,
    pub optional_host_permissions: Vec<String>,
    pub surfaces: ExecutionSurfaces,
    pub tree_digest: String,
    pub tree_complete: bool,
    /// See [`ExtensionRecord::enumeration_complete`]. Carried into the baseline
    /// so a gap ABOVE the tree walk reaches a verify run rather than being
    /// visible only as a profile-level rejection nobody compares.
    pub enumeration_complete: bool,
    pub surface_hash: String,
}

impl BaselineEntry {
    fn from_record(record: &ExtensionRecord) -> Self {
        Self {
            identity: record.identity.clone(),
            browser: record.identity.profile.root.family,
            profile_directory: record.identity.profile.profile_directory.clone(),
            extension_id: record.id.clone(),
            version: record.version.clone(),
            version_directory: record.version_directory.clone(),
            version_directories: record.version_directories.clone(),
            manifest_version: record.manifest_version,
            install_class: record.install_class,
            provenance: record.provenance,
            permissions: record.permissions.clone(),
            optional_permissions: record.optional_permissions.clone(),
            host_permissions: record.host_permissions.clone(),
            optional_host_permissions: record.optional_host_permissions.clone(),
            surfaces: record.surfaces.clone(),
            tree_digest: record.tree.digest.clone(),
            tree_complete: record.tree.complete,
            enumeration_complete: record.enumeration_complete,
            surface_hash: record.surface_hash.clone(),
        }
    }

    /// Whether this side of a comparison covered enough of the extension for a
    /// byte-level statement about it to mean anything.
    fn comparable(&self) -> bool {
        self.tree_complete && self.enumeration_complete
    }

    fn sort_key(&self) -> BrowserExtensionIdentity {
        self.identity.clone()
    }

    /// The `(browser, profile, id)` identity a drift entry refers to.
    pub fn subject(&self) -> DriftSubject {
        DriftSubject {
            identity: self.identity.clone(),
            browser: self.browser,
            profile_directory: self.profile_directory.clone(),
            extension_id: self.extension_id.clone(),
        }
    }
}

/// A content-addressed, optionally ed25519-signed extension baseline.
///
/// Modelled directly on [`crate::capsule_receipt::CapsuleRunReceipt`]: the same
/// canonicalizer ([`crate::audit::canonical_json_for_hash`]), the same content
/// address (sha256 over the canonical JSON with `receipt_id` and `signature`
/// blanked), and the same signing key and routine
/// ([`crate::audit::sign_canonical_bytes`]), so there is exactly one signing key
/// path in the product and no second crypto dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserBaseline {
    pub schema: u32,
    pub receipt_type: String,
    /// sha256 over the canonical JSON with `receipt_id` and `signature` blanked.
    pub receipt_id: String,
    pub created_at: String,
    pub tirith_version: String,
    /// The HASHING-rules version. A baseline written under an older value yields
    /// one [`ExtensionDrift::SchemaUpgradeRequired`] instead of phantom drift.
    pub format_version: u32,
    pub platform: Option<HostPlatform>,
    /// The coverage of the run that produced this baseline. A baseline taken
    /// from a partial run cannot prove absence later, and this field is what
    /// says so.
    pub coverage: AuditCoverage,
    pub entries: Vec<BaselineEntry>,
    /// sha256 over the canonical JSON of `entries` alone. Stable across runs of
    /// an unchanged profile (unlike `receipt_id`, which binds `created_at`), so
    /// it is the drift fast path and the idempotency check.
    pub inventory_hash: String,
    pub signature: Option<String>,
}

impl BrowserBaseline {
    /// Whether this parsed document is a legacy marker that must never be used
    /// as a comparison or signature-verification anchor.
    pub fn requires_schema_upgrade(&self) -> bool {
        self.schema != BROWSER_AUDIT_SCHEMA
            || self.format_version != BROWSER_BASELINE_FORMAT_VERSION
    }

    /// Build a baseline from a completed audit, stamp the content address, and
    /// sign it when the audit chain has a key.
    pub fn from_report(report: &BrowserAuditReport) -> Self {
        let entries = report.entries();
        let inventory_hash = inventory_hash(&entries);
        let mut baseline = Self {
            schema: BROWSER_AUDIT_SCHEMA,
            receipt_type: BROWSER_BASELINE_TYPE.to_string(),
            receipt_id: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            tirith_version: env!("CARGO_PKG_VERSION").to_string(),
            format_version: BROWSER_BASELINE_FORMAT_VERSION,
            platform: report.platform,
            coverage: report.coverage,
            entries,
            inventory_hash,
            signature: None,
        };
        baseline.receipt_id = baseline.compute_content_hash();
        baseline.signature =
            crate::audit::sign_canonical_bytes(baseline.signing_payload().as_bytes());
        baseline
    }

    /// The canonical JSON the signature covers: the whole document with the
    /// signature blanked and the content address PRESENT, so the signature binds
    /// the content address rather than floating free of it.
    pub fn signing_payload(&self) -> String {
        self.canonical_json(false)
    }

    /// Lowercase-hex sha256 of the canonical JSON with `receipt_id` and
    /// `signature` blanked.
    pub fn compute_content_hash(&self) -> String {
        crate::command_card::sha256_hex(self.canonical_json(true).as_bytes())
    }

    fn canonical_json(&self, blank_receipt_id: bool) -> String {
        let serialized = serde_json::to_value(self);
        debug_assert!(
            serialized.is_ok(),
            "browser baseline failed to serialize; a field is not serializable"
        );
        let mut value = serialized.unwrap_or(serde_json::Value::Null);
        if let Some(object) = value.as_object_mut() {
            if blank_receipt_id {
                object.insert(
                    "receipt_id".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
            object.insert("signature".to_string(), serde_json::Value::Null);
        }
        crate::audit::canonical_json_for_hash(&value)
    }

    /// Whether the stored id still matches a recomputation over the content.
    pub fn content_hash_matches(&self) -> bool {
        self.receipt_id == self.compute_content_hash()
    }

    /// Verify the detached signature against an ed25519 public key. `false` for
    /// an absent, malformed, or non-verifying signature, so a caller cannot read
    /// "unsigned" as "verified".
    pub fn signature_verifies(&self, public_key: &[u8; 32]) -> bool {
        use base64::Engine as _;
        use ed25519_dalek::Verifier as _;

        let Some(encoded) = self.signature.as_deref() else {
            return false;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
            return false;
        };
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify(self.signing_payload().as_bytes(), &signature)
            .is_ok()
    }

    /// Every internal-consistency rule, checked before the baseline is trusted
    /// as a comparison anchor.
    pub fn validate(&self) -> Result<(), BaselineError> {
        if self.schema != BROWSER_AUDIT_SCHEMA {
            return Err(BaselineError::UnsupportedSchema(self.schema));
        }
        if self.receipt_type != BROWSER_BASELINE_TYPE {
            return Err(BaselineError::WrongType);
        }
        let mut identities = BTreeSet::new();
        for entry in &self.entries {
            if entry.browser != entry.identity.profile.root.family
                || entry.profile_directory != entry.identity.profile.profile_directory
                || entry.extension_id != entry.identity.extension_id
            {
                return Err(BaselineError::IdentityMismatch);
            }
            if !identities.insert(entry.identity.clone()) {
                return Err(BaselineError::DuplicateIdentity);
            }
        }
        if !self.content_hash_matches() {
            return Err(BaselineError::ContentHashMismatch);
        }
        if self.inventory_hash != inventory_hash(&self.entries) {
            return Err(BaselineError::InventoryHashMismatch);
        }
        Ok(())
    }

    /// Serialize for publication.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Parse and validate a baseline document.
    pub fn parse(text: &str) -> Result<Self, BaselineError> {
        #[derive(Deserialize)]
        struct BaselineHeader {
            schema: u32,
            receipt_type: String,
        }

        let header: BaselineHeader =
            serde_json::from_str(text).map_err(|_| BaselineError::MalformedDocument)?;
        if header.receipt_type != BROWSER_BASELINE_TYPE {
            return Err(BaselineError::WrongType);
        }
        if header.schema == 1 && BROWSER_AUDIT_SCHEMA == 2 {
            #[derive(Deserialize)]
            struct LegacyBaselineV1 {
                schema: u32,
                receipt_type: String,
                receipt_id: String,
                created_at: String,
                tirith_version: String,
                format_version: u32,
                platform: Option<HostPlatform>,
                coverage: AuditCoverage,
                entries: Vec<serde_json::Value>,
                inventory_hash: String,
                signature: Option<String>,
            }

            let legacy: LegacyBaselineV1 =
                serde_json::from_str(text).map_err(|_| BaselineError::MalformedDocument)?;
            let LegacyBaselineV1 {
                schema,
                receipt_type,
                receipt_id,
                created_at,
                tirith_version,
                format_version,
                platform,
                coverage,
                entries,
                inventory_hash,
                signature,
            } = legacy;
            let _ = (
                schema,
                receipt_type,
                created_at,
                tirith_version,
                platform,
                coverage,
                signature,
            );
            let entry_value = serde_json::Value::Array(entries);
            let expected_inventory = crate::command_card::sha256_hex(
                crate::mcp_lock::canonical_json(&entry_value).as_bytes(),
            );
            if inventory_hash != expected_inventory {
                return Err(BaselineError::InventoryHashMismatch);
            }
            let mut value: serde_json::Value =
                serde_json::from_str(text).map_err(|_| BaselineError::MalformedDocument)?;
            let Some(object) = value.as_object_mut() else {
                return Err(BaselineError::MalformedDocument);
            };
            object.insert(
                "receipt_id".to_string(),
                serde_json::Value::String(String::new()),
            );
            object.insert("signature".to_string(), serde_json::Value::Null);
            let expected_receipt = crate::command_card::sha256_hex(
                crate::audit::canonical_json_for_hash(&value).as_bytes(),
            );
            if receipt_id != expected_receipt {
                return Err(BaselineError::ContentHashMismatch);
            }
            // An old baseline cannot deserialize into schema-v2 entries and it
            // must never become a comparison anchor. Return a bounded marker
            // carrying only version facts; callers report one upgrade and may
            // atomically replace the original after producing a fresh report.
            return Ok(Self {
                schema: header.schema,
                receipt_type: BROWSER_BASELINE_TYPE.to_string(),
                receipt_id: String::new(),
                created_at: String::new(),
                tirith_version: String::new(),
                format_version,
                platform: None,
                coverage: AuditCoverage::Partial,
                entries: Vec::new(),
                inventory_hash: String::new(),
                signature: None,
            });
        }
        if header.schema != BROWSER_AUDIT_SCHEMA {
            return Err(BaselineError::UnsupportedSchema(header.schema));
        }
        let baseline: Self =
            serde_json::from_str(text).map_err(|_| BaselineError::MalformedDocument)?;
        baseline.validate()?;
        Ok(baseline)
    }
}

/// sha256 over the canonical JSON of the baseline entries alone.
fn inventory_hash(entries: &[BaselineEntry]) -> String {
    let value = serde_json::to_value(entries).unwrap_or(serde_json::Value::Null);
    crate::command_card::sha256_hex(crate::mcp_lock::canonical_json(&value).as_bytes())
}

/// Why a baseline could not be loaded or trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineError {
    MalformedDocument,
    UnsupportedSchema(u32),
    WrongType,
    IdentityMismatch,
    DuplicateIdentity,
    ContentHashMismatch,
    InventoryHashMismatch,
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedDocument => write!(f, "the baseline is not a valid baseline document"),
            Self::UnsupportedSchema(schema) => {
                write!(f, "unsupported baseline schema {schema}")
            }
            Self::WrongType => write!(f, "the document is not a browser extension baseline"),
            Self::IdentityMismatch => write!(
                f,
                "a baseline entry's structured identity disagrees with its compatibility fields"
            ),
            Self::DuplicateIdentity => {
                write!(f, "the baseline contains a duplicate extension identity")
            }
            Self::ContentHashMismatch => write!(
                f,
                "receipt_id does not match the canonical baseline content"
            ),
            Self::InventoryHashMismatch => {
                write!(f, "inventory_hash does not match the recorded entries")
            }
        }
    }
}

impl std::error::Error for BaselineError {}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

/// Which extension a drift entry is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DriftSubject {
    pub identity: BrowserExtensionIdentity,
    pub browser: BrowserFamily,
    pub profile_directory: String,
    pub extension_id: String,
}

/// One named execution-surface field that changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceChange {
    Background,
    ContentScripts,
    ContentScriptMatches,
    NativeMessaging,
    ExternallyConnectable,
    WebAccessibleResources,
    DeclarativeNetRequest,
    DevtoolsPage,
    ChromeUrlOverrides,
    SandboxPages,
    ContentSecurityPolicy,
}

impl SurfaceChange {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::ContentScripts => "content_scripts",
            Self::ContentScriptMatches => "content_script_matches",
            Self::NativeMessaging => "native_messaging",
            Self::ExternallyConnectable => "externally_connectable",
            Self::WebAccessibleResources => "web_accessible_resources",
            Self::DeclarativeNetRequest => "declarative_net_request",
            Self::DevtoolsPage => "devtools_page",
            Self::ChromeUrlOverrides => "chrome_url_overrides",
            Self::SandboxPages => "sandbox_pages",
            Self::ContentSecurityPolicy => "content_security_policy",
        }
    }
}

/// One difference between the current audit and the baseline.
///
/// Every variant is INTEGRITY, never risk: an extension that already held
/// `<all_urls>` when the baseline was taken produces no drift now, however broad
/// its authority is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExtensionDrift {
    /// The baseline was written under different hashing rules. Emitted once, in
    /// place of phantom drift on every extension.
    SchemaUpgradeRequired {
        from_schema: u32,
        to_schema: u32,
        from_version: u32,
        to_version: u32,
    },
    /// An extension present now that the baseline did not record.
    New {
        subject: DriftSubject,
        version: String,
    },
    /// An extension the baseline recorded that is no longer present.
    Removed {
        subject: DriftSubject,
        version: String,
    },
    /// The declared version changed.
    VersionChanged {
        subject: DriftSubject,
        from: String,
        to: String,
    },
    /// The declared version changed while the version DIRECTORY did not, and the
    /// tree bytes changed with it.
    ///
    /// Chrome unpacks an update into a new `<version>_<ordinal>` directory, so a
    /// version string that moves inside a fixed directory is a state a real
    /// update cannot produce: the bytes were rewritten in place and the manifest
    /// was relabelled to make it look routine. Reported separately from
    /// [`ExtensionDrift::VersionChanged`] because the version bump is exactly
    /// what an operator would otherwise dismiss.
    VersionDirectoryReused {
        subject: DriftSubject,
        version_directory: String,
        from: String,
        to: String,
        from_digest: String,
        to_digest: String,
    },
    /// The SET of version directories present under this extension changed.
    ///
    /// Only the selected directory is hashed, so a second complete tree dropped
    /// beside it (which `extensions.settings.<id>.path` in `Preferences` can
    /// point the browser at) changes no digest. The set is the fact that says it
    /// is there. More than one directory is ordinary DURING a browser update;
    /// the change of the set is what is reported, never its size.
    VersionDirectorySetChange {
        subject: DriftSubject,
        added: Vec<String>,
        removed: Vec<String>,
    },
    /// `manifest_version` changed, an MV2/MV3 move.
    ManifestVersionChanged {
        subject: DriftSubject,
        from: u64,
        to: u64,
    },
    /// The version is unchanged but the tree digest is not. The strongest
    /// tamper signal this audit produces, and it is driven by the sorted-tree
    /// digest rather than by any version string.
    SameVersionByteChange {
        subject: DriftSubject,
        version: String,
        from_digest: String,
        to_digest: String,
    },
    /// The version is unchanged but at least one side's tree digest covers less
    /// than the whole tree, so no integrity statement can be made either way.
    ///
    /// This exists so a partial walk can neither raise a false tamper alarm nor
    /// be read as a clean result. An attacker who plants one unreadable entry to
    /// suppress a byte comparison lands here rather than in silence, and the
    /// rejection that made the tree incomplete is reported alongside it.
    IntegrityNotComparable {
        subject: DriftSubject,
        version: String,
        /// Whether the BASELINE's digest covered the whole tree.
        baseline_complete: bool,
        /// Whether THIS run's digest covered the whole tree.
        current_complete: bool,
    },
    /// API permissions were added.
    PermissionExpansion {
        subject: DriftSubject,
        added: Vec<String>,
    },
    /// API permissions were removed.
    PermissionReduction {
        subject: DriftSubject,
        removed: Vec<String>,
    },
    /// Host match patterns were added.
    HostExpansion {
        subject: DriftSubject,
        added: Vec<String>,
    },
    /// Host match patterns were removed.
    HostReduction {
        subject: DriftSubject,
        removed: Vec<String>,
    },
    /// OPTIONAL API permissions were added. Grantable at runtime through
    /// `chrome.permissions.request`, and auto-grantable for a policy install, so
    /// an added optional `debugger` is a real authority expansion even though
    /// nothing is granted yet.
    OptionalPermissionExpansion {
        subject: DriftSubject,
        added: Vec<String>,
    },
    /// Optional API permissions were removed.
    OptionalPermissionReduction {
        subject: DriftSubject,
        removed: Vec<String>,
    },
    /// Optional host match patterns were added.
    OptionalHostExpansion {
        subject: DriftSubject,
        added: Vec<String>,
    },
    /// Optional host match patterns were removed.
    OptionalHostReduction {
        subject: DriftSubject,
        removed: Vec<String>,
    },
    /// The declared-surface digest moved without any field-level difference
    /// above accounting for it.
    ///
    /// [`ExtensionRecord::surface_hash`] covers every declared-surface field, so
    /// this can only fire if a field entered the hash without entering
    /// [`compare_entry`]. It exists so that omission is a reported drift rather
    /// than a silent hole, which is precisely how the optional permission lists
    /// went unnoticed.
    SurfaceHashChanged {
        subject: DriftSubject,
        from: String,
        to: String,
    },
    /// One or more execution surfaces changed shape.
    ExecutionSurfaceChange {
        subject: DriftSubject,
        changes: Vec<SurfaceChange>,
    },
    /// The provenance class changed.
    ProvenanceChange {
        subject: DriftSubject,
        from: ProvenanceClass,
        to: ProvenanceClass,
    },
    /// The install class changed. A store install that becomes a developer
    /// unpacked load is a real event, not a relabelling.
    InstallClassChange {
        subject: DriftSubject,
        from: InstallClass,
        to: InstallClass,
    },
}

impl ExtensionDrift {
    fn bucket(&self) -> u8 {
        match self {
            Self::SchemaUpgradeRequired { .. } => 0,
            Self::Removed { .. } => 1,
            Self::New { .. } => 2,
            Self::VersionDirectoryReused { .. } => 3,
            Self::SameVersionByteChange { .. } => 4,
            Self::IntegrityNotComparable { .. } => 5,
            Self::VersionDirectorySetChange { .. } => 6,
            Self::VersionChanged { .. } => 7,
            Self::ManifestVersionChanged { .. } => 8,
            Self::InstallClassChange { .. } => 9,
            Self::ProvenanceChange { .. } => 10,
            Self::HostExpansion { .. } => 11,
            Self::PermissionExpansion { .. } => 12,
            Self::OptionalHostExpansion { .. } => 13,
            Self::OptionalPermissionExpansion { .. } => 14,
            Self::ExecutionSurfaceChange { .. } => 15,
            Self::SurfaceHashChanged { .. } => 16,
            Self::HostReduction { .. } => 17,
            Self::PermissionReduction { .. } => 18,
            Self::OptionalHostReduction { .. } => 19,
            Self::OptionalPermissionReduction { .. } => 20,
        }
    }

    /// The extension this drift refers to, or `None` for the document-wide
    /// [`ExtensionDrift::SchemaUpgradeRequired`].
    pub fn subject(&self) -> Option<&DriftSubject> {
        match self {
            Self::SchemaUpgradeRequired { .. } => None,
            Self::New { subject, .. }
            | Self::Removed { subject, .. }
            | Self::VersionChanged { subject, .. }
            | Self::VersionDirectoryReused { subject, .. }
            | Self::VersionDirectorySetChange { subject, .. }
            | Self::ManifestVersionChanged { subject, .. }
            | Self::SameVersionByteChange { subject, .. }
            | Self::IntegrityNotComparable { subject, .. }
            | Self::PermissionExpansion { subject, .. }
            | Self::PermissionReduction { subject, .. }
            | Self::HostExpansion { subject, .. }
            | Self::HostReduction { subject, .. }
            | Self::OptionalPermissionExpansion { subject, .. }
            | Self::OptionalPermissionReduction { subject, .. }
            | Self::OptionalHostExpansion { subject, .. }
            | Self::OptionalHostReduction { subject, .. }
            | Self::SurfaceHashChanged { subject, .. }
            | Self::ExecutionSurfaceChange { subject, .. }
            | Self::ProvenanceChange { subject, .. }
            | Self::InstallClassChange { subject, .. } => Some(subject),
        }
    }

    fn sort_key(&self) -> (u8, Option<DriftSubject>) {
        (self.bucket(), self.subject().cloned())
    }

    /// Stable wire token for the variant.
    pub fn token(&self) -> &'static str {
        match self {
            Self::SchemaUpgradeRequired { .. } => "schema_upgrade_required",
            Self::New { .. } => "new",
            Self::Removed { .. } => "removed",
            Self::VersionChanged { .. } => "version_changed",
            Self::VersionDirectoryReused { .. } => "version_directory_reused",
            Self::VersionDirectorySetChange { .. } => "version_directory_set_change",
            Self::ManifestVersionChanged { .. } => "manifest_version_changed",
            Self::SameVersionByteChange { .. } => "same_version_byte_change",
            Self::IntegrityNotComparable { .. } => "integrity_not_comparable",
            Self::PermissionExpansion { .. } => "permission_expansion",
            Self::PermissionReduction { .. } => "permission_reduction",
            Self::HostExpansion { .. } => "host_expansion",
            Self::HostReduction { .. } => "host_reduction",
            Self::OptionalPermissionExpansion { .. } => "optional_permission_expansion",
            Self::OptionalPermissionReduction { .. } => "optional_permission_reduction",
            Self::OptionalHostExpansion { .. } => "optional_host_expansion",
            Self::OptionalHostReduction { .. } => "optional_host_reduction",
            Self::SurfaceHashChanged { .. } => "surface_hash_changed",
            Self::ExecutionSurfaceChange { .. } => "execution_surface_change",
            Self::ProvenanceChange { .. } => "provenance_change",
            Self::InstallClassChange { .. } => "install_class_change",
        }
    }
}

/// Compare a current audit against a baseline.
///
/// Fast path: an identical `inventory_hash` means nothing changed, so no
/// per-extension work is done. Otherwise the two `(browser, profile, id)`-sorted
/// sides are merge-walked and each difference is emitted as its OWN variant, so
/// a host expansion and a byte change are never collapsed into one "changed"
/// entry an operator has to unpick.
pub fn compute_drift(
    report: &BrowserAuditReport,
    baseline: &BrowserBaseline,
) -> Vec<ExtensionDrift> {
    if baseline.schema != BROWSER_AUDIT_SCHEMA
        || baseline.format_version != BROWSER_BASELINE_FORMAT_VERSION
    {
        return vec![ExtensionDrift::SchemaUpgradeRequired {
            from_schema: baseline.schema,
            to_schema: BROWSER_AUDIT_SCHEMA,
            from_version: baseline.format_version,
            to_version: BROWSER_BASELINE_FORMAT_VERSION,
        }];
    }

    let current = report.entries();
    if inventory_hash(&current) == baseline.inventory_hash {
        return Vec::new();
    }

    let mut recorded: BTreeMap<BrowserExtensionIdentity, &BaselineEntry> = BTreeMap::new();
    for entry in &baseline.entries {
        recorded.insert(entry.sort_key(), entry);
    }
    let mut observed: BTreeMap<BrowserExtensionIdentity, &BaselineEntry> = BTreeMap::new();
    for entry in &current {
        observed.insert(entry.sort_key(), entry);
    }

    let mut drifts = Vec::new();
    for (key, before) in &recorded {
        if !observed.contains_key(key) {
            drifts.push(ExtensionDrift::Removed {
                subject: before.subject(),
                version: before.version.clone(),
            });
        }
    }
    for (key, after) in &observed {
        let Some(before) = recorded.get(key) else {
            drifts.push(ExtensionDrift::New {
                subject: after.subject(),
                version: after.version.clone(),
            });
            continue;
        };
        drifts.extend(compare_entry(before, after));
    }

    drifts.sort_by_key(|drift| drift.sort_key());
    drifts
}

fn compare_entry(before: &BaselineEntry, after: &BaselineEntry) -> Vec<ExtensionDrift> {
    let subject = after.subject();
    let mut drifts = Vec::new();

    if before.version != after.version {
        drifts.push(ExtensionDrift::VersionChanged {
            subject: subject.clone(),
            from: before.version.clone(),
            to: after.version.clone(),
        });
        // The digest comparison below is deliberately skipped once the version
        // moved, so this is the one place the byte change still has to be
        // reported: a version bump inside an unchanged version directory is an
        // in-place rewrite wearing an update's clothes.
        if before.comparable()
            && after.comparable()
            && before.version_directory == after.version_directory
            && !before.version_directory.is_empty()
            && before.tree_digest != after.tree_digest
        {
            drifts.push(ExtensionDrift::VersionDirectoryReused {
                subject: subject.clone(),
                version_directory: after.version_directory.clone(),
                from: before.version.clone(),
                to: after.version.clone(),
                from_digest: before.tree_digest.clone(),
                to_digest: after.tree_digest.clone(),
            });
        }
    } else if !before.comparable() || !after.comparable() {
        // An incomplete digest covers less than the whole tree, so it can
        // neither prove nor disprove a byte change. Reporting a difference as
        // tamper would fire every time a browser held a file lock, and reporting
        // a match as clean would be a false negative an attacker could
        // manufacture by planting one unreadable entry. Say what is true
        // instead: this extension could not be compared.
        drifts.push(ExtensionDrift::IntegrityNotComparable {
            subject: subject.clone(),
            version: after.version.clone(),
            baseline_complete: before.comparable(),
            current_complete: after.comparable(),
        });
    } else if before.tree_digest != after.tree_digest {
        // Same declared version, different bytes. Deliberately an `else`: when
        // the version moved, a different digest is the expected consequence and
        // reporting both would bury the one signal that matters.
        drifts.push(ExtensionDrift::SameVersionByteChange {
            subject: subject.clone(),
            version: after.version.clone(),
            from_digest: before.tree_digest.clone(),
            to_digest: after.tree_digest.clone(),
        });
    }

    let added = difference(&after.permissions, &before.permissions);
    if !added.is_empty() {
        drifts.push(ExtensionDrift::PermissionExpansion {
            subject: subject.clone(),
            added,
        });
    }
    let removed = difference(&before.permissions, &after.permissions);
    if !removed.is_empty() {
        drifts.push(ExtensionDrift::PermissionReduction {
            subject: subject.clone(),
            removed,
        });
    }

    let host_added = difference(&after.host_permissions, &before.host_permissions);
    if !host_added.is_empty() {
        drifts.push(ExtensionDrift::HostExpansion {
            subject: subject.clone(),
            added: host_added,
        });
    }
    let host_removed = difference(&before.host_permissions, &after.host_permissions);
    if !host_removed.is_empty() {
        drifts.push(ExtensionDrift::HostReduction {
            subject: subject.clone(),
            removed: host_removed,
        });
    }

    let optional_added = difference(&after.optional_permissions, &before.optional_permissions);
    if !optional_added.is_empty() {
        drifts.push(ExtensionDrift::OptionalPermissionExpansion {
            subject: subject.clone(),
            added: optional_added,
        });
    }
    let optional_removed = difference(&before.optional_permissions, &after.optional_permissions);
    if !optional_removed.is_empty() {
        drifts.push(ExtensionDrift::OptionalPermissionReduction {
            subject: subject.clone(),
            removed: optional_removed,
        });
    }
    let optional_host_added = difference(
        &after.optional_host_permissions,
        &before.optional_host_permissions,
    );
    if !optional_host_added.is_empty() {
        drifts.push(ExtensionDrift::OptionalHostExpansion {
            subject: subject.clone(),
            added: optional_host_added,
        });
    }
    let optional_host_removed = difference(
        &before.optional_host_permissions,
        &after.optional_host_permissions,
    );
    if !optional_host_removed.is_empty() {
        drifts.push(ExtensionDrift::OptionalHostReduction {
            subject: subject.clone(),
            removed: optional_host_removed,
        });
    }

    if before.manifest_version != after.manifest_version {
        drifts.push(ExtensionDrift::ManifestVersionChanged {
            subject: subject.clone(),
            from: before.manifest_version,
            to: after.manifest_version,
        });
    }

    let directories_added = difference(&after.version_directories, &before.version_directories);
    let directories_removed = difference(&before.version_directories, &after.version_directories);
    if !directories_added.is_empty() || !directories_removed.is_empty() {
        drifts.push(ExtensionDrift::VersionDirectorySetChange {
            subject: subject.clone(),
            added: directories_added,
            removed: directories_removed,
        });
    }

    let changes = surface_changes(&before.surfaces, &after.surfaces);
    if !changes.is_empty() {
        drifts.push(ExtensionDrift::ExecutionSurfaceChange {
            subject: subject.clone(),
            changes,
        });
    }

    if before.provenance != after.provenance {
        drifts.push(ExtensionDrift::ProvenanceChange {
            subject: subject.clone(),
            from: before.provenance,
            to: after.provenance,
        });
    }
    if before.install_class != after.install_class {
        drifts.push(ExtensionDrift::InstallClassChange {
            subject: subject.clone(),
            from: before.install_class,
            to: after.install_class,
        });
    }

    // The surface digest covers every declared-surface field, so a difference
    // here with nothing above it accounting for the difference means a field
    // entered the hash without entering this comparison. Report the residue
    // rather than let it be the silence it was.
    if before.surface_hash != after.surface_hash && drifts.is_empty() {
        drifts.push(ExtensionDrift::SurfaceHashChanged {
            subject,
            from: before.surface_hash.clone(),
            to: after.surface_hash.clone(),
        });
    }

    drifts
}

fn difference(left: &[String], right: &[String]) -> Vec<String> {
    let right: BTreeSet<&String> = right.iter().collect();
    left.iter()
        .filter(|value| !right.contains(value))
        .cloned()
        .collect()
}

/// Each execution surface compared on its own, so an operator sees WHICH surface
/// moved rather than a single boolean.
fn surface_changes(before: &ExecutionSurfaces, after: &ExecutionSurfaces) -> Vec<SurfaceChange> {
    let mut changes = Vec::new();
    if before.background != after.background {
        changes.push(SurfaceChange::Background);
    }
    if before.content_script_count != after.content_script_count {
        changes.push(SurfaceChange::ContentScripts);
    }
    if before.content_script_matches != after.content_script_matches {
        changes.push(SurfaceChange::ContentScriptMatches);
    }
    if before.native_messaging != after.native_messaging {
        changes.push(SurfaceChange::NativeMessaging);
    }
    if before.externally_connectable != after.externally_connectable
        || before.externally_connectable_matches != after.externally_connectable_matches
        || before.externally_connectable_ids != after.externally_connectable_ids
    {
        changes.push(SurfaceChange::ExternallyConnectable);
    }
    if before.web_accessible_resource_count != after.web_accessible_resource_count {
        changes.push(SurfaceChange::WebAccessibleResources);
    }
    if before.declarative_net_request_rulesets != after.declarative_net_request_rulesets {
        changes.push(SurfaceChange::DeclarativeNetRequest);
    }
    if before.devtools_page != after.devtools_page {
        changes.push(SurfaceChange::DevtoolsPage);
    }
    if before.chrome_url_overrides != after.chrome_url_overrides {
        changes.push(SurfaceChange::ChromeUrlOverrides);
    }
    if before.sandbox_page_count != after.sandbox_page_count {
        changes.push(SurfaceChange::SandboxPages);
    }
    if before.content_security_policy != after.content_security_policy {
        changes.push(SurfaceChange::ContentSecurityPolicy);
    }
    changes.sort();
    changes
}

#[cfg(test)]
mod tests;
