//! M12 ch3 — `tirith browser install-extension`: write the Chrome Native
//! Messaging Host manifest so the companion extension can launch
//! `tirith browser host`.
//!
//! Chrome discovers the host via a JSON manifest (`sh.tirith.browser.json`) in a
//! per-OS `NativeMessagingHosts` directory, naming the host, the absolute exe
//! path, the `stdio` transport, and the `allowed_origins`. Mirrors
//! `clipboard::install_service`: dry-run by default, `--apply` writes it
//! (idempotent).
//!
//! The extension ID is not known yet (separate, unpublished repo);
//! `--extension-id <id>` supplies it, else a clearly-marked placeholder + note.
//!
//! On Windows the host is registered via a registry key, not a file drop — we
//! print guidance rather than writing the registry.
//!
//! `--browser <chrome|chromium|brave|edge>` (default `chrome`) selects which
//! browser's `NativeMessagingHosts` directory the manifest targets.

use std::path::PathBuf;

use super::write_json_stdout;

/// A Chromium-family browser whose per-OS `NativeMessagingHosts` directory the
/// manifest can target. Selected by `--browser`; defaults to [`Browser::Chrome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Browser {
    /// Google Chrome (the default).
    #[default]
    Chrome,
    /// Chromium (the open-source base).
    Chromium,
    /// Brave.
    Brave,
    /// Microsoft Edge (Chromium-based).
    Edge,
}

impl std::str::FromStr for Browser {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chrome" | "google-chrome" => Ok(Browser::Chrome),
            "chromium" => Ok(Browser::Chromium),
            "brave" => Ok(Browser::Brave),
            "edge" | "microsoft-edge" | "msedge" => Ok(Browser::Edge),
            other => Err(format!(
                "unknown browser '{other}' (expected chrome, chromium, brave, or edge)"
            )),
        }
    }
}

impl Browser {
    /// Short tag for JSON envelopes / human messages.
    fn as_str(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Chromium => "chromium",
            Browser::Brave => "brave",
            Browser::Edge => "edge",
        }
    }

    /// The Windows registry root for this browser's native-messaging host keys
    /// (`HKCU\<root>\<HOST_NAME>`). Per-browser vendor sub-tree, so `--browser
    /// edge` doesn't point at the Chrome key.
    fn windows_registry_root(self) -> &'static str {
        match self {
            Browser::Chrome => "Software\\Google\\Chrome\\NativeMessagingHosts",
            Browser::Chromium => "Software\\Chromium\\NativeMessagingHosts",
            Browser::Brave => "Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts",
            Browser::Edge => "Software\\Microsoft\\Edge\\NativeMessagingHosts",
        }
    }
}

/// `true` when `id` is a well-formed Chrome extension ID: exactly 32 letters
/// `a`–`p`. A malformed id would render an `allowed_origins` Chrome can never
/// match, so we reject it. [`PLACEHOLDER_EXTENSION_ID`] deliberately fails this
/// (handled separately with a replace-me note).
pub fn is_valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// The native messaging host name — must match the extension's
/// `chrome.runtime.connectNative(...)` arg and the manifest `name`.
pub const HOST_NAME: &str = "sh.tirith.browser";

/// Placeholder extension ID used when `--extension-id` is omitted. Obviously not
/// a real ID (32 letters a–p), so a manifest written with it cannot silently
/// authorize a real extension.
pub const PLACEHOLDER_EXTENSION_ID: &str = "EXTENSION_ID_PLACEHOLDER_REPLACE_ME";

/// `tirith browser install-extension` entry point.
///
/// `extension_id` defaults to [`PLACEHOLDER_EXTENSION_ID`] (with a note) when
/// omitted; a non-placeholder id that isn't 32 letters `a`–`p` is rejected.
/// `apply` writes the manifest (else dry-run); `json` emits an envelope.
/// Returns 0 on success/dry-run; 1 on a write failure, malformed id,
/// unresolvable exe path, or unresolvable manifest path on non-Windows.
pub fn install_extension(
    extension_id: Option<String>,
    browser: Browser,
    apply: bool,
    json: bool,
) -> i32 {
    let platform = manifest_platform();

    // The manifest `path` MUST be absolute — Chrome/Chromium silently refuse a
    // relative one. Fail fast (in both dry-run and --apply) if our own exe path
    // can't be resolved; there is no PATH-relative fallback.
    let Some(exe) = current_tirith_exe() else {
        let msg = "cannot determine the absolute path of the tirith executable; aborting so we \
                   never write a relative native-messaging manifest path";
        if json {
            let env = serde_json::json!({
                "platform": platform,
                "browser": browser.as_str(),
                "host_name": HOST_NAME,
                "written": false,
                "error": msg,
            });
            let _ = write_json_stdout(
                &env,
                "tirith browser install-extension: failed to write JSON output",
            );
        } else {
            eprintln!("tirith browser install-extension: {msg}");
        }
        return 1;
    };

    // A blank/whitespace `--extension-id` is treated as "not provided".
    let (extension_id, is_placeholder) = match extension_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(id) => (id, false),
        None => (PLACEHOLDER_EXTENSION_ID.to_string(), true),
    };

    // N1+N2 — reject a malformed (non-placeholder) id before rendering a
    // manifest that could never authorize the extension. Placeholder is exempt.
    if !is_placeholder && !is_valid_extension_id(&extension_id) {
        let msg = format!(
            "invalid --extension-id '{extension_id}': a Chrome extension id is exactly 32 \
             letters in the range a–p"
        );
        if json {
            let env = serde_json::json!({
                "platform": platform,
                "browser": browser.as_str(),
                "host_name": HOST_NAME,
                "written": false,
                "error": msg,
            });
            // Parseable envelope even on the error path; the non-zero exit
            // signals failure.
            let _ = write_json_stdout(
                &env,
                "tirith browser install-extension: failed to write JSON output",
            );
        } else {
            eprintln!("tirith browser install-extension: {msg}");
        }
        return 1;
    }

    let manifest = render_manifest(&exe, &extension_id);
    let manifest_path = manifest_path(browser);

    let Some(path) = manifest_path else {
        // CR2 — Windows (registry-based) is an expected success; a None path on
        // macOS/Linux is a genuine HOME-resolve failure.
        if cfg!(target_os = "windows") {
            if json {
                let env = serde_json::json!({
                    "platform": platform,
                    "browser": browser.as_str(),
                    "host_name": HOST_NAME,
                    "manifest_path": serde_json::Value::Null,
                    "written": false,
                    "extension_id": extension_id,
                    "extension_id_is_placeholder": is_placeholder,
                    "manifest": manifest,
                    "note": windows_guidance(&exe, browser),
                });
                if !write_json_stdout(
                    &env,
                    "tirith browser install-extension: failed to write JSON output",
                ) {
                    return 1;
                }
            } else {
                eprintln!(
                    "tirith browser install-extension: {}",
                    windows_guidance(&exe, browser)
                );
                eprintln!("tirith browser install-extension: manifest body to register:");
                println!("{manifest}");
            }
            // Not an error — the operator has what they need to register it
            // manually. Exit 0 (dry-run sense).
            return 0;
        }

        // Non-Windows: a `None` path is a real failure. Distinguish an
        // unsupported target from an unresolvable HOME so the operator is
        // pointed at the right problem; exit non-zero either way.
        let msg = if platform == "unsupported" {
            "native messaging host installation is not supported on this platform"
        } else {
            "cannot resolve the manifest path: no home directory ($HOME) could be resolved"
        };
        if json {
            let env = serde_json::json!({
                "platform": platform,
                "browser": browser.as_str(),
                "host_name": HOST_NAME,
                "manifest_path": serde_json::Value::Null,
                "written": false,
                "error": msg,
            });
            let _ = write_json_stdout(
                &env,
                "tirith browser install-extension: failed to write JSON output",
            );
        } else {
            eprintln!("tirith browser install-extension: {msg}");
        }
        return 1;
    };

    // dry-run (default): print the manifest + target path.
    if !apply {
        if json {
            let env = serde_json::json!({
                "platform": platform,
                "browser": browser.as_str(),
                "host_name": HOST_NAME,
                "manifest_path": path.display().to_string(),
                "written": false,
                "extension_id": extension_id,
                "extension_id_is_placeholder": is_placeholder,
                "manifest": manifest,
            });
            if !write_json_stdout(
                &env,
                "tirith browser install-extension: failed to write JSON output",
            ) {
                return 1;
            }
        } else {
            eprintln!(
                "tirith browser install-extension: dry-run; would write the {} manifest to {}",
                browser.as_str(),
                path.display()
            );
            eprintln!("tirith browser install-extension: rerun with --apply to install.");
            if is_placeholder {
                eprintln!(
                    "tirith browser install-extension: NOTE — using a PLACEHOLDER extension id. \
                     Pass --extension-id <id> with the companion extension's real Chrome id \
                     (32 letters a–p) or the host will refuse the connection."
                );
            }
            // The manifest goes to stdout so it can be redirected.
            println!("{manifest}");
        }
        return 0;
    }

    // --apply: write the manifest (idempotent).
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            let msg = format!("failed to create {}: {e}", parent.display());
            return apply_failure(json, platform, browser, &path, &msg);
        }
    }

    // Idempotent: skip the write when on-disk content already matches.
    let needs_write =
        !matches!(std::fs::read_to_string(&path), Ok(existing) if existing == manifest);
    if needs_write {
        if let Err(e) =
            super::write_file_atomic(&path, manifest.as_bytes(), /*overwrite=*/ true)
        {
            let msg = format!("failed to write {}: {e}", path.display());
            return apply_failure(json, platform, browser, &path, &msg);
        }
    }

    if json {
        let env = serde_json::json!({
            "platform": platform,
            "browser": browser.as_str(),
            "host_name": HOST_NAME,
            "manifest_path": path.display().to_string(),
            "written": needs_write,
            "extension_id": extension_id,
            "extension_id_is_placeholder": is_placeholder,
        });
        if !write_json_stdout(
            &env,
            "tirith browser install-extension: failed to write JSON output",
        ) {
            return 1;
        }
    } else {
        if needs_write {
            eprintln!(
                "tirith browser install-extension: wrote the {} manifest to {}",
                browser.as_str(),
                path.display()
            );
        } else {
            eprintln!(
                "tirith browser install-extension: {} already up to date",
                path.display()
            );
        }
        if is_placeholder {
            eprintln!(
                "tirith browser install-extension: NOTE — wrote a PLACEHOLDER extension id. \
                 Re-run with --extension-id <id> once the companion extension is published."
            );
        }
    }
    0
}

/// Emit an `--apply` write failure (with the known `manifest_path`) and return
/// the non-zero exit code, keeping `--json --apply` machine-readable on
/// `create_dir_all` / `write_file_atomic` errors.
fn apply_failure(
    json: bool,
    platform: &str,
    browser: Browser,
    path: &std::path::Path,
    msg: &str,
) -> i32 {
    if json {
        let env = serde_json::json!({
            "platform": platform,
            "browser": browser.as_str(),
            "host_name": HOST_NAME,
            "manifest_path": path.display().to_string(),
            "written": false,
            "error": msg,
        });
        let _ = write_json_stdout(
            &env,
            "tirith browser install-extension: failed to write JSON output",
        );
    } else {
        eprintln!("tirith browser install-extension: {msg}");
    }
    1
}

/// Build the native messaging host manifest JSON. Pretty-printed and stable so
/// the idempotency content comparison is reliable.
pub fn render_manifest(exe: &str, extension_id: &str) -> String {
    let manifest = serde_json::json!({
        "name": HOST_NAME,
        "description": "tirith browser native-messaging host (paste provenance, M12)",
        "path": exe,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    });
    serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".to_string())
}

/// Short OS-only platform tag for JSON envelopes / human messages (the browser
/// is reported separately). `windows-registry` describes the install mechanism.
fn manifest_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-registry"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "unsupported"
    }
}

/// The per-OS, per-browser NativeMessagingHosts manifest path. `None` on Windows
/// (registry-based), unsupported platforms, or when `$HOME` cannot be resolved.
/// Each Chromium-family browser keeps its own directory (G2):
///
/// | Browser  | macOS (`~/Library/Application Support/...`)   | Linux (`~/.config/...`)                  |
/// | -------- | --------------------------------------------- | ---------------------------------------- |
/// | Chrome   | `Google/Chrome`                               | `google-chrome`                          |
/// | Chromium | `Chromium`                                    | `chromium`                               |
/// | Brave    | `BraveSoftware/Brave-Browser`                 | `BraveSoftware/Brave-Browser`            |
/// | Edge     | `Microsoft Edge`                              | `microsoft-edge`                         |
fn manifest_path(browser: Browser) -> Option<PathBuf> {
    let home = home::home_dir()?;
    let file = format!("{HOST_NAME}.json");
    #[cfg(target_os = "macos")]
    {
        let vendor = match browser {
            Browser::Chrome => "Google/Chrome",
            Browser::Chromium => "Chromium",
            Browser::Brave => "BraveSoftware/Brave-Browser",
            Browser::Edge => "Microsoft Edge",
        };
        Some(
            home.join("Library/Application Support")
                .join(vendor)
                .join("NativeMessagingHosts")
                .join(file),
        )
    }
    #[cfg(target_os = "linux")]
    {
        let vendor = match browser {
            Browser::Chrome => "google-chrome",
            Browser::Chromium => "chromium",
            Browser::Brave => "BraveSoftware/Brave-Browser",
            Browser::Edge => "microsoft-edge",
        };
        Some(
            home.join(".config")
                .join(vendor)
                .join("NativeMessagingHosts")
                .join(file),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (home, file, browser);
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (home, file, browser);
        None
    }
}

/// Windows guidance text — register the host via a per-browser registry key
/// (G2/N4) rather than a directory drop.
fn windows_guidance(exe: &str, browser: Browser) -> String {
    let root = browser.windows_registry_root();
    format!(
        "on Windows, register the native messaging host via the registry rather than a file drop. \
         Save the manifest body below to a file (e.g. %LOCALAPPDATA%\\tirith\\{HOST_NAME}.json), \
         then create the key \
         HKCU\\{root}\\{HOST_NAME} with its default value \
         set to that file's path. The host executable is: {exe}"
    )
}

/// Resolve the ABSOLUTE path to the current `tirith` binary for the manifest
/// `path` (the exe Chrome spawns). `None` when no absolute path is determinable.
/// No PATH-relative fallback: Chrome/Chromium require an absolute `path`, so a
/// relative one would silently fail to launch; the caller fails fast on `None`.
fn current_tirith_exe() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered manifest carries host name, exe path, stdio transport, and
    /// the extension id as a `chrome-extension://` origin.
    #[test]
    fn manifest_contains_required_fields() {
        let m = render_manifest("/usr/local/bin/tirith", "abcdefghijklmnopabcdefghijklmnop");
        let parsed: serde_json::Value = serde_json::from_str(&m).expect("manifest is valid JSON");
        assert_eq!(parsed["name"], HOST_NAME);
        assert_eq!(parsed["path"], "/usr/local/bin/tirith");
        assert_eq!(parsed["type"], "stdio");
        let origins = parsed["allowed_origins"].as_array().expect("origins array");
        assert_eq!(origins.len(), 1);
        assert_eq!(
            origins[0],
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/"
        );
        assert!(
            parsed["description"].as_str().unwrap().contains("tirith"),
            "description should mention tirith"
        );
    }

    /// `current_tirith_exe()` resolves to an absolute path in a normal run (the
    /// property the manifest depends on). The `None` branch can't be forced
    /// in-process, so we assert the happy path.
    #[test]
    fn current_tirith_exe_is_some_and_absolute() {
        let s = current_tirith_exe()
            .expect("current_exe()/canonicalize() should resolve in a normal test run");
        assert!(
            std::path::Path::new(&s).is_absolute(),
            "manifest `path` must be absolute; got {s}"
        );
    }

    /// The exe path is embedded verbatim, so one with spaces survives the JSON
    /// round-trip.
    #[test]
    fn manifest_preserves_exe_path_with_spaces() {
        let m = render_manifest(
            "/Applications/My Tools/tirith",
            "abcdefghijklmnopabcdefghijklmnop",
        );
        let parsed: serde_json::Value = serde_json::from_str(&m).unwrap();
        assert_eq!(parsed["path"], "/Applications/My Tools/tirith");
    }

    /// The placeholder id flows into the origin so a dry-run shows the
    /// (obviously-fake) origin to replace.
    #[test]
    fn placeholder_id_appears_in_origin() {
        let m = render_manifest("/bin/tirith", PLACEHOLDER_EXTENSION_ID);
        assert!(
            m.contains(&format!("chrome-extension://{PLACEHOLDER_EXTENSION_ID}/")),
            "placeholder id must appear in the origin; got: {m}"
        );
    }

    /// Windows guidance names the (Chrome) registry key and the host exe.
    #[test]
    fn windows_guidance_mentions_registry_and_exe() {
        let g = windows_guidance("C:\\tools\\tirith.exe", Browser::Chrome);
        assert!(g.contains("HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts"));
        assert!(g.contains(HOST_NAME));
        assert!(g.contains("C:\\tools\\tirith.exe"));
    }

    /// N4 — `--browser` is honored in the Windows guidance: each browser's
    /// guidance names its own registry root, not Chrome's.
    #[test]
    fn windows_guidance_honors_browser_registry_root() {
        let edge = windows_guidance("C:\\tools\\tirith.exe", Browser::Edge);
        assert!(
            edge.contains("HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts"),
            "Edge guidance must name the Edge registry root; got: {edge}"
        );
        assert!(
            !edge.contains("Google\\Chrome"),
            "Edge guidance must NOT point at the Chrome root; got: {edge}"
        );

        let brave = windows_guidance("C:\\tools\\tirith.exe", Browser::Brave);
        assert!(
            brave.contains("HKCU\\Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts"),
            "Brave guidance must name the Brave registry root; got: {brave}"
        );

        let chromium = windows_guidance("C:\\tools\\tirith.exe", Browser::Chromium);
        assert!(
            chromium.contains("HKCU\\Software\\Chromium\\NativeMessagingHosts"),
            "Chromium guidance must name the Chromium registry root; got: {chromium}"
        );
    }

    /// On file-drop platforms the manifest path ends in the host filename inside
    /// a `NativeMessagingHosts` directory.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn manifest_path_targets_native_messaging_hosts_dir() {
        // Skip rather than fail if HOME is unset (CI sandboxes occasionally do).
        let Some(p) = manifest_path(Browser::Chrome) else {
            eprintln!("skipping: no home dir resolved in this environment");
            return;
        };
        let s = p.display().to_string();
        assert!(
            s.ends_with(&format!("NativeMessagingHosts/{HOST_NAME}.json")),
            "got {s}"
        );
    }

    /// G2 — each Chromium-family browser targets a distinct, vendor-specific
    /// directory (all ending in the host filename with the expected vendor
    /// segment).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn manifest_path_is_per_browser() {
        let cases = [
            (
                Browser::Chrome,
                if cfg!(target_os = "macos") {
                    "Google/Chrome"
                } else {
                    "google-chrome"
                },
            ),
            (
                Browser::Chromium,
                if cfg!(target_os = "macos") {
                    "Chromium"
                } else {
                    "chromium"
                },
            ),
            (Browser::Brave, "Brave-Browser"),
            (
                Browser::Edge,
                if cfg!(target_os = "macos") {
                    "Microsoft Edge"
                } else {
                    "microsoft-edge"
                },
            ),
        ];
        let mut seen: Vec<String> = Vec::new();
        for (browser, segment) in cases {
            let Some(p) = manifest_path(browser) else {
                eprintln!("skipping: no home dir resolved in this environment");
                return;
            };
            let s = p.display().to_string();
            assert!(
                s.ends_with(&format!("NativeMessagingHosts/{HOST_NAME}.json")),
                "{} path must end in the host filename; got {s}",
                browser.as_str()
            );
            assert!(
                s.contains(segment),
                "{} path must contain the vendor segment '{segment}'; got {s}",
                browser.as_str()
            );
            seen.push(s);
        }
        // The four paths are mutually distinct.
        let before = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(before, seen.len(), "per-browser paths must be distinct");
    }

    /// N1+N2 — the validator accepts exactly 32 letters a–p, rejects everything
    /// else.
    #[test]
    fn extension_id_validator_accepts_only_32_letters_a_to_p() {
        assert!(is_valid_extension_id("abcdefghijklmnopabcdefghijklmnop"));
        assert!(is_valid_extension_id(&"a".repeat(32)));
        assert!(is_valid_extension_id(&"p".repeat(32)));
        // Wrong length, out-of-range letters, digits, uppercase, placeholder.
        assert!(!is_valid_extension_id("abcdefghijklmnop"));
        assert!(!is_valid_extension_id(&"a".repeat(33)));
        assert!(!is_valid_extension_id(&"q".repeat(32)));
        assert!(!is_valid_extension_id(&"z".repeat(32)));
        assert!(!is_valid_extension_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_extension_id("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"));
        assert!(!is_valid_extension_id(PLACEHOLDER_EXTENSION_ID));
    }

    /// The platform tag is OS-only, no browser suffix (regression: a `--browser
    /// brave` run no longer reports `macos-chrome`).
    #[test]
    fn manifest_platform_is_os_only_no_browser_suffix() {
        let p = manifest_platform();
        assert!(
            !p.contains("chrome"),
            "platform tag must not hardcode a browser; got '{p}'"
        );
        #[cfg(target_os = "macos")]
        assert_eq!(p, "macos");
        #[cfg(target_os = "linux")]
        assert_eq!(p, "linux");
        #[cfg(target_os = "windows")]
        assert_eq!(p, "windows-registry");
    }

    /// `--browser` parses the four values (case-insensitively), rejects unknown.
    #[test]
    fn browser_parses_known_values() {
        use std::str::FromStr;
        assert_eq!(Browser::from_str("chrome").unwrap(), Browser::Chrome);
        assert_eq!(Browser::from_str("Chromium").unwrap(), Browser::Chromium);
        assert_eq!(Browser::from_str("BRAVE").unwrap(), Browser::Brave);
        assert_eq!(Browser::from_str("edge").unwrap(), Browser::Edge);
        assert_eq!(Browser::from_str("msedge").unwrap(), Browser::Edge);
        assert!(Browser::from_str("safari").is_err());
        // The default is Chrome.
        assert_eq!(Browser::default(), Browser::Chrome);
    }
}
