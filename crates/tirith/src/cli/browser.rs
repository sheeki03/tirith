//! M12 ch3 — `tirith browser install-extension`: write the Chrome **Native
//! Messaging Host manifest** so the companion browser extension can launch
//! `tirith browser host`.
//!
//! Chrome discovers a native messaging host by a JSON manifest named after the
//! host (`sh.tirith.browser.json`) placed in a per-OS `NativeMessagingHosts`
//! directory. The manifest names the host, the absolute path to the executable
//! Chrome should spawn, the `stdio` transport, and the `allowed_origins` —
//! exactly which extension IDs may connect.
//!
//! This mirrors `clipboard::install_service`: a DRY-RUN by default (prints the
//! manifest + target path), and `--apply` actually writes it (creating the
//! directory). It is idempotent — re-applying identical content is a no-op.
//!
//! ## The extension ID is not known yet
//!
//! The TypeScript extension lives in a separate repo and is not yet published,
//! so its Chrome extension ID is unknown. `--extension-id <id>` supplies it;
//! without it we use a clearly-marked placeholder and print a note that the real
//! ID is required before the host will actually accept a connection.
//!
//! ## Windows
//!
//! On Windows the manifest is registered via a REGISTRY key
//! (`HKCU\Software\Google\Chrome\NativeMessagingHosts\sh.tirith.browser`)
//! pointing at a manifest file, not by dropping a file in a well-known
//! directory. We do NOT write the registry here — we print guidance.

use std::path::PathBuf;

use super::write_json_stdout;

/// The native messaging host name. Must match the value the companion extension
/// passes to `chrome.runtime.connectNative(...)` and the `name` field in the
/// manifest. Lives under the `sh.tirith` reverse-DNS prefix the rest of tirith
/// uses (cf. `sh.tirith.clipboard` launchd label).
pub const HOST_NAME: &str = "sh.tirith.browser";

/// Documented placeholder extension ID, used when `--extension-id` is omitted.
/// A real Chrome extension ID is 32 lowercase letters `a`–`p`; this placeholder
/// is obviously NOT a real ID, so a manifest written with it cannot silently
/// authorize a real extension. The accompanying note tells the operator to
/// re-run with `--extension-id`.
pub const PLACEHOLDER_EXTENSION_ID: &str = "EXTENSION_ID_PLACEHOLDER_REPLACE_ME";

/// `tirith browser install-extension` entry point.
///
/// * `extension_id` — the Chrome extension ID allowed to connect; defaults to
///   [`PLACEHOLDER_EXTENSION_ID`] with a note when omitted.
/// * `apply` — write the manifest (creating the dir) instead of just printing.
/// * `json` — emit a JSON envelope instead of the human text.
///
/// Returns the process exit code (0 on success / dry-run; 1 on a write failure
/// or an unsupported platform with `--apply`).
pub fn install_extension(extension_id: Option<String>, apply: bool, json: bool) -> i32 {
    let platform = manifest_platform();
    let exe = current_tirith_exe();

    // Resolve and validate the extension ID. A blank/whitespace value is
    // treated as "not provided" so `--extension-id ''` doesn't write an empty
    // origin.
    let (extension_id, is_placeholder) = match extension_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(id) => (id, false),
        None => (PLACEHOLDER_EXTENSION_ID.to_string(), true),
    };

    let manifest = render_manifest(&exe, &extension_id);
    let manifest_path = manifest_path();

    // ---- platforms without a file-drop install (Windows) -------------------
    let Some(path) = manifest_path else {
        // Windows: registry-based registration, not a directory drop.
        if json {
            let env = serde_json::json!({
                "platform": platform,
                "host_name": HOST_NAME,
                "manifest_path": serde_json::Value::Null,
                "written": false,
                "extension_id": extension_id,
                "extension_id_is_placeholder": is_placeholder,
                "manifest": manifest,
                "note": windows_guidance(&exe),
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
                windows_guidance(&exe)
            );
            eprintln!("tirith browser install-extension: manifest body to register:");
            println!("{manifest}");
        }
        // Not an error: we gave the operator everything they need to register
        // it manually. Exit 0 in the dry-run sense.
        return 0;
    };

    // ---- dry-run (default): print the manifest + target path ---------------
    if !apply {
        if json {
            let env = serde_json::json!({
                "platform": platform,
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
                "tirith browser install-extension: dry-run; would write to {}",
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
            // The manifest itself goes to stdout so it can be redirected.
            println!("{manifest}");
        }
        return 0;
    }

    // ---- --apply: write the manifest (idempotent) --------------------------
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "tirith browser install-extension: failed to create {}: {e}",
                parent.display()
            );
            return 1;
        }
    }

    // Idempotency: skip the write when the on-disk content already matches.
    let needs_write =
        !matches!(std::fs::read_to_string(&path), Ok(existing) if existing == manifest);
    if needs_write {
        if let Err(e) =
            super::write_file_atomic(&path, manifest.as_bytes(), /*overwrite=*/ true)
        {
            eprintln!(
                "tirith browser install-extension: failed to write {}: {e}",
                path.display()
            );
            return 1;
        }
    }

    if json {
        let env = serde_json::json!({
            "platform": platform,
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
            eprintln!("tirith browser install-extension: wrote {}", path.display());
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

/// Build the native messaging host manifest JSON for the given executable path
/// and extension id. Pretty-printed and stable so the idempotency content
/// comparison is reliable.
pub fn render_manifest(exe: &str, extension_id: &str) -> String {
    let manifest = serde_json::json!({
        "name": HOST_NAME,
        "description": "tirith browser native-messaging host (paste provenance, M12)",
        "path": exe,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    });
    // `to_string_pretty` cannot fail for a value we built; fall back defensively.
    serde_json::to_string_pretty(&manifest).unwrap_or_else(|_| "{}".to_string())
}

/// Short platform tag for JSON envelopes / human messages.
fn manifest_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos-chrome"
    }
    #[cfg(target_os = "linux")]
    {
        "linux-chrome"
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

/// The per-OS path of the Chrome NativeMessagingHosts manifest. `None` on
/// Windows (registry-based) and unsupported platforms.
///
/// * macOS:  `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/sh.tirith.browser.json`
/// * Linux:  `~/.config/google-chrome/NativeMessagingHosts/sh.tirith.browser.json`
fn manifest_path() -> Option<PathBuf> {
    let home = home::home_dir()?;
    let file = format!("{HOST_NAME}.json");
    #[cfg(target_os = "macos")]
    {
        Some(
            home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts")
                .join(file),
        )
    }
    #[cfg(target_os = "linux")]
    {
        Some(
            home.join(".config/google-chrome/NativeMessagingHosts")
                .join(file),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (home, file);
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (home, file);
        None
    }
}

/// Guidance text printed on Windows, where the host is registered via a registry
/// key rather than a directory drop.
fn windows_guidance(exe: &str) -> String {
    format!(
        "on Windows, register the native messaging host via the registry rather than a file drop. \
         Save the manifest body below to a file (e.g. %LOCALAPPDATA%\\tirith\\{HOST_NAME}.json), \
         then create the key \
         HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\{HOST_NAME} with its default value \
         set to that file's path. The host executable is: {exe}"
    )
}

/// Resolve the path to the current `tirith` binary for the manifest's `path`
/// field — the executable Chrome will spawn. Falls back to the literal
/// `"tirith"` (relying on PATH) if `current_exe()` fails, mirroring
/// `clipboard::current_tirith_exe`.
fn current_tirith_exe() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "tirith".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered manifest carries the host name, the exe path, the stdio
    /// transport, and the extension id woven into a `chrome-extension://` origin.
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

    /// The manifest embeds the exe path verbatim (the load-bearing `path` field
    /// Chrome spawns), so a path with spaces survives the JSON round-trip.
    #[test]
    fn manifest_preserves_exe_path_with_spaces() {
        let m = render_manifest(
            "/Applications/My Tools/tirith",
            "abcdefghijklmnopabcdefghijklmnop",
        );
        let parsed: serde_json::Value = serde_json::from_str(&m).unwrap();
        assert_eq!(parsed["path"], "/Applications/My Tools/tirith");
    }

    /// The placeholder extension id flows into the origin so a dry-run shows the
    /// operator exactly the (obviously-fake) origin they need to replace.
    #[test]
    fn placeholder_id_appears_in_origin() {
        let m = render_manifest("/bin/tirith", PLACEHOLDER_EXTENSION_ID);
        assert!(
            m.contains(&format!("chrome-extension://{PLACEHOLDER_EXTENSION_ID}/")),
            "placeholder id must appear in the origin; got: {m}"
        );
    }

    /// Windows guidance names the registry key and the host executable so a
    /// Windows operator can register it manually.
    #[test]
    fn windows_guidance_mentions_registry_and_exe() {
        let g = windows_guidance("C:\\tools\\tirith.exe");
        assert!(g.contains("HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts"));
        assert!(g.contains(HOST_NAME));
        assert!(g.contains("C:\\tools\\tirith.exe"));
    }

    /// On the file-drop platforms the manifest path ends in the host filename
    /// inside a `NativeMessagingHosts` directory.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn manifest_path_targets_native_messaging_hosts_dir() {
        // home::home_dir() is set in normal test environments; if it isn't,
        // skip rather than fail (CI sandboxes occasionally unset HOME).
        let Some(p) = manifest_path() else {
            eprintln!("skipping: no home dir resolved in this environment");
            return;
        };
        let s = p.display().to_string();
        assert!(
            s.ends_with(&format!("NativeMessagingHosts/{HOST_NAME}.json")),
            "got {s}"
        );
    }
}
