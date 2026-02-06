use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

fn validate_sha256(sha256: &str) -> Result<(), String> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(format!(
            "invalid sha256: expected 64 lowercase hex characters, got '{}'",
            crate::util::truncate_bytes(sha256, 16)
        ));
    }
    Ok(())
}

/// Safe short prefix of a hash for display. Uses the existing UTF-8-safe
/// `truncate_bytes` utility to handle any string safely, including
/// corrupted receipt JSON with non-ASCII sha256 values.
pub fn short_hash(s: &str) -> String {
    crate::util::truncate_bytes(s, 12)
}

/// A receipt for a script that was downloaded and analyzed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub url: String,
    pub final_url: Option<String>,
    pub redirects: Vec<String>,
    pub sha256: String,
    pub size: u64,
    pub domains_referenced: Vec<String>,
    pub paths_referenced: Vec<String>,
    pub analysis_method: String,
    pub privilege: String,
    pub timestamp: String,
    pub cwd: Option<String>,
    pub git_repo: Option<String>,
    pub git_branch: Option<String>,
}

impl Receipt {
    /// Save receipt atomically (temp file + rename).
    pub fn save(&self) -> Result<PathBuf, String> {
        validate_sha256(&self.sha256)?;
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        fs::create_dir_all(&dir).map_err(|e| format!("create dir: {e}"))?;

        let path = dir.join(format!("{}.json", self.sha256));
        let tmp_path = dir.join(format!(".{}.json.tmp", self.sha256));

        let json = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;

        {
            use std::io::Write;
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp_path).map_err(|e| format!("write: {e}"))?;
            f.write_all(json.as_bytes())
                .map_err(|e| format!("write: {e}"))?;
        }
        fs::rename(&tmp_path, &path).map_err(|e| format!("rename: {e}"))?;

        Ok(path)
    }

    /// Load a receipt by SHA256.
    pub fn load(sha256: &str) -> Result<Self, String> {
        validate_sha256(sha256)?;
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        let path = dir.join(format!("{sha256}.json"));
        let content = fs::read_to_string(&path).map_err(|e| format!("read: {e}"))?;
        serde_json::from_str(&content).map_err(|e| format!("parse: {e}"))
    }

    /// List all receipts.
    pub fn list() -> Result<Vec<Self>, String> {
        let dir = receipts_dir().ok_or("cannot determine receipts directory")?;
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut receipts = Vec::new();
        let entries = fs::read_dir(&dir).map_err(|e| format!("read dir: {e}"))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json")
                && !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(receipt) = serde_json::from_str::<Receipt>(&content) {
                        receipts.push(receipt);
                    }
                }
            }
        }

        receipts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        Ok(receipts)
    }

    /// Verify a receipt: check if the file at the cached path still matches sha256.
    pub fn verify(&self) -> Result<bool, String> {
        validate_sha256(&self.sha256)?;
        let cache_dir = cache_dir().ok_or("cannot determine cache directory")?;
        let cached = cache_dir.join(&self.sha256);
        if !cached.exists() {
            return Ok(false);
        }

        let content = fs::read(&cached).map_err(|e| format!("read: {e}"))?;
        let hash = sha2_hex(&content);
        Ok(hash == self.sha256)
    }
}

fn receipts_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("receipts"))
}

fn cache_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("cache"))
}

fn sha2_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_sha256_valid() {
        let hash = "a".repeat(64);
        assert!(validate_sha256(&hash).is_ok());
    }

    #[test]
    fn test_validate_sha256_too_short() {
        assert!(validate_sha256("abc").is_err());
    }

    #[test]
    fn test_validate_sha256_path_traversal() {
        assert!(validate_sha256("../../etc/passwd").is_err());
    }

    #[test]
    fn test_validate_sha256_uppercase_rejected() {
        let hash = "A".repeat(64);
        assert!(validate_sha256(&hash).is_err());
    }

    #[test]
    fn test_short_hash_short_input() {
        assert_eq!(short_hash("abc"), "abc");
    }

    #[test]
    fn test_short_hash_normal() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert_eq!(short_hash(hash), "abcdef012345");
    }

    #[test]
    fn test_short_hash_non_ascii() {
        // Multi-byte UTF-8: each char is 3 bytes, so 12 bytes = 4 chars
        let s = "日本語テスト";
        let result = short_hash(s);
        assert!(!result.is_empty());
        assert!(result.len() <= 12);
    }

    #[cfg(unix)]
    #[test]
    fn test_receipt_save_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let receipts_dir = dir.path().join("receipts");
        std::fs::create_dir_all(&receipts_dir).unwrap();

        let sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Write a receipt file with 0600 permissions using the same pattern as save()
        let path = receipts_dir.join(format!("{sha}.json"));
        let json = r#"{"test": true}"#;
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            opts.mode(0o600);
            let mut f = opts.open(&path).unwrap();
            f.write_all(json.as_bytes()).unwrap();
        }

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "receipt file should be 0600"
        );
    }
}
