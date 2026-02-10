use std::sync::OnceLock;

/// Global session ID for the current tirith process lifetime.
static SESSION_ID: OnceLock<String> = OnceLock::new();

/// Get or generate the session ID.
///
/// Priority:
/// 1. `TIRITH_SESSION_ID` env var (set by shell hooks for cross-command sessions)
/// 2. Auto-generated UUID for this process
pub fn session_id() -> &'static str {
    SESSION_ID.get_or_init(|| {
        std::env::var("TIRITH_SESSION_ID").unwrap_or_else(|_| generate_session_id())
    })
}

/// Generate a new session ID (UUID v4 format without external dep).
fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    // Simple hash-based ID: not cryptographic, just unique enough for session tracking
    let hash = timestamp
        .wrapping_mul(6364136223846793005)
        .wrapping_add(pid as u128);
    format!("{:016x}-{:08x}", hash as u64, (hash >> 64) as u32)
}

/// Generate a fresh session ID suitable for `tirith init` to export.
pub fn new_session_id() -> String {
    generate_session_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_stable_within_process() {
        let id1 = session_id();
        let id2 = session_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_generate_session_id_unique() {
        let a = generate_session_id();
        // Small sleep to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_millis(1));
        let b = generate_session_id();
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_session_id_format() {
        let id = generate_session_id();
        // Format: 16 hex chars, dash, 8 hex chars
        assert_eq!(id.len(), 25);
        assert_eq!(id.chars().nth(16), Some('-'));
    }
}
