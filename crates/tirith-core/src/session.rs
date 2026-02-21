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

/// Generate a new session ID using UUID v4.
fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
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
        // UUID v4 format: 8-4-4-4-12 hex chars = 36 chars
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }
}
