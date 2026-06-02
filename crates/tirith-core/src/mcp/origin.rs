//! Per-MCP-session origin state (M4 item 8).
//!
//! The MCP server is a stdio process: one client `initialize`s once, then issues
//! `tools/call` requests. The [`AgentOrigin::Mcp`] payload (from
//! `initialize.clientInfo`) is process-scoped. The dispatcher writes it on
//! `initialize`; the tools layer reads it per verdict and enforces
//! `agent_rules.deny`.
//!
//! [`AgentOrigin::Mcp`]: crate::agent_origin::AgentOrigin::Mcp

use std::sync::RwLock;

use crate::agent_origin::AgentOrigin;
use crate::mcp::types::ClientInfo;

/// Process-scoped store of the current MCP session's origin.
///
/// `RwLock<Option<...>>` not `OnceLock` because the MCP spec lets clients
/// re-`initialize`; the second one replaces the first.
static MCP_ORIGIN: RwLock<Option<AgentOrigin>> = RwLock::new(None);

/// Record the MCP client identity from an `initialize` payload.
///
/// `client_info: None` (some clients omit it) records an `unknown-mcp-client`
/// origin so the audit entry still attributes it to MCP, not the CLI default.
pub fn set_from_initialize(client_info: Option<&ClientInfo>) {
    let origin = match client_info {
        Some(ci) => {
            AgentOrigin::mcp(&ci.name, ci.version.as_deref()).unwrap_or_else(|| AgentOrigin::Mcp {
                client_name: "unknown-mcp-client".to_string(),
                client_version: None,
            })
        }
        None => AgentOrigin::Mcp {
            client_name: "unknown-mcp-client".to_string(),
            client_version: None,
        },
    };

    // Recover from a poisoned lock so we can still update the origin.
    let mut guard = MCP_ORIGIN
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(origin);
}

/// Return the current MCP session's origin, or `None` before `initialize`.
///
/// Recovers from a poisoned `RwLock` so an unrelated panic doesn't silently
/// strip the MCP origin off every later verdict (the inner data is still valid).
pub fn current() -> Option<AgentOrigin> {
    let guard = match MCP_ORIGIN.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.as_ref().cloned()
}

/// Test-only mutex serializing [`MCP_ORIGIN`] access across the parallel
/// lib-tests. Even read-only tests must hold it, since a parallel writer would
/// invalidate the reader's expected value.
#[cfg(test)]
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-only: acquire [`TEST_SERIAL`] without touching [`MCP_ORIGIN`] (for tests
/// that drive the dispatcher). Recovers from a poisoned mutex.
#[cfg(test)]
#[must_use = "bind to `let _guard = serial_lock();` to hold the test lock"]
pub(crate) fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only reset hook: acquire [`TEST_SERIAL`], clear [`MCP_ORIGIN`], and
/// return the guard to hold for the rest of the test. Recovers from poisoning.
#[cfg(test)]
#[must_use = "bind to `let _guard = reset_for_test();` to hold the test lock"]
pub(crate) fn reset_for_test() -> std::sync::MutexGuard<'static, ()> {
    let guard = serial_lock();
    let mut store = MCP_ORIGIN
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *store = None;
    drop(store);
    guard
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_from_initialize_with_client_info_records_mcp_origin() {
        let _guard = reset_for_test();
        let ci = ClientInfo {
            name: "Claude Code".to_string(),
            version: Some("1.2.3".to_string()),
        };
        set_from_initialize(Some(&ci));
        let origin = current().expect("origin should be set");
        match origin {
            AgentOrigin::Mcp {
                client_name,
                client_version,
            } => {
                assert_eq!(client_name, "Claude Code");
                assert_eq!(client_version.as_deref(), Some("1.2.3"));
            }
            other => panic!("expected Mcp variant, got {other:?}"),
        }
    }

    #[test]
    fn set_from_initialize_with_no_client_info_records_unknown() {
        let _guard = reset_for_test();
        set_from_initialize(None);
        let origin = current().expect("origin should be set");
        match origin {
            AgentOrigin::Mcp {
                client_name,
                client_version,
            } => {
                assert_eq!(client_name, "unknown-mcp-client");
                assert_eq!(client_version, None);
            }
            other => panic!("expected Mcp variant, got {other:?}"),
        }
    }

    #[test]
    fn hostile_client_info_is_sanitized() {
        let _guard = reset_for_test();
        // A huge name with ANSI/newline/NUL must not crash, must cap at
        // MAX_LABEL_LEN, and must leave no control bytes.
        let hostile = format!("{}\n\x1b[31m\x00", "x".repeat(1_000_000));
        let ci = ClientInfo {
            name: hostile,
            version: None,
        };
        set_from_initialize(Some(&ci));
        let origin = current().expect("origin should be set");
        if let AgentOrigin::Mcp { client_name, .. } = origin {
            assert!(client_name.len() <= crate::agent_origin::MAX_LABEL_LEN);
            assert!(!client_name.contains('\n'));
            assert!(!client_name.contains('\x1b'));
            assert!(!client_name.contains('\x00'));
        } else {
            panic!("expected Mcp variant");
        }
    }

    #[test]
    fn blank_client_name_falls_back_to_unknown() {
        let _guard = reset_for_test();
        let ci = ClientInfo {
            name: "   ".to_string(),
            version: None,
        };
        set_from_initialize(Some(&ci));
        let origin = current().expect("origin should be set");
        if let AgentOrigin::Mcp { client_name, .. } = origin {
            assert_eq!(client_name, "unknown-mcp-client");
        } else {
            panic!("expected Mcp variant");
        }
    }

    /// CodeRabbit Minor (cid 3292343382): a poisoned `RwLock` is recoverable for
    /// reads. Before the fix `current()` returned `None` after any unrelated
    /// write-lock panic, stripping `agent_origin` off every later verdict. Uses
    /// a local `RwLock` (so poisoning can't leak) to exercise the recovery arm.
    #[test]
    fn poisoned_lock_still_returns_stored_origin() {
        use std::panic::{self, AssertUnwindSafe};
        use std::sync::RwLock;

        // Local store mirroring MCP_ORIGIN; keeps poisoning contained.
        let store: RwLock<Option<AgentOrigin>> = RwLock::new(Some(AgentOrigin::Mcp {
            client_name: "poison-survivor".to_string(),
            client_version: Some("9.9.9".to_string()),
        }));

        // Poison the lock by panicking inside a write scope.
        let poison_result = panic::catch_unwind(AssertUnwindSafe(|| {
            let _guard = store.write().expect("first write should not be poisoned");
            panic!("intentional panic to poison the RwLock");
        }));
        assert!(poison_result.is_err(), "panic should have been caught");
        assert!(store.is_poisoned(), "lock must be poisoned for this test");

        // The recovery shape `current()` uses must still surface the value.
        let guard = match store.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_ref().cloned() {
            Some(AgentOrigin::Mcp {
                client_name,
                client_version,
            }) => {
                assert_eq!(client_name, "poison-survivor");
                assert_eq!(client_version.as_deref(), Some("9.9.9"));
            }
            other => panic!("expected Some(Mcp), got {other:?}"),
        }
    }
}
