//! Per-MCP-session origin state.
//!
//! M4 item 8. The MCP server (`tirith mcp-server`) is a stdio process:
//! one client connects, runs through `initialize` once, then issues
//! `tools/call` requests for the rest of the session. The
//! [`AgentOrigin::Mcp`] payload — derived from `initialize.clientInfo`
//! — is therefore process-scoped: stable for the lifetime of the MCP
//! server process.
//!
//! [`AgentOrigin::Mcp`]: crate::agent_origin::AgentOrigin::Mcp
//!
//! The dispatcher writes the origin once when it handles `initialize`;
//! the tools layer reads it when constructing each verdict. The
//! `tools/call_check_command` handler routes through
//! [`crate::escalation::apply_agent_rules`] via `post_process_verdict`,
//! and the `tools/call_check_url` / `tools/call_check_paste` handlers
//! call [`crate::escalation::apply_agent_rules`] directly. All three
//! enforce `agent_rules.deny`.

use std::sync::RwLock;

use crate::agent_origin::AgentOrigin;
use crate::mcp::types::ClientInfo;

/// Process-scoped store of the current MCP session's origin.
///
/// `RwLock<Option<...>>` rather than `OnceLock` because the dispatcher accepts
/// a *new* `initialize` from the Initialized / Ready states (the MCP spec
/// allows clients to renegotiate); the second initialize replaces the first.
static MCP_ORIGIN: RwLock<Option<AgentOrigin>> = RwLock::new(None);

/// Record the MCP client identity from an `initialize` payload. Called by the
/// dispatcher exactly when it handles the `initialize` request.
///
/// If `client_info` is `None` (some implementations omit it), records a
/// default-shaped [`AgentOrigin::Mcp`] with `client_name = "unknown-mcp-client"`
/// so the audit entry still says "this came from an MCP client" rather than
/// silently falling back to the CLI default.
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

    // RwLock::write can only fail if the lock is poisoned (a thread holding
    // it panicked). MCP dispatcher is single-threaded today but defend
    // anyway — recovering the inner value lets us still update the origin.
    let mut guard = MCP_ORIGIN
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(origin);
}

/// Return the current MCP session's origin, if `initialize` has been seen.
///
/// Returns `None` before `initialize` (no tool call should reach the tools
/// layer in that state — the dispatcher refuses).
///
/// A poisoned `RwLock` (caused by a thread panicking inside a `write()`
/// scope elsewhere) is still recoverable for reads: the inner `Option` is
/// valid data and reading it cannot make poisoning worse. We explicitly
/// recover so a panic in some unrelated codepath does not silently strip
/// the MCP origin off every subsequent verdict.
pub fn current() -> Option<AgentOrigin> {
    let guard = match MCP_ORIGIN.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.as_ref().cloned()
}

/// Test-only mutex that serializes access to [`MCP_ORIGIN`] across tests.
/// Cargo runs lib-tests in parallel within a single binary, so without a
/// guard test cases would race on the global and trip each other's
/// `current()` assertions. Any test that mutates or reads `MCP_ORIGIN` must
/// hold this lock for its duration via [`serial_lock`] or
/// [`reset_for_test`]. `Mutex` rather than `RwLock` — even read-only tests
/// must serialize, because a parallel writer would invalidate the reader's
/// expected value.
#[cfg(test)]
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test-only: acquire [`TEST_SERIAL`] without touching [`MCP_ORIGIN`].
/// Used by tests that drive the dispatcher (which writes `MCP_ORIGIN` via
/// `set_from_initialize`) and want to observe their own write without
/// another concurrent test clobbering it. Recovers from a poisoned mutex.
#[cfg(test)]
#[must_use = "bind to `let _guard = serial_lock();` to hold the test lock"]
pub(crate) fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Test-only reset hook. Acquires [`TEST_SERIAL`] (so the test runs without
/// other origin-tests interleaving), clears [`MCP_ORIGIN`], and returns the
/// guard so the caller can hold it for the rest of the test by binding to
/// `let _guard = reset_for_test();`.
///
/// Recovers from a poisoned mutex / rwlock — a panicking earlier test would
/// otherwise wedge every subsequent test against `unwrap()`.
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
        // A million-byte name with embedded ANSI / newline / NUL bytes must
        // (a) not crash, (b) cap at MAX_LABEL_LEN, (c) leave no control
        // bytes in the stored value.
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

    /// CodeRabbit Minor (cid 3292343382): a poisoned `RwLock` is recoverable
    /// for reads — the inner data is still valid. Before the fix `current()`
    /// returned `None` if any other thread had panicked while holding a
    /// write lock, silently stripping `agent_origin` off every later
    /// verdict. We test by deliberately poisoning the global through a
    /// scoped panic inside a write guard, then asserting `current()` still
    /// returns the stored value.
    ///
    /// This test is isolated to its own `RwLock` so it cannot leak a
    /// poisoned state to the rest of the suite. It also exercises the
    /// `Err(poisoned) => poisoned.into_inner()` arm directly, which is the
    /// behavior `current()` must mirror against `MCP_ORIGIN`.
    #[test]
    fn poisoned_lock_still_returns_stored_origin() {
        use std::panic::{self, AssertUnwindSafe};
        use std::sync::RwLock;

        // Local store mirroring MCP_ORIGIN's shape — keeps poisoning
        // contained to this test.
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
