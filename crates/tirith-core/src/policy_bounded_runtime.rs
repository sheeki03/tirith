//! Internal bounded input admission for automatic activation processes.
//! Runtime resolution, authority selection and overlays stay unchanged. An
//! unreadable/oversized/special user list refuses this entire scoped operation;
//! it is never interpreted as an absent allowlist or blocklist.

use super::{Policy, PolicyDiagnosticCapture};
use crate::policy_snapshot::InputReader;
use crate::util::OpenRegularError;
use std::cell::{Cell, RefCell};
use std::path::Path;
use std::rc::{Rc, Weak};

// Two named user list inputs. Other runtime inputs already retain their own
// regular-file/body bounds. This is an admission limit, not a workload budget.
const USER_LIST_CAP: u64 = 1024 * 1024;

thread_local! {
    static ACTIVE: RefCell<Weak<Cell<bool>>> = const { RefCell::new(Weak::new()) };
}

/// Internal thread-local scope for the fixed automatic broker/relay/probe/check
/// routes. It grants no policy or execution authority. A nested scope shares
/// refusal state; dropping it cannot erase an outer refusal. Ordinary callers
/// keep their existing user-list reader and diagnostic behavior.
#[doc(hidden)]
pub struct BoundedRuntimePolicyInputs {
    _state: Rc<Cell<bool>>,
    _diagnostics: PolicyDiagnosticCapture,
}

impl BoundedRuntimePolicyInputs {
    pub fn enter() -> Self {
        let state = ACTIVE.with(|active| {
            let existing = active.borrow().upgrade();
            existing.unwrap_or_else(|| {
                let state = Rc::new(Cell::new(false));
                *active.borrow_mut() = Rc::downgrade(&state);
                state
            })
        });
        Self {
            _state: state,
            _diagnostics: PolicyDiagnosticCapture::start_silent(),
        }
    }
}

pub(crate) fn bounded_runtime_refused() -> bool {
    ACTIVE.with(|active| active.borrow().upgrade().is_some_and(|state| state.get()))
}

pub(crate) fn user_list_reader() -> InputReader {
    if ACTIVE.with(|active| active.borrow().upgrade().is_some()) {
        InputReader::BoundedUserList(USER_LIST_CAP)
    } else {
        InputReader::UserList
    }
}

pub(crate) fn read_bounded_user_list(path: &Path, cap: u64) -> Result<Vec<u8>, OpenRegularError> {
    // Open nonblocking, then inspect that actual descriptor and read cap+1.
    // Preserve the ordinary reader's symlink-to-regular-file semantics; a
    // symlink to a special/oversized file still refuses through descriptor stat.
    let result = crate::util::read_regular_capped(path, cap).and_then(|bytes| {
        std::str::from_utf8(&bytes).map_err(|_| {
            OpenRegularError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded runtime list is not UTF-8",
            ))
        })?;
        Ok(bytes)
    });
    if matches!(&result, Err(error) if !matches!(error, OpenRegularError::NotFound)) {
        ACTIVE.with(|active| {
            if let Some(state) = active.borrow().upgrade() {
                state.set(true);
            }
        });
    }
    result
}

pub(crate) fn refuse_bounded_runtime_if_needed(policy: Policy) -> Policy {
    if bounded_runtime_refused() {
        // Apply after all overlays too: a later trust/list overlay cannot
        // suppress the existing fail-closed policy's all-input block rule.
        Policy::fail_closed_policy()
    } else {
        policy
    }
}

#[cfg(test)]
#[path = "policy_bounded_runtime_tests.rs"]
mod tests;
