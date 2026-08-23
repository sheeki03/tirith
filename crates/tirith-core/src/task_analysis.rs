//! Trusted analysis context for task-envelope shell actions.
//!
//! The context is deliberately separate from provenance receipts. A receipt
//! proves where content came from; it must not let an untrusted document choose
//! the shell grammar, working directory, or policy identity used to decide
//! whether command analysis is complete.

use std::path::{Component, Path, PathBuf};

use crate::tokenize::ShellType;

/// Runtime facts supplied by a Tirith-owned execution boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskAnalysisContext {
    effective_shell: Option<ShellType>,
    claimed_shell: Option<ShellType>,
    cwd: Option<PathBuf>,
    cwd_authoritative: bool,
    policy_identity: Option<String>,
}

impl TaskAnalysisContext {
    /// A diagnostic-only caller claim. It may select a parser for useful
    /// hints, but it can never make an enforcement decision complete.
    pub fn with_claimed_shell(shell: ShellType) -> Self {
        Self {
            claimed_shell: Some(shell),
            ..Self::default()
        }
    }

    /// Construct context owned by a boundary that knows which shell will
    /// execute the command. Boundary facts always override caller claims.
    pub fn trusted(shell: ShellType, cwd: Option<&Path>, policy_identity: Option<&str>) -> Self {
        let cwd_authoritative = cwd.is_some_and(Path::is_absolute);
        Self {
            effective_shell: Some(shell),
            claimed_shell: None,
            cwd: cwd.map(normalize_cwd),
            cwd_authoritative,
            policy_identity: policy_identity.map(str::to_owned),
        }
    }

    /// Add an untrusted claim without replacing an effective boundary shell.
    pub fn with_claim(mut self, shell: Option<ShellType>) -> Self {
        self.claimed_shell = shell;
        self
    }

    pub fn effective_shell(&self) -> Option<ShellType> {
        self.effective_shell
    }

    pub(crate) fn parser_shell(&self) -> Option<ShellType> {
        self.effective_shell.or(self.claimed_shell)
    }

    /// Completeness requires all identity-defining boundary facts. An absent
    /// policy projection or an unspecified cwd cannot be treated as a stable
    /// execution identity.
    pub(crate) fn has_authoritative_identity(&self) -> bool {
        self.effective_shell.is_some() && self.cwd_authoritative && self.policy_identity.is_some()
    }

    pub(crate) fn cwd(&self) -> Option<&Path> {
        self.cwd.as_deref()
    }

    pub(crate) fn cwd_is_authoritative(&self) -> bool {
        self.cwd_authoritative
    }

    pub(crate) fn policy_identity(&self) -> Option<&str> {
        self.policy_identity.as_deref()
    }
}

/// Lexically normalize a trusted cwd without resolving symlinks or performing
/// I/O. The identity is only a parser-context binding, not a containment proof.
fn normalize_cwd(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let previous_is_normal = normalized
                    .components()
                    .next_back()
                    .is_some_and(|previous| matches!(previous, Component::Normal(_)));
                if previous_is_normal {
                    normalized.pop();
                } else if !path.is_absolute() {
                    normalized.push(component.as_os_str());
                }
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_shell_overrides_a_caller_claim() {
        let context = TaskAnalysisContext::trusted(ShellType::PowerShell, None, None)
            .with_claim(Some(ShellType::Posix));
        assert_eq!(context.parser_shell(), Some(ShellType::PowerShell));
        assert_eq!(context.effective_shell(), Some(ShellType::PowerShell));
    }

    #[test]
    fn relative_cwd_is_not_authoritative_and_keeps_leading_parents() {
        let context = TaskAnalysisContext::trusted(
            ShellType::Posix,
            Some(Path::new("../../repo")),
            Some("policy"),
        );
        assert!(!context.has_authoritative_identity());
        assert_eq!(context.cwd(), Some(Path::new("../../repo")));
    }
}
