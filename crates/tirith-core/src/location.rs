//! A shared, serializable description of WHERE an inspected subject lives.
//!
//! Introduced in A2 (typed scan outcomes / coverage) and reused by A3's artifact
//! model, so the same location shape carries a coverage gap, an artifact file, an
//! `ArtifactSignal`, and an `ExecutionEdge`. Three independent coordinates, all
//! optional, because a subject may be located by any combination of them:
//!
//! * `outer_path` — the on-disk container (a wheel/archive path, or the scanned
//!   file itself for a plain file).
//! * `member_path` — a path INSIDE that container (a ZIP member like
//!   `pkg/bootstrap.pth`); `None` for a non-archive subject.
//! * `installed_path` — the resolved on-disk path of an INSTALLED file (used by
//!   the installed-distribution paths in B5), distinct from `outer_path` because
//!   an installed file has no archive container.
//!
//! The [`std::fmt::Display`] form renders `outer.whl!/member` (the conventional
//! archive-member notation) so JSON/SARIF and human output agree on one string.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Where an inspected subject (a scanned file, an archive member, an installed
/// file) is located. Every coordinate is optional; see the module docs for how
/// they combine. Serializes with `skip_serializing_if` so an absent coordinate
/// adds no JSON noise.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectLocation {
    /// The on-disk container or the file itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outer_path: Option<PathBuf>,
    /// A path inside the container (an archive member), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_path: Option<String>,
    /// The resolved on-disk path of an installed file, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_path: Option<PathBuf>,
}

impl SubjectLocation {
    /// A location that is just an on-disk file (no archive member, not installed).
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self {
            outer_path: Some(path.into()),
            member_path: None,
            installed_path: None,
        }
    }

    /// A location for an archive member: `outer` is the container, `member` the
    /// path inside it.
    pub fn member(outer: impl Into<PathBuf>, member: impl Into<String>) -> Self {
        Self {
            outer_path: Some(outer.into()),
            member_path: Some(member.into()),
            installed_path: None,
        }
    }

    /// A location for a resolved installed file.
    pub fn installed(path: impl Into<PathBuf>) -> Self {
        Self {
            outer_path: None,
            member_path: None,
            installed_path: Some(path.into()),
        }
    }
}

impl std::fmt::Display for SubjectLocation {
    /// Render the conventional `outer.whl!/member` notation when a member is
    /// present, else the outer or installed path, else `<unknown>`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.outer_path, &self.member_path, &self.installed_path) {
            (Some(outer), Some(member), _) => {
                // Normalize a leading slash on the member so we render exactly one
                // `!/` separator regardless of how the member path was stored.
                let member = member.trim_start_matches('/');
                write!(f, "{}!/{}", outer.display(), member)
            }
            (Some(outer), None, _) => write!(f, "{}", outer.display()),
            (None, _, Some(installed)) => write!(f, "{}", installed.display()),
            (None, Some(member), None) => write!(f, "{member}"),
            (None, None, None) => write!(f, "<unknown>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_renders_archive_member_notation() {
        let loc = SubjectLocation::member("foo.whl", "pkg/file.pth");
        assert_eq!(loc.to_string(), "foo.whl!/pkg/file.pth");
    }

    #[test]
    fn display_collapses_leading_slash_on_member() {
        // A member stored with a leading slash must still render exactly one `!/`.
        let loc = SubjectLocation::member("foo.whl", "/pkg/file.pth");
        assert_eq!(loc.to_string(), "foo.whl!/pkg/file.pth");
    }

    #[test]
    fn display_plain_path() {
        let loc = SubjectLocation::from_path("/tmp/note.md");
        assert_eq!(loc.to_string(), "/tmp/note.md");
    }

    #[test]
    fn display_installed_path() {
        let loc = SubjectLocation::installed("/venv/lib/site-packages/x.py");
        assert_eq!(loc.to_string(), "/venv/lib/site-packages/x.py");
    }

    #[test]
    fn display_unknown_when_empty() {
        assert_eq!(SubjectLocation::default().to_string(), "<unknown>");
    }

    #[test]
    fn serde_round_trip_omits_absent_fields() {
        let loc = SubjectLocation::from_path("/tmp/a");
        let json = serde_json::to_string(&loc).unwrap();
        // Only the present coordinate is serialized.
        assert!(json.contains("outer_path"));
        assert!(!json.contains("member_path"));
        assert!(!json.contains("installed_path"));
        let back: SubjectLocation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, loc);
    }
}
