//! Pure lexical path parsing and containment.
//!
//! This module never consults the filesystem. It makes the input dialect and
//! root class explicit, keeps unresolved parent traversal as state, and compares
//! Windows roots/components with ASCII-only case folding. It is suitable for
//! conservative classification and policy matching, not canonical filesystem
//! authorization across symlinks.

use std::fmt;

/// Separator and root grammar used to parse an input path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathDialect {
    Posix,
    Windows,
}

/// The lexical root carried by a parsed path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootClass {
    Relative,
    PosixRoot,
    DriveRelative,
    DriveAbsolute,
    Unc,
    RootedNoDrive,
    Verbatim,
    Device,
}

/// Parent traversal that cannot be represented by normalized components.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParentState {
    /// Unresolved leading `..` components on a relative path.
    pub leading: usize,
    /// An absolute path attempted to traverse above its root.
    pub above_root: bool,
    /// At least one parent component was intentionally retained rather than
    /// lexically cancelled (for symlink-conservative classifiers).
    pub unresolved: bool,
}

impl ParentState {
    pub fn is_clean(self) -> bool {
        self.leading == 0 && !self.above_root && !self.unresolved
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RootIdentity {
    Relative,
    Posix,
    DriveRelative(u8),
    DriveAbsolute(u8),
    Unc { server: String, share: String },
    RootedNoDrive,
    VerbatimDrive(u8),
    VerbatimUnc { server: String, share: String },
    VerbatimOpaque(String),
    Device,
}

/// A separator- and dot-normalized lexical path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalPath {
    dialect: PathDialect,
    root_class: RootClass,
    root_identity: RootIdentity,
    components: Vec<String>,
    parent_state: ParentState,
    parents_preserved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexicalPathError {
    InteriorNul,
    IncompleteUncRoot,
    InvalidUncRoot,
    InvalidVerbatimRoot,
    InvalidDeviceRoot,
}

impl fmt::Display for LexicalPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InteriorNul => "path contains an interior NUL",
            Self::IncompleteUncRoot => "UNC path requires both server and share roots",
            Self::InvalidUncRoot => "UNC server/share root is invalid",
            Self::InvalidVerbatimRoot => "verbatim Windows root is invalid",
            Self::InvalidDeviceRoot => "Windows device root is invalid",
        })
    }
}

impl std::error::Error for LexicalPathError {}

impl LexicalPath {
    pub fn parse(input: &str, dialect: PathDialect) -> Result<Self, LexicalPathError> {
        Self::parse_inner(input, dialect, false)
    }

    /// Parse while retaining each `..` component in normalized output. Parent
    /// state still records leading/above-root behavior and marks the result
    /// unresolved, so containment always rejects it. This is intended for
    /// conservative classifiers that treat any parent traversal as sensitive.
    pub fn parse_preserving_parents(
        input: &str,
        dialect: PathDialect,
    ) -> Result<Self, LexicalPathError> {
        Self::parse_inner(input, dialect, true)
    }

    fn parse_inner(
        input: &str,
        dialect: PathDialect,
        preserve_parents: bool,
    ) -> Result<Self, LexicalPathError> {
        if input.contains('\0') {
            return Err(LexicalPathError::InteriorNul);
        }
        match dialect {
            PathDialect::Posix => Ok(parse_posix(input, preserve_parents)),
            PathDialect::Windows => parse_windows(input, preserve_parents),
        }
    }

    pub fn parse_auto(input: &str) -> Result<Self, LexicalPathError> {
        Self::parse(input, detect_dialect(input))
    }

    pub fn dialect(&self) -> PathDialect {
        self.dialect
    }

    pub fn root_class(&self) -> RootClass {
        self.root_class
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }

    pub fn parent_state(&self) -> ParentState {
        self.parent_state
    }

    /// Render the normalized path with `/` separators. Windows roots and
    /// components are already ASCII-folded. Above-root attempts are clamped in
    /// ordinary mode; parent-preserving mode renders the retained `..` tokens.
    pub fn to_slash_string(&self) -> String {
        let tail = if self.parents_preserved {
            self.components.join("/")
        } else {
            let mut components = Vec::with_capacity(
                self.parent_state
                    .leading
                    .saturating_add(self.components.len()),
            );
            components.extend((0..self.parent_state.leading).map(|_| "..".to_string()));
            components.extend(self.components.iter().cloned());
            components.join("/")
        };
        let rooted = |root: String| {
            if tail.is_empty() {
                root
            } else if root.ends_with('/') {
                format!("{root}{tail}")
            } else {
                format!("{root}/{tail}")
            }
        };
        match &self.root_identity {
            RootIdentity::Relative => tail,
            RootIdentity::Posix => rooted("/".to_string()),
            RootIdentity::DriveRelative(drive) => {
                format!("{}:{tail}", char::from(*drive))
            }
            RootIdentity::DriveAbsolute(drive) => rooted(format!("{}:/", char::from(*drive))),
            RootIdentity::Unc { server, share } => rooted(format!("//{server}/{share}")),
            RootIdentity::RootedNoDrive => rooted("/".to_string()),
            RootIdentity::VerbatimDrive(drive) => rooted(format!("//?/{}:/", char::from(*drive))),
            RootIdentity::VerbatimUnc { server, share } => {
                rooted(format!("//?/unc/{server}/{share}"))
            }
            RootIdentity::VerbatimOpaque(anchor) => rooted(format!("//?/{anchor}")),
            RootIdentity::Device => rooted("//./".to_string()),
        }
    }

    /// Whether the path has a syntactic root, including rooted-no-drive and
    /// device namespaces that are not safe fully-qualified filesystem roots.
    pub fn has_root(&self) -> bool {
        !matches!(
            self.root_class,
            RootClass::Relative | RootClass::DriveRelative
        )
    }

    /// Whether the path identifies a complete, ordinary absolute namespace.
    /// Device paths and Windows rooted-no-drive paths deliberately return false.
    pub fn is_fully_qualified(&self) -> bool {
        matches!(
            self.root_identity,
            RootIdentity::Posix
                | RootIdentity::DriveAbsolute(_)
                | RootIdentity::Unc { .. }
                | RootIdentity::VerbatimDrive(_)
                | RootIdentity::VerbatimUnc { .. }
        )
    }

    /// Component-safe lexical containment.
    ///
    /// Both paths must use the same dialect and exact root identity. Unresolved
    /// parent traversal, device paths, rooted-no-drive paths, drive-relative
    /// paths, and opaque verbatim namespaces fail closed.
    pub fn is_within(&self, base: &Self) -> bool {
        if self.dialect != base.dialect
            || !self.parent_state.is_clean()
            || !base.parent_state.is_clean()
            || self.root_identity != base.root_identity
        {
            return false;
        }

        match &self.root_identity {
            RootIdentity::Relative => {
                // An empty relative base (`""` or `.`) has no stable identity
                // and must not become an implicit universal root.
                if base.components.is_empty() {
                    return false;
                }
            }
            RootIdentity::Posix
            | RootIdentity::DriveAbsolute(_)
            | RootIdentity::Unc { .. }
            | RootIdentity::VerbatimDrive(_)
            | RootIdentity::VerbatimUnc { .. } => {}
            RootIdentity::DriveRelative(_)
            | RootIdentity::RootedNoDrive
            | RootIdentity::VerbatimOpaque(_)
            | RootIdentity::Device => return false,
        }

        base.components.len() <= self.components.len()
            && base
                .components
                .iter()
                .zip(&self.components)
                .all(|(base, path)| base == path)
    }
}

/// Conservative dialect detection for mixed-platform policy inputs.
///
/// A drive prefix, any backslash, or a double-slash namespace selects Windows.
/// A single leading `/` remains POSIX.
pub fn detect_dialect(input: &str) -> PathDialect {
    let bytes = input.as_bytes();
    if (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || input.contains('\\')
        || input.starts_with("//")
    {
        PathDialect::Windows
    } else {
        PathDialect::Posix
    }
}

/// Parse two mixed-platform paths and compare them conservatively.
///
/// The POSIX root sentinel `/` retains the custom-rule contract of matching any
/// clean, fully-qualified ordinary path, including Windows drive, UNC, and safe
/// verbatim absolute paths. No other cross-dialect containment is allowed.
pub fn is_within(path: &str, base: &str) -> bool {
    if path.is_empty() || base.is_empty() {
        return false;
    }
    let path_text = path;
    let base_text = base;
    let Ok(mut path) = LexicalPath::parse_auto(path) else {
        return false;
    };
    let Ok(mut base) = LexicalPath::parse_auto(base) else {
        return false;
    };

    // A separator-free relative input carries no dialect signal. When its peer
    // is explicitly Windows-relative (via backslashes), parse both with that
    // grammar rather than introducing an artificial cross-dialect mismatch.
    if path.dialect != base.dialect
        && path.root_class == RootClass::Relative
        && base.root_class == RootClass::Relative
    {
        let Ok(windows_path) = LexicalPath::parse(path_text, PathDialect::Windows) else {
            return false;
        };
        let Ok(windows_base) = LexicalPath::parse(base_text, PathDialect::Windows) else {
            return false;
        };
        path = windows_path;
        base = windows_base;
    }

    if base.root_class == RootClass::PosixRoot
        && base.components.is_empty()
        && base.parent_state.is_clean()
    {
        return path.parent_state.is_clean() && path.is_fully_qualified();
    }
    path.is_within(&base)
}

fn parse_posix(input: &str, preserve_parents: bool) -> LexicalPath {
    let rooted = input.starts_with('/');
    let (components, parent_state) = normalize_components(input, false, rooted, preserve_parents);
    LexicalPath {
        dialect: PathDialect::Posix,
        root_class: if rooted {
            RootClass::PosixRoot
        } else {
            RootClass::Relative
        },
        root_identity: if rooted {
            RootIdentity::Posix
        } else {
            RootIdentity::Relative
        },
        components,
        parent_state,
        parents_preserved: preserve_parents,
    }
}

fn parse_windows(input: &str, preserve_parents: bool) -> Result<LexicalPath, LexicalPathError> {
    let slashed = input.replace('\\', "/");

    if let Some(rest) = slashed.strip_prefix("//?/") {
        return parse_verbatim(rest, preserve_parents);
    }
    if let Some(rest) = slashed
        .strip_prefix("//./")
        .or_else(|| slashed.strip_prefix("/??/"))
        .or_else(|| slashed.strip_prefix("//??/"))
    {
        if rest.is_empty() {
            return Err(LexicalPathError::InvalidDeviceRoot);
        }
        let (components, parent_state) = normalize_components(rest, true, true, preserve_parents);
        return Ok(LexicalPath {
            dialect: PathDialect::Windows,
            root_class: RootClass::Device,
            root_identity: RootIdentity::Device,
            components,
            parent_state,
            parents_preserved: preserve_parents,
        });
    }
    if let Some(rest) = slashed.strip_prefix("//") {
        let (server, share, tail) = split_unc_root(rest)?;
        let (components, parent_state) = normalize_components(tail, true, true, preserve_parents);
        return Ok(LexicalPath {
            dialect: PathDialect::Windows,
            root_class: RootClass::Unc,
            root_identity: RootIdentity::Unc {
                server: ascii_fold(server),
                share: ascii_fold(share),
            },
            components,
            parent_state,
            parents_preserved: preserve_parents,
        });
    }

    let bytes = slashed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = bytes[0].to_ascii_lowercase();
        let absolute = bytes.get(2) == Some(&b'/');
        let tail = &slashed[2..];
        let (components, parent_state) =
            normalize_components(tail, true, absolute, preserve_parents);
        return Ok(LexicalPath {
            dialect: PathDialect::Windows,
            root_class: if absolute {
                RootClass::DriveAbsolute
            } else {
                RootClass::DriveRelative
            },
            root_identity: if absolute {
                RootIdentity::DriveAbsolute(drive)
            } else {
                RootIdentity::DriveRelative(drive)
            },
            components,
            parent_state,
            parents_preserved: preserve_parents,
        });
    }
    if let Some(stripped) = slashed.strip_prefix('/') {
        let (components, parent_state) =
            normalize_components(stripped, true, true, preserve_parents);
        return Ok(LexicalPath {
            dialect: PathDialect::Windows,
            root_class: RootClass::RootedNoDrive,
            root_identity: RootIdentity::RootedNoDrive,
            components,
            parent_state,
            parents_preserved: preserve_parents,
        });
    }

    let (components, parent_state) = normalize_components(&slashed, true, false, preserve_parents);
    Ok(LexicalPath {
        dialect: PathDialect::Windows,
        root_class: RootClass::Relative,
        root_identity: RootIdentity::Relative,
        components,
        parent_state,
        parents_preserved: preserve_parents,
    })
}

fn parse_verbatim(rest: &str, preserve_parents: bool) -> Result<LexicalPath, LexicalPathError> {
    if rest
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("UNC/"))
    {
        let (server, share, tail) = split_unc_root(&rest[4..])?;
        let (components, parent_state) = normalize_components(tail, true, true, preserve_parents);
        return Ok(LexicalPath {
            dialect: PathDialect::Windows,
            root_class: RootClass::Verbatim,
            root_identity: RootIdentity::VerbatimUnc {
                server: ascii_fold(server),
                share: ascii_fold(share),
            },
            components,
            parent_state,
            parents_preserved: preserve_parents,
        });
    }

    let bytes = rest.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        let (components, parent_state) =
            normalize_components(&rest[3..], true, true, preserve_parents);
        return Ok(LexicalPath {
            dialect: PathDialect::Windows,
            root_class: RootClass::Verbatim,
            root_identity: RootIdentity::VerbatimDrive(bytes[0].to_ascii_lowercase()),
            components,
            parent_state,
            parents_preserved: preserve_parents,
        });
    }
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(LexicalPathError::InvalidVerbatimRoot);
    }

    let (anchor, tail) = rest
        .split_once('/')
        .map_or((rest, ""), |(anchor, tail)| (anchor, tail));
    if anchor.is_empty() || matches!(anchor, "." | "..") {
        return Err(LexicalPathError::InvalidVerbatimRoot);
    }
    let (components, parent_state) = normalize_components(tail, true, true, preserve_parents);
    Ok(LexicalPath {
        dialect: PathDialect::Windows,
        root_class: RootClass::Verbatim,
        root_identity: RootIdentity::VerbatimOpaque(ascii_fold(anchor)),
        components,
        parent_state,
        parents_preserved: preserve_parents,
    })
}

fn split_unc_root(rest: &str) -> Result<(&str, &str, &str), LexicalPathError> {
    let Some(server_end) = rest.find('/') else {
        return Err(LexicalPathError::IncompleteUncRoot);
    };
    let server = &rest[..server_end];
    let after_server = &rest[server_end + 1..];
    let (share, tail) = after_server
        .split_once('/')
        .map_or((after_server, ""), |(share, tail)| (share, tail));
    if server.is_empty() || share.is_empty() {
        return Err(LexicalPathError::IncompleteUncRoot);
    }
    if !valid_unc_root_component(server) || !valid_unc_root_component(share) {
        return Err(LexicalPathError::InvalidUncRoot);
    }
    Ok((server, share, tail))
}

fn valid_unc_root_component(component: &str) -> bool {
    !matches!(component, "." | "..")
        && !component.ends_with(' ')
        && !component.ends_with('.')
        && !component
            .chars()
            .any(|character| character.is_control() || r#"<>:"|?*"#.contains(character))
}

fn normalize_components(
    input: &str,
    windows: bool,
    rooted: bool,
    preserve_parents: bool,
) -> (Vec<String>, ParentState) {
    let mut components = Vec::new();
    let mut parent_state = ParentState::default();
    let mut resolved_depth = 0usize;
    for component in input.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if resolved_depth == 0 {
                    if rooted {
                        parent_state.above_root = true;
                    } else {
                        parent_state.leading = parent_state.leading.saturating_add(1);
                    }
                } else {
                    resolved_depth -= 1;
                }
                if preserve_parents {
                    parent_state.unresolved = true;
                    components.push("..".to_string());
                } else if resolved_depth < components.len() {
                    components.pop();
                }
            }
            component => {
                resolved_depth = resolved_depth.saturating_add(1);
                components.push(if windows {
                    ascii_fold(component)
                } else {
                    component.to_string()
                });
            }
        }
    }
    (components, parent_state)
}

fn ascii_fold(value: &str) -> String {
    value
        .chars()
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(input: &str, dialect: PathDialect) -> LexicalPath {
        LexicalPath::parse(input, dialect).unwrap()
    }

    #[test]
    fn classifies_every_root_family() {
        for (input, dialect, class) in [
            ("a/b", PathDialect::Posix, RootClass::Relative),
            ("/a", PathDialect::Posix, RootClass::PosixRoot),
            ("C:rel", PathDialect::Windows, RootClass::DriveRelative),
            ("C:/abs", PathDialect::Windows, RootClass::DriveAbsolute),
            ("//server/share/x", PathDialect::Windows, RootClass::Unc),
            ("/rooted", PathDialect::Windows, RootClass::RootedNoDrive),
            ("//?/C:/verbatim", PathDialect::Windows, RootClass::Verbatim),
            ("//./COM1", PathDialect::Windows, RootClass::Device),
        ] {
            assert_eq!(parsed(input, dialect).root_class(), class, "{input}");
        }

        assert!(!parsed("C:rel", PathDialect::Windows).has_root());
        assert!(parsed("/rooted", PathDialect::Windows).has_root());
        assert!(!parsed("/rooted", PathDialect::Windows).is_fully_qualified());
        assert!(!parsed("//./COM1", PathDialect::Windows).is_fully_qualified());
        assert!(parsed("//server/share", PathDialect::Windows).is_fully_qualified());
    }

    #[test]
    fn normalizes_separators_dots_and_windows_ascii_case() {
        let posix = parsed("/A//b/./c/../d", PathDialect::Posix);
        assert_eq!(posix.components(), &["A", "b", "d"]);

        let windows = parsed(r"C:\Repo//A\.\B\..\File", PathDialect::Windows);
        assert_eq!(windows.components(), &["repo", "a", "file"]);
        assert_eq!(windows.root_class(), RootClass::DriveAbsolute);
    }

    #[test]
    fn retains_leading_and_above_root_parent_state() {
        let relative = parsed("a/../../../dist", PathDialect::Posix);
        assert_eq!(relative.components(), &["dist"]);
        assert_eq!(
            relative.parent_state(),
            ParentState {
                leading: 2,
                above_root: false,
                unresolved: false,
            }
        );

        let absolute = parsed("/../../safe", PathDialect::Posix);
        assert_eq!(absolute.components(), &["safe"]);
        assert_eq!(
            absolute.parent_state(),
            ParentState {
                leading: 0,
                above_root: true,
                unresolved: false,
            }
        );

        let drive_relative = parsed(r"C:..\x", PathDialect::Windows);
        assert_eq!(drive_relative.parent_state().leading, 1);
        let drive_absolute = parsed(r"C:\..\x", PathDialect::Windows);
        assert!(drive_absolute.parent_state().above_root);
    }

    #[test]
    fn unc_root_is_integral_and_cannot_be_popped() {
        for invalid in [
            "//server",
            "//server/",
            "//server//share",
            "//server/..",
            "//server./share",
            "//server/share?",
        ] {
            assert!(LexicalPath::parse(invalid, PathDialect::Windows).is_err());
        }

        let unc = parsed("//Server/Share/../x", PathDialect::Windows);
        assert_eq!(unc.root_class(), RootClass::Unc);
        assert!(unc.parent_state().above_root);
        assert_eq!(unc.components(), &["x"]);
    }

    #[test]
    fn component_containment_is_root_aware_and_fail_closed() {
        assert!(is_within("/repo/src", "/repo"));
        assert!(!is_within("/repo-other", "/repo"));
        assert!(!is_within("/Repo/src", "/repo"));

        assert!(is_within(r"c:\REPO\src", "C:/repo"));
        assert!(is_within(r"Repo\src", "repo"));
        assert!(!is_within(r"D:\repo\src", "C:/repo"));
        assert!(is_within(r"\\Server\Share\Dir", r"\\server\share"));
        assert!(!is_within(r"\\server\other\dir", r"\\server\share"));

        assert!(!is_within("../repo/src", "../repo"));
        assert!(!is_within("C:repo/src", "C:repo"));
        assert!(!is_within(r"\repo\src", r"\repo"));
        assert!(!is_within(r"\\.\C:\repo", r"\\.\C:\"));
    }

    #[test]
    fn root_sentinel_accepts_only_clean_fully_qualified_paths() {
        for absolute in ["/", "/x", "C:/", r"C:\x", r"\\server\share\x", r"\\?\C:\x"] {
            assert!(is_within(absolute, "/"), "{absolute}");
        }
        for unsafe_or_relative in [
            "",
            "relative",
            "C:",
            "C:relative",
            r"\rooted-no-drive",
            r"\\.\PhysicalDrive0",
            "/../../x",
        ] {
            assert!(!is_within(unsafe_or_relative, "/"), "{unsafe_or_relative}");
        }
    }

    #[test]
    fn safe_verbatim_roots_match_only_the_same_identity() {
        assert!(is_within(r"\\?\C:\Repo\src", r"\\?\c:\repo"));
        assert!(is_within(
            r"\\?\UNC\Server\Share\src",
            r"\\?\unc\server\share"
        ));
        assert!(!is_within(r"\\?\Volume{one}\src", r"\\?\Volume{one}"));
    }

    #[test]
    fn auto_detection_does_not_case_fold_posix_paths() {
        assert_eq!(detect_dialect("/Home/User"), PathDialect::Posix);
        assert_eq!(detect_dialect(r"C:\Home\User"), PathDialect::Windows);
        assert_eq!(detect_dialect(r"relative\windows"), PathDialect::Windows);
        assert!(!is_within("/Home/User", "/home"));
    }
}
