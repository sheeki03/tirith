//! Policy discovery must distinguish named entries from virtual filesystems
//! which synthesize directories for arbitrary lookups (for example kio-fuse).

use std::path::Path;

// Discovery runs on every intercepted command. A huge or unreadable listing
// is inconclusive, never evidence that a policy can safely be ignored.
const MAX_DISCOVERY_ENTRIES: usize = 4096;

pub(crate) fn entry_exists(path: &Path, follow: bool) -> bool {
    let metadata = if follow {
        std::fs::metadata(path)
    } else {
        std::fs::symlink_metadata(path)
    }
    .map(|metadata| metadata.is_dir());
    #[cfg(all(test, not(windows)))]
    let metadata = DIRECTORY_LOOKUPS.with(|root| {
        if root
            .borrow()
            .as_ref()
            .is_some_and(|root| path.starts_with(root))
        {
            Ok(true)
        } else {
            metadata
        }
    });
    // Preserve marker/allowlist lookup semantics: an inaccessible or broken
    // `.git` is not a new boundary which could hide an ancestor policy.
    if follow && metadata.is_err() {
        return false;
    }
    // Win32 lookup may resolve an arbitrary 8.3 alternate name which read_dir
    // does not expose. Preserve its existing directory behavior rather than
    // risking absence based only on long names. kio-fuse is a Unix filesystem.
    #[cfg(windows)]
    if matches!(&metadata, Ok(true)) {
        return true;
    }
    entry_exists_with(path, metadata, listed_entry)
}

fn entry_exists_with(
    path: &Path,
    metadata: std::io::Result<bool>,
    mut listed: impl FnMut(&Path) -> Option<bool>,
) -> bool {
    match metadata {
        // Keep named files, symlinks (including dangling ones), FIFOs, etc.
        // Their safety and readability belong to the existing scoped reader.
        Ok(false) => true,
        Ok(true) => match listed(path) {
            Some(present) => present,
            // A synthetic `.tirith/` may not itself be enumerable. Its absence
            // in the real parent listing also disproves the policy candidate.
            None => path.parent().and_then(listed) != Some(false),
        },
        Err(error) => !matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        ),
    }
}

/// None means enumeration failed or exceeded its bound. Only a complete,
/// successful listing can prove absence; an actual directory policy still
/// reaches the reader and fails closed as a non-regular file.
fn listed_entry(path: &Path) -> Option<bool> {
    let name = path.file_name()?;
    let parent = path.parent()?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let entries = std::fs::read_dir(parent).ok()?;
    listed_name(
        name,
        entries.map(|entry| entry.map(|entry| entry.file_name())),
    )
}

fn listed_name(
    name: &std::ffi::OsStr,
    entries: impl Iterator<Item = std::io::Result<std::ffi::OsString>>,
) -> Option<bool> {
    // All automatic policy/marker names are ASCII. An unfamiliar parent
    // name may have filesystem-specific normalization, so do not use it to
    // prove absence when the candidate's own listing was inconclusive.
    if !name.as_encoded_bytes().is_ascii() {
        return None;
    }
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DISCOVERY_ENTRIES {
            return None;
        }
        if names_may_alias(name, &entry.ok()?) {
            return Some(true);
        }
    }
    Some(false)
}

// Filesystem lookup can fold case, normalize Unicode, ignore format characters,
// or trim trailing ASCII dots/spaces. Over-admitting a possible alias retains
// the scoped reader's fail-closed behavior; under-admitting one could skip a
// real directory policy. Normalize only the listed name, never the read path.
fn names_may_alias(name: &std::ffi::OsStr, entry: &std::ffi::OsStr) -> bool {
    use unicode_normalization::UnicodeNormalization;
    let Some(entry) = entry.to_str() else {
        return false;
    };
    let matches = |entry: &str| {
        entry
            .trim_end_matches(['.', ' '])
            .as_bytes()
            .eq_ignore_ascii_case(name.as_encoded_bytes())
    };
    if entry.is_ascii() {
        return matches(entry);
    }
    static IGNORABLE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"\p{Default_Ignorable_Code_Point}")
            .expect("valid Unicode property for filesystem aliases")
    });
    let folded: String = entry.nfkc().flat_map(char::to_uppercase).collect();
    matches(&IGNORABLE.replace_all(&folded, ""))
}

#[cfg(all(test, not(windows)))]
thread_local! {
    static DIRECTORY_LOOKUPS: std::cell::RefCell<Option<std::path::PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Model the reported virtual filesystem's stat behavior while retaining real
/// directory listings. Scoped to this thread; never compiled into production.
#[cfg(all(test, not(windows)))]
pub(crate) fn with_directory_lookups<T>(root: &Path, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<std::path::PathBuf>);
    impl Drop for Restore {
        fn drop(&mut self) {
            DIRECTORY_LOOKUPS.with(|root| *root.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(DIRECTORY_LOOKUPS.with(|value| value.replace(Some(root.into()))));
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::io::{Error, ErrorKind};

    #[test]
    fn directory_shaped_candidate_requires_an_actual_name() {
        let path = Path::new("repo/.tirith/policy.yaml");
        assert!(!entry_exists_with(path, Ok(true), |_| Some(false)));
        assert!(entry_exists_with(path, Ok(true), |_| Some(true)));
        assert!(entry_exists_with(path, Ok(true), |_| None));
    }

    #[test]
    fn unenumerable_phantom_parent_must_be_proven_absent() {
        let path = Path::new("repo/.tirith/policy.yaml");
        for parent in [Some(true), None, Some(false)] {
            let present = entry_exists_with(path, Ok(true), |candidate| {
                if candidate == path {
                    None
                } else {
                    parent
                }
            });
            assert_eq!(present, parent != Some(false));
        }
    }

    #[test]
    fn files_and_symlinks_are_never_rejected_by_enumeration() {
        assert!(entry_exists_with(
            Path::new("policy.yaml"),
            Ok(false),
            |_| { panic!("must preserve non-directory entries without enumeration") }
        ));
    }

    #[test]
    fn metadata_errors_are_not_silently_downgraded_to_absence() {
        for kind in [ErrorKind::PermissionDenied, ErrorKind::Other] {
            assert!(entry_exists_with(
                Path::new("policy.yaml"),
                Err(Error::from(kind)),
                |_| None
            ));
        }
        for kind in [ErrorKind::NotFound, ErrorKind::NotADirectory] {
            assert!(!entry_exists_with(
                Path::new("policy.yaml"),
                Err(Error::from(kind)),
                |_| None
            ));
        }
    }

    #[test]
    fn filesystem_name_aliases_do_not_hide_real_directory_policies() {
        for alias in [
            "POLICY.YAML",
            "polıcy.yaml",
            "pol\u{200d}icy.yaml",
            "ｐｏｌｉｃｙ.yaml",
            "policy.yaml. ",
        ] {
            assert!(
                names_may_alias(OsStr::new("policy.yaml"), OsStr::new(alias)),
                "{alias}"
            );
        }
        assert!(names_may_alias(
            OsStr::new("allowlist"),
            OsStr::new("allowliſt")
        ));
        for unrelated in ["résultat", "結果", "policy.yaml.backup"] {
            assert!(!names_may_alias(
                OsStr::new("policy.yaml"),
                OsStr::new(unrelated)
            ));
        }
    }

    #[test]
    fn enumeration_is_exact_bounded_and_errors_are_inconclusive() {
        let name = OsStr::new(".git");
        assert_eq!(
            listed_name(
                name,
                [Ok(OsString::from("résultat")), Ok(OsString::from("結果"))].into_iter()
            ),
            Some(false)
        );
        assert_eq!(
            listed_name(name, [Ok(OsString::from(".GIT"))].into_iter()),
            Some(true)
        );
        assert_eq!(listed_name(OsStr::new("répo"), std::iter::empty()), None);
        assert_eq!(
            listed_name(name, [Ok(OsString::from(".git-other"))].into_iter()),
            Some(false)
        );
        assert_eq!(
            listed_name(name, [Ok(OsString::from(".git"))].into_iter()),
            Some(true)
        );
        assert_eq!(
            listed_name(
                name,
                [Err(Error::from(ErrorKind::PermissionDenied))].into_iter()
            ),
            None
        );
        assert_eq!(
            listed_name(name, (0..MAX_DISCOVERY_ENTRIES).map(|_| Ok("other".into()))),
            Some(false)
        );
        assert_eq!(
            listed_name(
                name,
                (0..=MAX_DISCOVERY_ENTRIES).map(|_| Ok("other".into()))
            ),
            None
        );
    }
}
