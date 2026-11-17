//! Where a command's program lives. The requester looks the program up
//! itself and runs it from the absolute path it found, which it sends as
//! [`crate::RunRequest::program`], so the vault device shows what will really
//! run rather than a name an agent could have given to a program of its own.

use std::path::{Component, Path, PathBuf};

/// Folders where any process, an agent included, may have just written a
/// program.
const TEMPORARY: &[&str] = &[
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
    "/dev/shm",
];

/// `path` with `.` and `..` resolved by name, as for a path without symbolic
/// links. A `..` above the root stays at the root.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => out.push(component),
            },
            other => out.push(other),
        }
    }
    out
}

/// Whether `path` is in a temporary folder.
pub fn temporary(path: &Path) -> bool {
    let path = normalize(path);
    TEMPORARY.iter().any(|folder| path.starts_with(folder))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_resolved_by_name() {
        assert_eq!(normalize(Path::new("/usr/local/../bin/./gh")), PathBuf::from("/usr/bin/gh"));
        assert_eq!(normalize(Path::new("/../tmp")), PathBuf::from("/tmp"));
    }

    #[test]
    fn temporary_folders() {
        assert!(temporary(Path::new("/tmp/x/gh")));
        assert!(temporary(Path::new("/private/var/folders/ab/T/gh")));
        assert!(temporary(Path::new("/usr/bin/../../tmp/gh")));
        assert!(!temporary(Path::new("/opt/homebrew/bin/gh")));
        assert!(!temporary(Path::new("/tmpfoo/gh")));
    }
}
