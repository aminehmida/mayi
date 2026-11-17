//! Finds the program a command runs, and the environment it runs in.
//!
//! An agent could put a program called `gh` in a folder of its own and put
//! that folder first in PATH, or set a variable that makes the real `gh` load
//! its code: the owner would then approve `gh pr list` and the secret would go
//! to the agent's program. So the program is looked up here, without the
//! working folder and temporary folders, run from the exact path found, and
//! that path is sent to the vault device to show. Variables that make
//! programs load or run other code are left out, as sudo does.
//!
//! This narrows what an agent can do; it does not stop one that can write to
//! a folder in PATH or to the program's own configuration. See the threat
//! model.

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use mayi_proto::program::{normalize, temporary};

/// Variables that make a program load or run other code: the dynamic
/// loaders', shells' and interpreters' start-up hooks, and the commands git
/// and similar tools run on their own.
const DROPPED: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "IFS",
    "CDPATH",
    "GLOBIGNORE",
    "ZDOTDIR",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONUSERBASE",
    "PERL5LIB",
    "PERLLIB",
    "PERL5OPT",
    "PERL5DB",
    "PERLIO_DEBUG",
    "RUBYLIB",
    "RUBYOPT",
    "NODE_OPTIONS",
    "NODE_PATH",
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_EXEC_PATH",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "GIT_EDITOR",
    "GH_PAGER",
    "GH_EDITOR",
    "GH_BROWSER",
    "PAGER",
    "EDITOR",
    "VISUAL",
    "BROWSER",
];

const DROPPED_PREFIXES: &[&str] = &["DYLD_", "LD_", "_RLD", "BASH_FUNC_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"];

/// Whether a variable of the agent's environment is left out of the command's.
pub fn dropped(key: &OsStr) -> bool {
    let Some(key) = key.to_str() else { return true };
    DROPPED.contains(&key) || DROPPED_PREFIXES.iter().any(|p| key.starts_with(p))
}

/// Where a program may have been put by the agent for this command: the
/// working folder (unless it is the home folder or above it, which hold the
/// usual tool folders) and temporary folders, the user's own included.
fn within_reach(dir: &Path, cwd: &Path) -> bool {
    let dir = normalize(dir);
    let home = std::env::var_os("HOME").map(|h| normalize(Path::new(&h)));
    let cwd_counts = home.as_deref().is_none_or(|home| !home.starts_with(cwd));
    (cwd_counts && dir.starts_with(cwd)) || temporary(&dir) || dir.starts_with(normalize(&std::env::temp_dir()))
}

/// PATH, or without one the folders the system looks in, as `execvp` does.
pub fn path_var() -> Option<OsString> {
    Some(std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/bin:/bin")))
}

/// The folders of `path` (PATH) to look programs up in: absolute ones only,
/// outside the agent's reach (see [`within_reach`]).
pub fn search_dirs(path: Option<&OsStr>, cwd: &Path) -> Vec<PathBuf> {
    let cwd = normalize(cwd);
    path.map(|p| std::env::split_paths(p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter(|dir| dir.is_absolute() && !within_reach(dir, &cwd))
        .collect()
}

/// PATH for the command: the same folders as the lookup.
pub fn search_path(dirs: &[PathBuf]) -> OsString {
    std::env::join_paths(dirs).unwrap_or_default()
}

fn executable(path: &Path) -> bool {
    path.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The absolute path `program` runs from. A name is looked up in `dirs`; a
/// path (anything with a `/`) is taken as given, relative to `cwd`.
/// Symbolic links are kept, so the path is the one a person would recognise.
pub fn locate(program: &str, cwd: &Path, dirs: &[PathBuf], path: Option<&OsStr>) -> Result<PathBuf, String> {
    if program.contains('/') {
        let found = normalize(&cwd.join(program));
        return if executable(&found) {
            Ok(found)
        } else {
            Err(format!("cannot run {program}: not an executable file"))
        };
    }
    if program.is_empty() {
        return Err("no command given".into());
    }
    if let Some(found) = dirs.iter().map(|dir| normalize(&dir.join(program))).find(|p| executable(p)) {
        return Ok(found);
    }
    // Only in a folder left out of the lookup: say so, and how to run it anyway.
    let skipped = path
        .map(|p| std::env::split_paths(p).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .map(|dir| dir.join(program))
        .find(|p| executable(p));
    Err(match skipped {
        Some(p) => format!(
            "{program} was found only at {}, in the working folder or a temporary folder, where mayi does \
             not look a program up; give its path to run it from there",
            p.display()
        ),
        None => format!("{program}: command not found"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tool(dir: &Path, name: &str) -> PathBuf {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, "#!/bin/sh\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn programs_in_the_agents_reach_are_not_looked_up() {
        let scratch = tempfile::tempdir().unwrap();
        // A temporary folder, as an agent could make one.
        tool(&scratch.path().join("bin"), "mayi-test-tool");
        let path = std::env::join_paths([scratch.path().join("bin"), PathBuf::from("/usr/bin"), PathBuf::from("bin")]).unwrap();
        let cwd = Path::new("/");
        let dirs = search_dirs(Some(&path), cwd);
        assert_eq!(dirs, vec![PathBuf::from("/usr/bin")]);
        let err = locate("mayi-test-tool", cwd, &dirs, Some(&path)).unwrap_err();
        assert!(err.contains("found only at") && err.contains("give its path"), "{err}");
        assert_eq!(locate("env", cwd, &dirs, Some(&path)).unwrap(), PathBuf::from("/usr/bin/env"));
        // Given by path, it runs from there.
        let given = scratch.path().join("bin/../bin/mayi-test-tool");
        assert_eq!(locate(given.to_str().unwrap(), cwd, &dirs, None).unwrap(), normalize(&given));
        assert!(locate("./nothing-here", cwd, &dirs, None).is_err());
    }

    #[test]
    fn the_working_folder_is_left_out_unless_it_holds_home() {
        let work = Path::new("/srv/project");
        assert!(within_reach(Path::new("/srv/project/node_modules/.bin"), work));
        assert!(!within_reach(Path::new("/usr/local/bin"), work));
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            assert!(!within_reach(&home.join(".local/bin"), &home));
            assert!(!within_reach(&home.join(".local/bin"), Path::new("/")));
        }
    }

    #[test]
    fn code_loading_variables_are_dropped() {
        for key in ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "BASH_ENV", "NODE_OPTIONS", "GIT_SSH_COMMAND", "BASH_FUNC_x%%"] {
            assert!(dropped(OsStr::new(key)), "{key}");
        }
        for key in ["HOME", "GH_TOKEN", "AWS_PROFILE", "KUBECONFIG", "LANG", "TERM"] {
            assert!(!dropped(OsStr::new(key)), "{key}");
        }
    }
}
