//! The AWS CLI's files: the portals it already knows (to suggest when
//! adding an AWS sign-in to Mayi), the sign-ins it keeps in plain files
//! (which any program, agents included, can read, so Mayi removes them once
//! it holds the sign-in), and the profiles Mayi adds so that `aws --profile`,
//! Terraform and the SDKs get their credentials from Mayi.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The lines around the profiles Mayi writes. Mayi rewrites what is
/// between them and leaves the rest of the file alone.
const BEGIN: &str = "# >>> Mayi: profiles for your AWS sign-ins in Mayi (Mayi rewrites this part)";
const END: &str = "# <<< Mayi";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Portal {
    pub start_url: String,
    pub region: String,
}

/// One AWS CLI profile backed by Mayi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The AWS CLI profile name, such as `mawaqit-production-ro`.
    pub name: String,
    /// What the AWS CLI runs for credentials.
    pub command: String,
    pub region: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Written {
    pub path: PathBuf,
    pub written: Vec<String>,
    /// Names already used by a profile of your own, left as they are.
    pub skipped: Vec<String>,
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

/// `~/.aws`, or where `AWS_CONFIG_FILE` points.
pub fn config_path() -> Option<PathBuf> {
    match std::env::var_os("AWS_CONFIG_FILE").filter(|p| !p.is_empty()) {
        Some(p) => Some(PathBuf::from(p)),
        None => home().map(|h| h.join(".aws").join("config")),
    }
}

fn cache_dir(kind: &str) -> Option<PathBuf> {
    home().map(|h| h.join(".aws").join(kind).join("cache"))
}

/// A start URL as AWS compares them: without the browser's `#/` or a
/// trailing slash.
pub fn normalize_start_url(url: &str) -> String {
    let url = url.trim();
    url.split('#').next().unwrap_or(url).trim_end_matches('/').to_string()
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else { return vec![] };
    entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect()
}

/// The `startUrl` and `region` of a cached AWS CLI sign-in, if it is one.
fn cached_portal(path: &Path) -> Option<Portal> {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    Some(Portal {
        start_url: normalize_start_url(value["startUrl"].as_str()?),
        region: value["region"].as_str()?.to_string(),
    })
}

/// `[section]` headers and `key = value` lines of an INI file.
fn sections(text: &str) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push((name.trim().to_string(), vec![]));
        } else if let (Some((key, value)), Some(last)) = (line.split_once('='), out.last_mut()) {
            if !line.starts_with('#') && !line.starts_with(';') {
                last.1.push((key.trim().to_string(), value.trim().to_string()));
            }
        }
    }
    out
}

/// Portals the AWS CLI knows on this machine, from its config and its
/// cached sign-ins, to suggest when adding one to Mayi.
pub fn portals() -> Vec<Portal> {
    let mut found = BTreeSet::new();
    if let Some(text) = config_path().and_then(|p| fs::read_to_string(p).ok()) {
        found.extend(config_portals(&text));
    }
    if let Some(dir) = cache_dir("sso") {
        found.extend(json_files(&dir).iter().filter_map(|p| cached_portal(p)));
    }
    found.into_iter().collect()
}

fn config_portals(text: &str) -> Vec<Portal> {
    sections(text)
        .into_iter()
        .filter_map(|(_, keys)| {
            let get = |k: &str| keys.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
            Some(Portal { start_url: normalize_start_url(&get("sso_start_url")?), region: get("sso_region")? })
        })
        .collect()
}

/// Removes the AWS CLI's cached sign-ins to `start_url`, and the role
/// credentials it cached (which say not which portal they came from).
/// Returns how many files went.
pub fn forget_sign_ins(start_url: &str) -> io::Result<usize> {
    let wanted = normalize_start_url(start_url);
    let mut removed = 0;
    if let Some(dir) = cache_dir("sso") {
        for path in json_files(&dir) {
            if cached_portal(&path).is_some_and(|p| p.start_url == wanted) {
                fs::remove_file(&path)?;
                removed += 1;
            }
        }
    }
    if let Some(dir) = cache_dir("cli") {
        for path in json_files(&dir) {
            fs::remove_file(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Whether the AWS CLI holds a sign-in to `start_url` in a plain file again
/// (someone ran `aws sso login`).
pub fn has_cached_sign_in(start_url: &str) -> bool {
    let wanted = normalize_start_url(start_url);
    cache_dir("sso").is_some_and(|dir| json_files(&dir).iter().any(|p| cached_portal(p).is_some_and(|c| c.start_url == wanted)))
}

/// A shell word for the AWS CLI, which splits `credential_process` like a
/// shell.
fn quote(word: &str) -> String {
    if !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "/._-+=:@,".contains(c)) {
        word.to_string()
    } else {
        format!("\"{}\"", word.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// The `credential_process` line for a profile: `mayi aws credentials`.
pub fn credentials_command(mayi: &str, sign_in: &str, profile: &str) -> String {
    format!("{} aws credentials {}", quote(mayi), quote(&format!("{sign_in}/{profile}")))
}

/// `existing` with Mayi's part replaced by `profiles`, skipping names a
/// profile outside Mayi's part already uses.
pub fn render(existing: &str, profiles: &[Profile]) -> (String, Vec<String>, Vec<String>) {
    let mut kept = Vec::new();
    let mut inside = false;
    for line in existing.lines() {
        match line.trim() {
            l if l == BEGIN => inside = true,
            l if l == END => inside = false,
            _ if inside => {}
            _ => kept.push(line),
        }
    }
    let theirs: BTreeSet<String> = sections(&kept.join("\n"))
        .into_iter()
        .filter_map(|(name, _)| name.strip_prefix("profile ").map(|n| n.trim().to_string()).or(Some(name)))
        .collect();
    let mut text = kept.join("\n").trim_end().to_string();
    let (mut written, mut skipped) = (Vec::new(), Vec::new());
    let mut block = String::new();
    for p in profiles {
        if theirs.contains(&p.name) {
            skipped.push(p.name.clone());
            continue;
        }
        block.push_str(&format!("\n[profile {}]\ncredential_process = {}\nregion = {}\n", p.name, p.command, p.region));
        written.push(p.name.clone());
    }
    if !written.is_empty() {
        if !text.is_empty() {
            text.push_str("\n\n");
        }
        text.push_str(BEGIN);
        text.push('\n');
        text.push_str(block.trim_start_matches('\n'));
        text.push_str(END);
    }
    if !text.is_empty() {
        text.push('\n');
    }
    (text, written, skipped)
}

/// Writes `profiles` into the AWS CLI config, replacing what Mayi wrote
/// before.
pub fn write_profiles(profiles: &[Profile]) -> io::Result<Written> {
    let path = config_path().ok_or_else(|| io::Error::other("no home folder"))?;
    let existing = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let (text, written, skipped) = render(&existing, profiles);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let temp = path.with_extension("mayi-tmp");
    fs::write(&temp, text)?;
    fs::rename(&temp, &path)?;
    Ok(Written { path, written, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str) -> Profile {
        Profile {
            name: name.into(),
            command: credentials_command("/opt/homebrew/bin/mayi", "mawaqit", name.trim_start_matches("mawaqit-")),
            region: "eu-west-3".into(),
        }
    }

    #[test]
    fn profiles_are_added_once_and_replaced_later() {
        let mine = "[default]\nregion = eu-west-1\n\n[profile mawaqit-production-ro]\nregion = us-east-1\n";
        let (text, written, skipped) = render(mine, &[profile("mawaqit-production-ro"), profile("mawaqit-production-admin")]);
        assert_eq!(written, ["mawaqit-production-admin"]);
        assert_eq!(skipped, ["mawaqit-production-ro"], "a profile of the owner's is left alone");
        assert!(text.starts_with(mine.trim_end()));
        assert!(text.contains(
            "[profile mawaqit-production-admin]\ncredential_process = /opt/homebrew/bin/mayi aws credentials mawaqit/production-admin\nregion = eu-west-3\n"
        ));

        // Written again with other profiles: Mayi's part is replaced, not added to.
        let (again, written, _) = render(&text, &[profile("mawaqit-development-admin")]);
        assert_eq!(written, ["mawaqit-development-admin"]);
        assert!(!again.contains("production-admin"));
        assert_eq!(again.matches(BEGIN).count(), 1);
        // And with none, Mayi's part goes away entirely.
        let (empty, _, _) = render(&again, &[]);
        assert_eq!(empty.trim_end(), mine.trim_end());
    }

    #[test]
    fn portals_are_read_from_the_config() {
        let config = "[profile a]\nsso_start_url = https://mawaqit.awsapps.com/start/#/\nsso_region = eu-west-3\n\
                      [sso-session stint]\nsso_start_url = https://stint.awsapps.com/start\nsso_region = eu-west-1\n\
                      [profile plain]\nregion = eu-west-1\n";
        assert_eq!(
            config_portals(config),
            [
                Portal { start_url: "https://mawaqit.awsapps.com/start".into(), region: "eu-west-3".into() },
                Portal { start_url: "https://stint.awsapps.com/start".into(), region: "eu-west-1".into() },
            ]
        );
    }

    #[test]
    fn commands_are_quoted_for_the_aws_cli() {
        assert_eq!(
            credentials_command("/Applications/My Apps/mayi", "a", "b"),
            "\"/Applications/My Apps/mayi\" aws credentials a/b"
        );
    }
}
