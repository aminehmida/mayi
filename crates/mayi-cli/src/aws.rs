//! `mayi aws`: AWS sign-ins held by a vault device, for the AWS CLI,
//! Terraform and the SDKs.
//!
//! `mayi aws setup` writes AWS CLI profiles whose `credential_process` is
//! `mayi aws credentials NAME/PROFILE`. The AWS CLI then runs that for each
//! command; the vault device decides by the profile's level, showing the
//! owner the AWS command that asked, and only that role's temporary
//! credentials come back. The sign-in itself never leaves the device.

use std::path::Path;

use mayi_proto::awscli::{self, Profile};
use mayi_proto::{write_frame, Binding, ClientMsg, RunRequest, ServerMsg};

use crate::{reach, session, Failure, Patience, EXIT_DENIED, EXIT_UNAVAILABLE, EXIT_USAGE};

/// What `credential_process` must print, keyed by the binding that fetches it.
const OUTPUT: [(&str, &str); 4] = [
    ("AccessKeyId", "access_key_id"),
    ("SecretAccessKey", "secret_access_key"),
    ("SessionToken", "session_token"),
    ("Expiration", "expiration"),
];

/// `NAME/PROFILE`, as requests name an AWS sign-in's profile.
pub fn split_target(target: &str) -> Result<(&str, &str), Failure> {
    match target.split_once('/') {
        Some((name, profile)) if !name.is_empty() && !profile.is_empty() && !profile.contains('/') => {
            Ok((name, profile))
        }
        _ => Err((EXIT_USAGE, format!("{target:?}: expected NAME/PROFILE, as `mayi list` shows it"))),
    }
}

/// The bindings `mayi run --aws NAME/PROFILE` adds.
pub fn bindings(target: &str) -> Result<Vec<Binding>, Failure> {
    let (name, profile) = split_target(target)?;
    Ok([
        ("AWS_ACCESS_KEY_ID", "access_key_id"),
        ("AWS_SECRET_ACCESS_KEY", "secret_access_key"),
        ("AWS_SESSION_TOKEN", "session_token"),
    ]
    .iter()
    .map(|(env, field)| Binding { env: env.to_string(), item: name.into(), field: format!("{profile}/{field}") })
    .collect())
}

/// Settings that would make the AWS CLI ignore the credentials `mayi run
/// --aws` gives it: an explicitly chosen profile wins over them.
pub const OVERRIDING: [&str; 2] = ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"];

/// The command to show for a tool run by an interpreter (Homebrew's AWS CLI
/// runs as `Python /opt/homebrew/bin/aws …`): the script and its arguments.
fn readable(argv: Vec<String>, program: Option<String>) -> (Vec<String>, Option<String>) {
    let interpreter = |path: &str| {
        let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        name.starts_with("python") || matches!(name.as_str(), "node" | "ruby" | "perl")
    };
    match argv.get(1) {
        Some(script) if interpreter(&argv[0]) && script.starts_with('/') => {
            let script = script.clone();
            (argv[1..].to_vec(), Some(script))
        }
        _ => (argv, program),
    }
}

fn json_string(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

/// `mayi aws credentials NAME/PROFILE`: asks the vault device and prints the
/// credentials as `credential_process` wants them.
pub fn credentials(target: &str, patience: Patience, remote: bool) -> Result<u8, Failure> {
    let (name, profile) = split_target(target)?;
    let caller = session::caller();
    // The owner is shown the AWS command that asked, not this one.
    let argv = caller
        .tool
        .as_ref()
        .and_then(|t| session::arguments(t.pid))
        .unwrap_or_else(|| vec!["(a program that did not say)".into()]);
    let program = caller.tool.as_ref().and_then(|t| session::program_path(t.pid));
    let (argv, program) = readable(argv, program);
    let request = RunRequest {
        bindings: OUTPUT
            .iter()
            .map(|(key, field)| Binding { env: key.to_string(), item: name.into(), field: format!("{profile}/{field}") })
            .collect(),
        argv,
        cwd: std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        reason: format!("AWS profile {name}/{profile}, for this command"),
        agent: std::env::var("MAYI_AGENT").ok().or(caller.agent).unwrap_or_else(|| "unknown".into()),
        session: std::env::var("MAYI_SESSION").ok().unwrap_or(caller.session),
        host: crate::hostname(),
        site: None,
        program,
    };
    let reach::Answer { reply, mut writer, .. } = reach::ask(&request, remote, patience.wait, patience.timeout)?;
    let env = match reply {
        ServerMsg::Released { env, .. } => env,
        ServerMsg::Denied { reason } => return Err((EXIT_DENIED, format!("denied: {reason}"))),
        _ => return Err((EXIT_UNAVAILABLE, "unexpected reply from the vault device".into())),
    };
    let fields: Vec<String> = OUTPUT
        .iter()
        .map(|(key, _)| format!("{}:{}", json_string(key), json_string(env.get(*key).map(String::as_str).unwrap_or(""))))
        .collect();
    println!("{{\"Version\":1,{}}}", fields.join(","));
    // Nothing runs under Mayi: the AWS command is already running.
    let _ = write_frame(&mut writer, &ClientMsg::Done { exit: Some(0) });
    Ok(0)
}

/// This `mayi`, by a path that survives upgrades.
fn mayi_path() -> String {
    let exe = std::env::current_exe().unwrap_or_else(|_| "mayi".into());
    let text = exe.to_string_lossy().into_owned();
    // A Homebrew formula lives under a versioned folder; its link does not.
    if text.contains("/Cellar/") {
        for link in ["/opt/homebrew/bin/mayi", "/usr/local/bin/mayi", "/home/linuxbrew/.linuxbrew/bin/mayi"] {
            if Path::new(link).exists() {
                return link.into();
            }
        }
    }
    text
}

/// `mayi aws setup`: an AWS CLI profile for every profile of every AWS
/// sign-in, and the AWS CLI's own saved sign-ins to those portals removed.
pub fn setup(remote: bool, keep_cli_sign_ins: bool) -> Result<u8, Failure> {
    let secrets = crate::secrets(remote)?;
    let mayi = mayi_path();
    let mut profiles = Vec::new();
    let mut portals = Vec::new();
    for s in &secrets {
        let Some(aws) = &s.aws else { continue };
        portals.push(aws.start_url.clone());
        for p in &aws.profiles {
            profiles.push((
                Profile {
                    name: format!("{}-{}", s.name, p.name),
                    command: awscli::credentials_command(&mayi, &s.name, &p.name),
                    region: aws.region.clone(),
                },
                p.level,
            ));
        }
    }
    if profiles.is_empty() {
        println!("No AWS sign-ins in Mayi yet: add one in the app (Secrets, Add, AWS).");
        return Ok(0);
    }
    let only: Vec<Profile> = profiles.iter().map(|(p, _)| p.clone()).collect();
    let written = awscli::write_profiles(&only).map_err(|e| (EXIT_UNAVAILABLE, format!("cannot write the AWS CLI config: {e}")))?;
    println!("AWS CLI profiles in {}:", written.path.display());
    for (p, level) in &profiles {
        if written.written.contains(&p.name) {
            println!("  {}\tlevel {level}", p.name);
        }
    }
    for name in &written.skipped {
        println!("  {name}\tnot written: a profile of yours already has this name");
    }
    if !keep_cli_sign_ins {
        for url in &portals {
            match awscli::forget_sign_ins(url) {
                Ok(0) => {}
                Ok(n) => println!("Removed {n} file(s) where the AWS CLI kept a sign-in to {url}: any program could read them."),
                Err(e) => eprintln!("mayi: could not remove the AWS CLI's saved sign-ins to {url}: {e}"),
            }
        }
    }
    if let Some((first, _)) = profiles.first() {
        println!("Try: aws sts get-caller-identity --profile {}", first.name);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_script_is_shown_rather_than_its_interpreter() {
        let python = "/opt/homebrew/Cellar/python@3.14/3.14.4_1/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python";
        let argv: Vec<String> = [python, "/opt/homebrew/bin/aws", "s3", "ls"].iter().map(|s| s.to_string()).collect();
        let (shown, program) = readable(argv, Some(python.into()));
        assert_eq!(shown, ["/opt/homebrew/bin/aws", "s3", "ls"]);
        assert_eq!(program.as_deref(), Some("/opt/homebrew/bin/aws"));
        let native: Vec<String> = ["aws", "s3", "ls"].iter().map(|s| s.to_string()).collect();
        assert_eq!(readable(native.clone(), Some("/usr/local/bin/aws".into())), (native, Some("/usr/local/bin/aws".into())));
    }

    #[test]
    fn targets_and_bindings() {
        assert_eq!(split_target("mawaqit/production-ro").unwrap(), ("mawaqit", "production-ro"));
        for bad in ["mawaqit", "/ro", "mawaqit/", "a/b/c"] {
            assert!(split_target(bad).is_err(), "{bad}");
        }
        let b = bindings("mawaqit/production-ro").unwrap();
        assert_eq!(b.len(), 3);
        assert_eq!(b[0], Binding { env: "AWS_ACCESS_KEY_ID".into(), item: "mawaqit".into(), field: "production-ro/access_key_id".into() });
    }
}
