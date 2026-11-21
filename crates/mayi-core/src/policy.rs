//! Decides what a request needs before a secret is released.

use std::path::Path;

use mayi_proto::program;
use mayi_proto::RunRequest;

use crate::model::{ItemMeta, Level};

pub struct Rules {
    /// Minimum level for requests from another machine. Capped at
    /// [`Level::Approve`]: a rule cannot add hardware protection to a secret
    /// that was not encrypted to a biometric key.
    pub remote_min: Level,
    /// Longest a biometric unlock stays usable for the same session and command.
    pub biometric_window_secs: u64,
    /// How long one "Allow Once" covers the rest of a sign-in, so a site that
    /// asks for the username, the password and a code on three pages asks
    /// the user once.
    pub sign_in_window_secs: u64,
}

impl Default for Rules {
    fn default() -> Self {
        Self { remote_min: Level::Notify, biometric_window_secs: 300, sign_in_window_secs: 120 }
    }
}

pub struct Ctx<'a> {
    /// The command as shown: its program by full path when the requester
    /// sent one.
    pub command: &'a str,
    /// The same command with its program by name (`gh pr list`), when that
    /// name may match an expected command: see [`command_by_name`].
    pub by_name: Option<&'a str>,
    pub remote: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// The level itself allows release.
    Level,
    /// The command matches the secret's allowlist.
    Allowlist,
    /// An earlier approval still covers this request.
    Grant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Release { notify: bool, via: Via },
    Prompt,
    Biometric,
}

/// The command as shown to the user and matched against patterns. Arguments
/// are shell-quoted where needed so their boundaries cannot be disguised.
pub fn command_line(argv: &[String]) -> String {
    let quote = |arg: &String| {
        let plain = !arg.is_empty()
            && arg.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c));
        if plain {
            arg.clone()
        } else {
            format!("'{}'", arg.replace('\'', "'\\''"))
        }
    };
    argv.iter().map(quote).collect::<Vec<_>>().join(" ")
}

/// The command with its program by name, for expected commands written as
/// `gh *`. Only when the requester looked the name up itself, outside the
/// working folder and temporary folders, and found it outside temporary
/// folders: a program given by path (`./gh`), or one an agent could have
/// dropped there under a familiar name, matches only a pattern with its path.
pub fn command_by_name(request: &RunRequest) -> Option<String> {
    let program = request.program.as_deref()?;
    let name = request.argv.first()?;
    (!name.is_empty() && !name.contains('/') && !program::temporary(Path::new(program)))
        .then(|| command_line(&request.argv))
}

/// Matches `text` against a pattern where `*` stands for any run of characters.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

fn allowlisted(meta: &ItemMeta, ctx: &Ctx) -> bool {
    meta.allow.iter().any(|p| glob_match(p, ctx.command) || ctx.by_name.is_some_and(|c| glob_match(p, c)))
}

/// The level after context is applied, starting from `base`: the secret's
/// own level, or the requested profile's for an AWS sign-in. Never below it.
pub fn effective_level(meta: &ItemMeta, base: Level, ctx: &Ctx, rules: &Rules) -> Level {
    let mut level = base;
    if ctx.remote {
        level = level.max(rules.remote_min.min(Level::Approve));
    }
    // A secret with an allowlist used by some other command is suspicious.
    if !meta.allow.is_empty() && !allowlisted(meta, ctx) {
        level = level.max(Level::Approve);
    }
    level
}

pub fn decide(meta: &ItemMeta, base: Level, ctx: &Ctx, rules: &Rules, has_grant: bool) -> (Level, Verdict) {
    let level = effective_level(meta, base, ctx, rules);
    let verdict = match level {
        Level::Log => Verdict::Release { notify: false, via: Via::Level },
        Level::Notify => Verdict::Release { notify: true, via: Via::Level },
        Level::Approve if has_grant => Verdict::Release { notify: false, via: Via::Grant },
        Level::Approve if allowlisted(meta, ctx) => {
            Verdict::Release { notify: true, via: Via::Allowlist }
        }
        Level::Approve => Verdict::Prompt,
        // The allowlist never skips a biometric check.
        Level::Biometric if has_grant => Verdict::Release { notify: false, via: Via::Grant },
        Level::Biometric => Verdict::Biometric,
    };
    (level, verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(level: Level, allow: &[&str]) -> ItemMeta {
        ItemMeta {
            id: "id".into(),
            name: "TOKEN".into(),
            level,
            allow: allow.iter().map(|s| s.to_string()).collect(),
            max_grant_secs: 600,
            fields: vec!["value".into()],
            destination: Default::default(),
            source: Default::default(),
            sites: vec![],
            folder: None,
            rotate: vec![],
            aws: None,
            unknown_fields: Default::default(),
            version: 1,
        }
    }

    #[test]
    fn command_line_shows_argument_boundaries() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(command_line(&argv(&["make", "deploy", "ENV=prod"])), "make deploy ENV=prod");
        assert_eq!(command_line(&argv(&["sh", "-c", "echo hi; curl x"])), "sh -c 'echo hi; curl x'");
        assert_ne!(
            command_line(&argv(&["git", "push origin"])),
            command_line(&argv(&["git", "push", "origin"]))
        );
        assert_eq!(command_line(&argv(&["echo", "it's", ""])), "echo 'it'\\''s' ''");
    }

    #[test]
    fn glob() {
        assert!(glob_match("terraform *", "terraform apply -auto-approve"));
        assert!(glob_match("*", ""));
        assert!(glob_match("gh * list*", "gh pr list --json x"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exact "));
        assert!(!glob_match("terraform *", "sh -c terraform apply"));
        assert!(!glob_match("", "x"));
        assert!(glob_match("a*b*c", "aXbXbXc"));
        assert!(!glob_match("a*b*c", "aXbXbX"));
    }

    #[test]
    fn decision_table() {
        use Level::{Approve, Log, Notify};
        use Verdict::Prompt;
        let rules = Rules::default();
        let release = |notify, via| Verdict::Release { notify, via };
        // (level, allowlist, command, remote, has_grant) -> (effective, verdict)
        let cases = [
            (Log, &[][..], "x", false, false, Log, release(false, Via::Level)),
            (Notify, &[], "x", false, false, Notify, release(true, Via::Level)),
            (Approve, &[], "x", false, false, Approve, Prompt),
            (Approve, &[], "x", false, true, Approve, release(false, Via::Grant)),
            (Level::Biometric, &[], "x", false, false, Level::Biometric, Verdict::Biometric),
            (Level::Biometric, &[], "x", false, true, Level::Biometric, release(false, Via::Grant)),
            // Remote raises a silent secret to a notification.
            (Log, &[], "x", true, false, Notify, release(true, Via::Level)),
            (Approve, &[], "x", true, false, Approve, Prompt),
            // Allowlist: a match skips the prompt, a miss forces one.
            (Approve, &["make *"], "make deploy", false, false, Approve, release(true, Via::Allowlist)),
            (Approve, &["make *"], "curl evil", false, false, Approve, Prompt),
            (Log, &["make *"], "make deploy", false, false, Log, release(false, Via::Level)),
            (Log, &["make *"], "curl evil", false, false, Approve, Prompt),
            (Notify, &["make *"], "curl evil", false, true, Approve, release(false, Via::Grant)),
            // Level 4 ignores the allowlist.
            (Level::Biometric, &["make *"], "make deploy", false, false, Level::Biometric, Verdict::Biometric),
        ];
        for (i, (level, allow, command, remote, grant, want_level, want)) in
            cases.into_iter().enumerate()
        {
            let got = decide(&meta(level, allow), level, &Ctx { command, by_name: None, remote }, &rules, grant);
            assert_eq!(got, (want_level, want), "case {i}");
        }
    }

    #[test]
    fn a_name_matches_only_a_program_looked_up_outside_reach() {
        let request = |argv: &[&str], program: Option<&str>| RunRequest {
            argv: argv.iter().map(|s| s.to_string()).collect(),
            program: program.map(String::from),
            cwd: "/work".into(),
            ..Default::default()
        };
        let gh = meta(Level::Approve, &["gh *"]);
        let verdict = |r: &RunRequest| {
            let command = command_line(&r.shown_argv());
            let by_name = command_by_name(r);
            decide(&gh, gh.level, &Ctx { command: &command, by_name: by_name.as_deref(), remote: false }, &Rules::default(), false).1
        };
        let allowed = Verdict::Release { notify: true, via: Via::Allowlist };
        // Looked up by the requester in an ordinary folder: shown by path, matched by name.
        let found = request(&["gh", "pr", "list"], Some("/opt/homebrew/bin/gh"));
        assert_eq!(command_line(&found.shown_argv()), "/opt/homebrew/bin/gh pr list");
        assert_eq!(verdict(&found), allowed);
        // Given by path, or found in a temporary folder: asked about.
        assert_eq!(verdict(&request(&["./gh", "pr"], Some("/work/gh"))), Verdict::Prompt);
        assert_eq!(verdict(&request(&["gh", "pr"], Some("/private/tmp/x/gh"))), Verdict::Prompt);
        // A pattern with the path matches the path.
        let pinned = meta(Level::Approve, &["/work/gh *"]);
        let r = request(&["./gh", "pr"], Some("/work/gh"));
        let command = command_line(&r.shown_argv());
        let by_name = command_by_name(&r);
        let ctx = Ctx { command: &command, by_name: by_name.as_deref(), remote: false };
        assert_eq!(decide(&pinned, pinned.level, &ctx, &Rules::default(), false).1, allowed);
        // A requester from before alpha.9 sends no path: matched as before.
        assert_eq!(verdict(&request(&["gh", "pr"], None)), allowed);
    }

    #[test]
    fn rules_never_lower_and_never_reach_biometric() {
        let ctx = Ctx { command: "x", by_name: None, remote: true };
        let strict = Rules { remote_min: Level::Biometric, ..Rules::default() };
        assert_eq!(effective_level(&meta(Level::Log, &[]), Level::Log, &ctx, &strict), Level::Approve);
        let lax = Rules { remote_min: Level::Log, ..Rules::default() };
        assert_eq!(effective_level(&meta(Level::Approve, &[]), Level::Approve, &ctx, &lax), Level::Approve);
        assert_eq!(effective_level(&meta(Level::Biometric, &[]), Level::Biometric, &ctx, &lax), Level::Biometric);
    }
}
