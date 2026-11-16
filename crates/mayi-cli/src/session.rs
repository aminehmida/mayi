//! Which agent session a request belongs to, when the agent does not say.
//!
//! Agents often run each command in a fresh shell (Claude Code does), so the
//! shell `mayi` runs in is no session: an approval "for this session" would
//! never cover the next command. The session is instead the first process
//! above `mayi` that is not a shell or a plain wrapper, which is usually the
//! agent itself. A person typing in a terminal gets the terminal tab's login
//! process. The process's start time is part of the session, so a process id
//! reused later is not mistaken for the same session.

use std::os::unix::process::parent_id;

pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// Seconds since the Unix epoch.
    pub started: u64,
}

/// Processes that only pass a command on, and so do not end a session.
const PASS_THROUGH: &[&str] = &[
    "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh", "nu", "elvish", "xonsh", "env", "sudo", "doas",
    "timeout", "nohup", "nice", "time", "caffeinate", "mayi",
];

/// The base name of a process, without a login shell's leading `-`.
fn base(name: &str) -> &str {
    let name = name.trim_start_matches('-');
    name.rsplit('/').next().unwrap_or(name)
}

#[cfg(target_os = "macos")]
fn info(pid: u32) -> Option<Process> {
    let mut bsd: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the buffer is a zeroed proc_bsdinfo of the size passed.
    let read = unsafe {
        libc::proc_pidinfo(pid as libc::c_int, libc::PROC_PIDTBSDINFO, 0, (&mut bsd as *mut libc::proc_bsdinfo).cast(), size)
    };
    if read != size {
        return None;
    }
    let text = |chars: &[libc::c_char]| {
        let bytes: Vec<u8> = chars.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    let name = text(&bsd.pbi_name);
    let name = if name.is_empty() { text(&bsd.pbi_comm) } else { name };
    Some(Process { pid, ppid: bsd.pbi_ppid, name, started: bsd.pbi_start_tvsec })
}

#[cfg(target_os = "linux")]
fn info(pid: u32) -> Option<Process> {
    // /proc/PID/stat: "PID (NAME) STATE PPID ...", the start time in clock
    // ticks after boot as field 22. NAME may itself contain spaces or ")".
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat[open + 1..close].to_string();
    let fields: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    let ppid = fields.get(1)?.parse().ok()?;
    let ticks: u64 = fields.get(19)?.parse().ok()?;
    // SAFETY: sysconf has no preconditions.
    let per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let boot: u64 = std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    Some(Process { pid, ppid, name, started: boot + ticks / per_second })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn info(_pid: u32) -> Option<Process> {
    None
}

/// The nearest process above this one that is not a shell or a wrapper.
pub fn agent_process() -> Option<Process> {
    let mut pid = parent_id();
    for _ in 0..16 {
        let process = info(pid)?;
        if process.pid <= 1 {
            return None;
        }
        if !PASS_THROUGH.contains(&base(&process.name)) {
            return Some(process);
        }
        pid = process.ppid;
    }
    None
}

fn clock(unix_secs: u64) -> String {
    let t = unix_secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return unix_secs.to_string();
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

/// The session to report when the agent gives none: readable in a prompt,
/// for example "claude (pid 43271, since 09:14:02)".
pub fn default_session() -> String {
    // In a terminal, the process above the shell can be one this user may
    // not read (macOS's `login` runs as root): the shell is then the session.
    match agent_process().or_else(|| info(parent_id())) {
        Some(p) => format!("{} (pid {}, since {})", base(&p.name), p.pid, clock(p.started)),
        None => format!("ppid:{}", parent_id()),
    }
}

/// A name for the agent when it gives none: the session's process, or
/// "terminal" for a person typing at one.
pub fn default_agent() -> Option<String> {
    use std::io::IsTerminal;
    agent_process()
        .map(|p| base(&p.name).to_string())
        .or_else(|| std::io::stdin().is_terminal().then(|| "terminal".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn names_are_compared_without_path_or_login_dash() {
        assert_eq!(base("-/bin/zsh"), "zsh");
        assert_eq!(base("-zsh"), "zsh");
        assert_eq!(base("/opt/homebrew/bin/claude"), "claude");
    }

    #[test]
    fn this_process_is_found() {
        let me = info(std::process::id()).expect("own process");
        assert_eq!(me.ppid, parent_id());
        assert!(me.started > 1_600_000_000, "a start time in seconds since the epoch");
    }

    /// Two commands run by the same parent through fresh shells, as an agent
    /// runs them, report the same session; the shells differ.
    #[test]
    fn fresh_shells_share_the_session_of_what_started_them() {
        let exe = std::env::current_exe().unwrap();
        let probe = |shell: &str| {
            let out = Command::new(shell)
                .arg("-c")
                .arg(format!("{} --exact session::tests::print_session --nocapture --ignored", exe.display()))
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.lines().find_map(|l| l.strip_prefix("SESSION=")).map(String::from).expect("printed")
        };
        let first = probe("sh");
        let second = probe("/bin/sh");
        assert_eq!(first, second);
        assert!(!first.starts_with("ppid:"), "{first}");
    }

    #[test]
    #[ignore = "run by fresh_shells_share_the_session_of_what_started_them"]
    fn print_session() {
        println!("SESSION={}", default_session());
    }
}
