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

/// The nearest process above `process` that is not a shell or a wrapper.
fn above(process: &Process) -> Option<Process> {
    let mut pid = process.ppid;
    for _ in 0..16 {
        let p = info(pid)?;
        if p.pid <= 1 {
            return None;
        }
        if !PASS_THROUGH.contains(&base(&p.name)) {
            return Some(p);
        }
        pid = p.ppid;
    }
    None
}

/// For `mayi aws credentials`, which the AWS CLI or an SDK runs: the tool
/// that asked (whose command the owner is shown), and the agent and session
/// above it (so an approval for the session covers its next commands, as
/// with `mayi run`).
pub struct Caller {
    pub tool: Option<Process>,
    pub agent: Option<String>,
    pub session: String,
}

pub fn caller() -> Caller {
    let tool = agent_process();
    let owner = tool.as_ref().and_then(above);
    let session = match owner.as_ref().or(tool.as_ref()) {
        Some(p) => format!("{} (pid {}, since {})", base(&p.name), p.pid, clock(p.started)),
        None => format!("ppid:{}", parent_id()),
    };
    Caller { agent: owner.map(|p| base(&p.name).to_string()), tool, session }
}

/// A process's arguments, as it was started.
#[cfg(target_os = "macos")]
pub fn arguments(pid: u32) -> Option<Vec<String>> {
    // KERN_PROCARGS2: argc, then the executable's path, NUL padding, then
    // argc NUL-terminated arguments (and the environment, not read).
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let mut size: libc::size_t = 0;
    // SAFETY: a size query with a null buffer, then a read into a buffer of
    // the size the kernel gave.
    unsafe {
        if libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
    }
    let mut buf = vec![0u8; size];
    // SAFETY: as above.
    unsafe {
        if libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
    }
    buf.truncate(size);
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let mut rest = &buf[4..];
    let path_end = rest.iter().position(|&b| b == 0)?;
    rest = &rest[path_end..];
    let start = rest.iter().position(|&b| b != 0)?;
    rest = &rest[start..];
    let args: Vec<String> =
        rest.split(|&b| b == 0).take(argc).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    (args.len() == argc && argc > 0).then_some(args)
}

#[cfg(target_os = "linux")]
pub fn arguments(pid: u32) -> Option<Vec<String>> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let args: Vec<String> = raw
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect();
    (!args.is_empty()).then_some(args)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn arguments(_pid: u32) -> Option<Vec<String>> {
    None
}

/// The full path of a process's program.
#[cfg(target_os = "macos")]
pub fn program_path(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: the buffer is valid for its length.
    let len = unsafe { libc::proc_pidpath(pid as libc::c_int, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (len > 0).then(|| String::from_utf8_lossy(&buf[..len as usize]).into_owned())
}

#[cfg(target_os = "linux")]
pub fn program_path(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok().and_then(|p| p.to_str().map(String::from))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn program_path(_pid: u32) -> Option<String> {
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
    fn a_process_arguments_and_path_are_read() {
        let me = std::process::id();
        let args = arguments(me).expect("own arguments");
        let mine: Vec<String> = std::env::args().collect();
        assert_eq!(args, mine);
        let path = program_path(me).expect("own path");
        assert_eq!(std::fs::canonicalize(path).unwrap(), std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap());
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
