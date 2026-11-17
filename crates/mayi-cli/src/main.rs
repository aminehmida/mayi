//! `mayi`: the requester. Asks a vault device for secrets and runs a command
//! with them. Stores no secret: only, once paired with a device on another
//! machine, its own tunnel key and where to find that device.

mod browser;
mod cdp;
mod config;
mod fill;
mod mask;
mod program;
mod reach;
mod session;

use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mayi_proto::noise::{self, PairingToken, MODE_PAIRING};
use mayi_proto::{read_frame, write_frame, Binding, ClientMsg, RunRequest, ServerMsg, DEFAULT_FIELD};

use config::{Config, Device};
use mask::Masker;

/// Exit codes for failures of mayi itself, as opposed to the command's own.
const EXIT_USAGE: u8 = 64;
const EXIT_UNAVAILABLE: u8 = 69;
const EXIT_TIMEOUT: u8 = 75;
const EXIT_DENIED: u8 = 77;

type Failure = (u8, String);

#[derive(Parser)]
#[command(name = "mayi", version, about = "Use secrets in commands without seeing them")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command with secrets injected as environment variables
    Run {
        /// Secret to inject: ENV=NAME, ENV=NAME/FIELD, or NAME (same env name)
        #[arg(short, long = "secret", value_name = "ENV=NAME[/FIELD]", required = true)]
        secrets: Vec<String>,
        /// Why the secrets are needed; shown to the user and logged
        #[arg(short, long)]
        reason: String,
        /// Name of the requesting agent
        #[arg(long, env = "MAYI_AGENT")]
        agent: Option<String>,
        /// Identifier of the agent session
        #[arg(long, env = "MAYI_SESSION")]
        session: Option<String>,
        /// Seconds to keep trying your devices until one takes the request
        #[arg(long, env = "MAYI_WAIT", default_value_t = 3600)]
        wait: u64,
        /// Seconds to wait for your answer once a device has the request
        #[arg(long, env = "MAYI_TIMEOUT", default_value_t = 900)]
        timeout: u64,
        /// Skip the vault device on this machine and use a paired one
        #[arg(long)]
        remote: bool,
        /// The command to run, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// List the names and levels of available secrets
    List {
        /// Skip the vault device on this machine and use a paired one
        #[arg(long)]
        remote: bool,
    },
    /// Pair this machine with a vault device on another machine
    Pair {
        /// The pairing token shown by the vault device, or `-` to read it from stdin
        token: String,
        /// What to call this machine on the vault device
        #[arg(long)]
        name: Option<String>,
    },
    /// List the vault devices this machine is paired with
    Devices,
    /// Type a login into the sign-in page open in your browser, then press Enter
    ///
    /// Reads the page's address from the browser over its debugging port,
    /// asks the vault device, and types the username, password or two-factor
    /// code that the page asks for. Nothing typed is printed. Run it again on
    /// each page of a sign-in that asks for more.
    Fill {
        /// The login to use, as `mayi list` shows it
        login: String,
        /// Why you are signing in; shown to the user and logged
        #[arg(short, long)]
        reason: String,
        /// The browser's debugging port or profile folder [default: 127.0.0.1:9222, then known profiles]
        #[arg(long, env = "MAYI_BROWSER")]
        browser: Option<String>,
        /// Fill the tab whose address or title contains this text, rather than
        /// the most recent tab on one of the login's websites
        #[arg(long)]
        tab: Option<String>,
        /// Click this element to submit, rather than pressing Enter
        #[arg(long, value_name = "CSS")]
        submit_selector: Option<String>,
        /// CSS selector of the username field, if it is not found
        #[arg(long, value_name = "CSS")]
        username_selector: Option<String>,
        /// CSS selector of the password field, if it is not found
        #[arg(long, value_name = "CSS")]
        password_selector: Option<String>,
        /// CSS selector of the two-factor code field, if it is not found
        #[arg(long, value_name = "CSS")]
        code_selector: Option<String>,
        #[arg(long, env = "MAYI_AGENT")]
        agent: Option<String>,
        #[arg(long, env = "MAYI_SESSION")]
        session: Option<String>,
        /// Seconds to keep trying your devices until one takes the request;
        /// shorter than for `run`, as sign-in pages go stale
        #[arg(long, env = "MAYI_WAIT", default_value_t = 600)]
        wait: u64,
        /// Seconds to wait for your answer once a device has the request
        #[arg(long, env = "MAYI_TIMEOUT", default_value_t = 900)]
        timeout: u64,
        /// Skip the vault device on this machine and use a paired one
        #[arg(long)]
        remote: bool,
    },
    /// Start a Chrome for your agent, with a debugging port mayi fill can use
    Browser {
        /// Debugging port to listen on, on this machine only
        #[arg(long, default_value_t = 9222)]
        port: u16,
        /// Run without a window
        #[arg(long)]
        headless: bool,
    },
}

/// An open conversation with a vault device, local or through a tunnel.
struct Channel {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

fn parse_binding(spec: &str) -> Result<Binding, String> {
    let (env, source) = spec.split_once('=').unwrap_or((spec, spec));
    let (item, field) = source.split_once('/').unwrap_or((source, DEFAULT_FIELD));
    let valid_env = env.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid_env {
        return Err(format!("{spec:?}: {env:?} is not a valid environment variable name"));
    }
    if item.is_empty() || field.is_empty() {
        return Err(format!("{spec:?}: expected ENV=NAME[/FIELD]"));
    }
    Ok(Binding { env: env.into(), item: item.into(), field: field.into() })
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length and gethostname NUL-terminates
    // within it or fails.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len() - 1) } == 0;
    if !ok {
        return String::new();
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(0);
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

/// Copies `from` to `to`, masking secret values on the way.
fn pump(mut from: impl Read, mut to: impl Write, mut masker: Masker) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let out = masker.feed(&buf[..n]);
                if to.write_all(&out).and_then(|()| to.flush()).is_err() {
                    return;
                }
            }
        }
    }
    let _ = to.write_all(&masker.finish());
    let _ = to.flush();
}

/// Reads the device's messages on a thread, so the caller can stop waiting.
fn replies(mut reader: Box<dyn Read + Send>) -> mpsc::Receiver<ServerMsg> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        while let Ok(Some(msg)) = read_frame::<_, ServerMsg>(&mut reader) {
            if tx.send(msg).is_err() {
                break;
            }
        }
    });
    rx
}

/// The agent and session to report, as given or as found: without a session
/// from the agent, its own process is the session (see `session.rs`).
fn requester_identity(agent: Option<String>, session: Option<String>) -> (String, String) {
    let agent = agent.unwrap_or_else(|| {
        if std::env::var_os("CLAUDECODE").is_some() {
            "claude-code".into()
        } else {
            session::default_agent().unwrap_or_else(|| "unknown".into())
        }
    });
    let session = session.unwrap_or_else(session::default_session);
    (agent, session)
}

/// How long to look for a device, and then to wait for an answer.
#[derive(Clone, Copy)]
pub struct Patience {
    pub wait: Duration,
    pub timeout: Duration,
}

impl Patience {
    fn secs(wait: u64, timeout: u64) -> Self {
        Self { wait: Duration::from_secs(wait), timeout: Duration::from_secs(timeout) }
    }
}

fn run(
    secrets: Vec<String>,
    reason: String,
    agent: Option<String>,
    session: Option<String>,
    patience: Patience,
    remote: bool,
    command: Vec<String>,
) -> Result<u8, Failure> {
    let bindings = secrets
        .iter()
        .map(|s| parse_binding(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (EXIT_USAGE, e))?;
    let (agent, session) = requester_identity(agent, session);
    // Looked up here, outside the working folder and temporary folders, and
    // run from exactly this path, which the owner is shown.
    let cwd = std::env::current_dir().map_err(|e| (EXIT_USAGE, format!("cannot read the working folder: {e}")))?;
    let path = program::path_var();
    let dirs = program::search_dirs(path.as_deref(), &cwd);
    let program_path = program::locate(&command[0], &cwd, &dirs, path.as_deref()).map_err(|e| (127, e))?;
    let program_shown = program_path
        .to_str()
        .ok_or_else(|| (127, format!("cannot run {}: its path is not valid UTF-8", program_path.display())))?
        .to_string();
    let request = RunRequest {
        bindings,
        argv: command.clone(),
        cwd: cwd.display().to_string(),
        reason,
        agent,
        session,
        host: hostname(),
        site: None,
        program: Some(program_shown),
    };

    let reach::Answer { reply, replies, mut writer } =
        reach::ask(&request, remote, patience.wait, patience.timeout)?;
    let env = match reply {
        ServerMsg::Released { env, .. } => env,
        ServerMsg::Denied { reason } => return Err((EXIT_DENIED, format!("denied: {reason}"))),
        _ => return Err((EXIT_UNAVAILABLE, "unexpected reply from the vault device".into())),
    };

    let mut child_cmd = Command::new(&program_path);
    child_cmd.arg0(&command[0]).args(&command[1..]);
    for (key, _) in std::env::vars_os().filter(|(key, _)| program::dropped(key)) {
        child_cmd.env_remove(key);
    }
    child_cmd
        .env("PATH", program::search_path(&dirs))
        .envs(&env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // With its own process group, Stop reaches the command's children too.
    // An interactive command must stay in the terminal's foreground group.
    let own_group = !io::stdin().is_terminal();
    if own_group {
        child_cmd.process_group(0);
    }
    let mut child = child_cmd
        .spawn()
        .map_err(|e| (127, format!("cannot run {}: {e}", command[0])))?;
    let pid = child.id() as libc::pid_t;

    let values = || env.values().map(String::as_str);
    let out = thread::spawn({
        let (from, masker) = (child.stdout.take().expect("piped"), Masker::new(values()));
        move || pump(from, io::stdout(), masker)
    });
    let err = thread::spawn({
        let (from, masker) = (child.stderr.take().expect("piped"), Masker::new(values()));
        move || pump(from, io::stderr(), masker)
    });

    // The connection stays open so the user can stop the command.
    let stopped = Arc::new(AtomicBool::new(false));
    thread::spawn({
        let stopped = stopped.clone();
        move || {
            for msg in replies {
                if matches!(msg, ServerMsg::Stop) {
                    stopped.store(true, Ordering::SeqCst);
                    // SAFETY: plain syscall; a negative pid addresses the group
                    // created above.
                    unsafe { libc::kill(if own_group { -pid } else { pid }, libc::SIGTERM) };
                }
            }
        }
    });

    let status = child.wait().map_err(|e| (1, format!("waiting for the command failed: {e}")))?;
    let _ = out.join();
    let _ = err.join();
    let code = status.code().or_else(|| status.signal().map(|s| 128 + s));
    let _ = write_frame(&mut writer, &ClientMsg::Done { exit: code });
    if stopped.load(Ordering::SeqCst) {
        eprintln!("mayi: the command was stopped by the user");
    }
    Ok(code.unwrap_or(1) as u8)
}

fn list(remote: bool) -> Result<u8, Failure> {
    let Channel { reader, mut writer } = reach::any(remote, Duration::from_secs(10))?;
    write_frame(&mut writer, &ClientMsg::List)
        .map_err(|e| (EXIT_UNAVAILABLE, format!("vault device connection lost: {e}")))?;
    match replies(reader).recv_timeout(Duration::from_secs(10)) {
        Ok(ServerMsg::Secrets { secrets }) => {
            for s in secrets {
                let sites = if s.login { format!("\tlogin for {}", s.sites.join(", ")) } else { String::new() };
                println!("{}\tlevel {}\t{}{sites}", s.name, s.level, s.fields.join(","));
            }
            Ok(0)
        }
        Ok(ServerMsg::Error { message }) => Err((EXIT_UNAVAILABLE, message)),
        _ => Err((EXIT_UNAVAILABLE, "no usable reply from the vault device".into())),
    }
}

fn pair(token: String, name: Option<String>) -> Result<u8, Failure> {
    let fail = |e: io::Error| (EXIT_UNAVAILABLE, e.to_string());
    let token = if token == "-" {
        let mut line = String::new();
        io::stdin().read_line(&mut line).map_err(fail)?;
        line
    } else {
        token
    };
    let token = PairingToken::decode(&token).map_err(|e| (EXIT_USAGE, e.to_string()))?;
    let mut config = Config::load().map_err(fail)?;
    let private = config.private_key().map_err(fail)?;
    let name = name.unwrap_or_else(hostname);

    let mut last = "the token lists no address".to_string();
    for address in &token.addresses {
        let attempt = reach::tcp_connect(address, token.port).and_then(|mut stream| {
            stream.set_read_timeout(Some(reach::CONNECT_TIMEOUT))?;
            let transport =
                noise::connect(&mut stream, MODE_PAIRING, &private, &token.device_public, Some(&token.secret))?;
            let (mut reader, mut writer) = noise::split(transport, stream.try_clone()?, stream);
            write_frame(&mut writer, &ClientMsg::Pair { name: name.clone() })?;
            read_frame::<_, ServerMsg>(&mut reader)
        });
        match attempt {
            Ok(Some(ServerMsg::Paired { device })) => {
                config.remember(Device {
                    name: device.clone(),
                    public_key: hex::encode(token.device_public),
                    port: token.port,
                    addresses: token.addresses.clone(),
                    vault: None,
                    reached: Some(format!("{address}:{}", token.port)),
                    seen: None,
                });
                config.save().map_err(fail)?;
                println!("Paired with {device} as {name}.");
                return Ok(0);
            }
            Ok(Some(ServerMsg::Error { message })) => last = format!("{address}: {message}"),
            Ok(_) => last = format!("{address}: unexpected reply"),
            Err(e) => last = format!("{address}: {e}"),
        }
    }
    Err((
        EXIT_UNAVAILABLE,
        format!("pairing failed ({last}). The token may have expired or been used already."),
    ))
}

fn devices() -> Result<u8, Failure> {
    let config = Config::load().map_err(|e| (EXIT_UNAVAILABLE, e.to_string()))?;
    for device in &config.devices {
        let seen = device.seen.map(|t| format!("\tlast reached {}", reach::clock(t))).unwrap_or_default();
        println!("{}\t{}\tport {}{seen}", device.name, device.addresses.join(","), device.port);
    }
    Ok(0)
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Cmd::Run { secrets, reason, agent, session, wait, timeout, remote, command } => {
            run(secrets, reason, agent, session, Patience::secs(wait, timeout), remote, command)
        }
        Cmd::List { remote } => list(remote),
        Cmd::Pair { token, name } => pair(token, name),
        Cmd::Devices => devices(),
        Cmd::Fill {
            login,
            reason,
            browser,
            tab,
            submit_selector,
            username_selector,
            password_selector,
            code_selector,
            agent,
            session,
            wait,
            timeout,
            remote,
        } => fill::fill(fill::FillArgs {
            login,
            reason,
            agent,
            session,
            patience: Patience::secs(wait, timeout),
            remote,
            browser,
            tab,
            submit_selector,
            username_selector,
            password_selector,
            code_selector,
        }),
        Cmd::Browser { port, headless } => browser::start(port, headless),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err((code, message)) => {
            eprintln!("mayi: {message}");
            ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_forms() {
        let b = |env: &str, item: &str, field: &str| Binding {
            env: env.into(),
            item: item.into(),
            field: field.into(),
        };
        assert_eq!(parse_binding("GH_TOKEN").unwrap(), b("GH_TOKEN", "GH_TOKEN", "value"));
        assert_eq!(parse_binding("TOKEN=github").unwrap(), b("TOKEN", "github", "value"));
        assert_eq!(parse_binding("USER=db/username").unwrap(), b("USER", "db", "username"));
        for bad in ["", "1X=a", "A B=c", "X=", "X=a/", "a-b"] {
            assert!(parse_binding(bad).is_err(), "{bad:?}");
        }
    }
}
