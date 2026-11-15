//! `mayi`: the requester. Asks a vault device for secrets and runs a command
//! with them. Stores no secret: only, once paired with a device on another
//! machine, its own tunnel key and where to find that device.

mod browser;
mod cdp;
mod config;
mod fill;
mod mask;
mod mcp;
mod session;

use std::io::{self, IsTerminal, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mayi_proto::noise::{self, PairingToken, MODE_PAIRING, MODE_SESSION};
use mayi_proto::{read_frame, write_frame, Binding, ClientMsg, Peer, RunRequest, ServerMsg, Wake, DEFAULT_FIELD};

use config::{Config, Device};
use mask::Masker;

/// Exit codes for failures of mayi itself, as opposed to the command's own.
const EXIT_USAGE: u8 = 64;
const EXIT_UNAVAILABLE: u8 = 69;
const EXIT_TIMEOUT: u8 = 75;
const EXIT_DENIED: u8 = 77;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

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
        /// Seconds to wait for the vault device to decide before giving up
        #[arg(long, env = "MAYI_TIMEOUT", default_value_t = 120)]
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
        /// Seconds to wait for the vault device to decide before giving up
        #[arg(long, env = "MAYI_TIMEOUT", default_value_t = 120)]
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
    /// Serve the Model Context Protocol on stdin/stdout, for agents without a shell
    Mcp,
}

/// An open conversation with a vault device, local or through a tunnel.
struct Channel {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
}

fn socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("MAYI_SOCKET") {
        return path.into();
    }
    let home = std::env::var_os("MAYI_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".mayi")
    });
    home.join("mayi.sock")
}

fn tcp_connect(address: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "address did not resolve");
    for addr in (address, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// What a successful connection to a device returns: the conversation, the
/// vault's current list of devices, and the address that worked.
type Reached = (Channel, Vec<Peer>, String);

/// Opens a session tunnel to a paired device, trying the address that worked
/// last and then each announced one, and asks it for the vault's devices.
fn connect_device(device: &Device, private: &[u8; 32]) -> io::Result<Reached> {
    let public = device.public()?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address known");
    for (address, port) in device.candidates() {
        let attempt = tcp_connect(&address, port).and_then(|mut stream| {
            // Bound the handshake and the first exchange; afterwards the
            // device may take minutes to decide.
            stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
            let transport = noise::connect(&mut stream, MODE_SESSION, private, &public, None)?;
            let (mut reader, mut writer) = noise::split(transport, stream.try_clone()?, stream.try_clone()?);
            write_frame(&mut writer, &ClientMsg::Peers)?;
            let peers = match read_frame::<_, ServerMsg>(&mut reader)? {
                Some(ServerMsg::Peers { devices }) => devices,
                Some(ServerMsg::Error { message }) => return Err(io::Error::other(message)),
                _ => return Err(io::Error::other("unexpected reply from the vault device")),
            };
            stream.set_read_timeout(None)?;
            Ok((Channel { reader: Box::new(reader), writer: Box::new(writer) }, peers))
        });
        match attempt {
            Ok((channel, peers)) => {
                let shown = if address.contains(':') { format!("[{address}]") } else { address };
                return Ok((channel, peers, format!("{shown}:{port}")));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Asks the wake-up gateway to send a device an empty push. Uses `curl`
/// rather than linking a TLS stack into a binary that otherwise needs none.
fn wake(wake: &Wake) -> io::Result<()> {
    let body = serde_json::json!({ "id": wake.id }).to_string();
    let status = Command::new("curl")
        .args(["-fsS", "-m", "10", "-o", "/dev/null", "-X", "POST"])
        .args(["-H", "content-type: application/json", "-d", &body, &wake.url])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() { Ok(()) } else { Err(io::Error::other("the wake-up gateway refused the request")) }
}

/// Connects to a device, waking it first if it is asleep and can be woken.
fn reach_device(device: &Device, private: &[u8; 32]) -> io::Result<Reached> {
    let first = connect_device(device, private);
    let (Err(error), Some(gateway)) = (&first, &device.wake) else { return first };
    if wake(gateway).is_err() {
        return Err(io::Error::other(format!("{error}; and it could not be woken")));
    }
    let patience = std::env::var("MAYI_WAKE_WAIT").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let deadline = std::time::Instant::now() + Duration::from_secs(patience);
    loop {
        thread::sleep(Duration::from_millis(500));
        match connect_device(device, private) {
            Ok(connected) => return Ok(connected),
            Err(e) if std::time::Instant::now() >= deadline => {
                return Err(io::Error::other(format!("{e}; woken but did not come up within {patience}s")))
            }
            Err(_) => {}
        }
    }
}

/// Finds a vault device: the one on this machine first, then paired ones.
fn open_channel(remote_only: bool) -> Result<Channel, String> {
    let socket = socket_path();
    let pinned = std::env::var_os("MAYI_SOCKET").is_some();
    let mut tried = Vec::new();
    if !remote_only {
        match UnixStream::connect(&socket) {
            Ok(stream) => {
                let reader = stream.try_clone().map_err(|e| e.to_string())?;
                return Ok(Channel { reader: Box::new(reader), writer: Box::new(stream) });
            }
            Err(e) => tried.push(format!("this machine ({}): {e}", socket.display())),
        }
        if pinned {
            return Err(format!("no vault device reachable: {}", tried.join("; ")));
        }
    }
    let mut config = Config::load().map_err(|e| format!("{}: {e}", config::path().display()))?;
    if config.devices.is_empty() {
        tried.push("no paired device (see `mayi pair`)".into());
    } else {
        let private = config.private_key().map_err(|e| e.to_string())?;
        for device in config.devices.clone() {
            match reach_device(&device, &private) {
                Ok((channel, peers, reached)) => {
                    // Keep the address that worked, and learn about devices
                    // added to or removed from the vault.
                    let mut changed = false;
                    if let Some(known) = config.devices.iter_mut().find(|d| d.public_key == device.public_key) {
                        changed = known.reached.as_deref() != Some(reached.as_str());
                        known.reached = Some(reached);
                    }
                    if config.update_peers(&device, peers) || changed {
                        let _ = config.save();
                    }
                    return Ok(channel);
                }
                Err(e) => tried.push(format!("{}: {e}", device.name)),
            }
        }
    }
    Err(format!("no vault device reachable: {}", tried.join("; ")))
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

fn run(
    secrets: Vec<String>,
    reason: String,
    agent: Option<String>,
    session: Option<String>,
    timeout: u64,
    remote: bool,
    command: Vec<String>,
) -> Result<u8, Failure> {
    let bindings = secrets
        .iter()
        .map(|s| parse_binding(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (EXIT_USAGE, e))?;
    let (agent, session) = requester_identity(agent, session);
    let request = RunRequest {
        bindings,
        argv: command.clone(),
        cwd: std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        reason,
        agent,
        session,
        host: hostname(),
        site: None,
    };

    let Channel { reader, mut writer } = open_channel(remote).map_err(|e| (EXIT_UNAVAILABLE, e))?;
    write_frame(&mut writer, &ClientMsg::Run(request))
        .map_err(|e| (EXIT_UNAVAILABLE, format!("vault device connection lost: {e}")))?;
    let replies = replies(reader);
    // Dropping the connection on timeout makes the device withdraw its prompt.
    let env = match replies.recv_timeout(Duration::from_secs(timeout)) {
        Ok(ServerMsg::Released { env, .. }) => env,
        Ok(ServerMsg::Denied { reason }) => return Err((EXIT_DENIED, format!("denied: {reason}"))),
        Ok(ServerMsg::Error { message }) => return Err((EXIT_UNAVAILABLE, message)),
        Ok(_) => return Err((EXIT_UNAVAILABLE, "unexpected reply from the vault device".into())),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err((EXIT_TIMEOUT, format!("no decision from the vault device within {timeout}s")))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err((EXIT_UNAVAILABLE, "the vault device closed the connection".into()))
        }
    };

    let mut child_cmd = Command::new(&command[0]);
    child_cmd
        .args(&command[1..])
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
    let Channel { reader, mut writer } = open_channel(remote).map_err(|e| (EXIT_UNAVAILABLE, e))?;
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
        let attempt = tcp_connect(address, token.port).and_then(|mut stream| {
            stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
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
                    wake: None,
                    vault: None,
                    reached: Some(format!("{address}:{}", token.port)),
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
        let wake = if device.wake.is_some() { "\tcan be woken" } else { "" };
        println!("{}\t{}\tport {}{wake}", device.name, device.addresses.join(","), device.port);
    }
    Ok(0)
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Cmd::Run { secrets, reason, agent, session, timeout, remote, command } => {
            run(secrets, reason, agent, session, timeout, remote, command)
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
            timeout,
            remote,
        } => fill::fill(fill::FillArgs {
            login,
            reason,
            agent,
            session,
            timeout,
            remote,
            browser,
            tab,
            submit_selector,
            username_selector,
            password_selector,
            code_selector,
        }),
        Cmd::Browser { port, headless } => browser::start(port, headless),
        Cmd::Mcp => mcp::serve().map(|()| 0).map_err(|e| (EXIT_UNAVAILABLE, e.to_string())),
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
