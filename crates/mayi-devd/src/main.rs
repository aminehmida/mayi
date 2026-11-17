//! Development vault device: the real core with software keys and prompts in
//! the terminal. It stands in for the Mac and Android apps until they exist.
//!
//! NOT SECURE: the "hardware" keys sit in a file and the biometric check is a
//! typed answer. Use it to try the flow, not to protect real secrets.

use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::thread;

use clap::{Parser, Subcommand};
use mayi_core::broker::{Approval, Broker, Notice, Prompt, Requester, Ui};
use mayi_core::grants::GrantScope;
use mayi_core::hardware::SoftwareKeys;
use mayi_core::model::{Kind, Level, NewItem, SecretValues};
use mayi_core::policy::{command_line, Rules};
use mayi_core::server::Server;
use mayi_core::vault::Vault;
use mayi_proto::{RunRequest, DEFAULT_FIELD, FIELD_PASSWORD, FIELD_TOTP, FIELD_USERNAME};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "mayi-devd", version, about = "Development vault device for Mayi (not secure)")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the vault and its software keys
    Init,
    /// Regain access to the vault file with a recovery key, after losing this device's keys
    Recover { key: String },
    /// Join an existing vault as another device: with the token from `add-device`, or
    /// without one, by showing a code for a device with the vault to add
    Join {
        token: Option<String>,
        #[arg(long, default_value = "dev-2")]
        name: String,
    },
    /// Add or replace a secret; values are read from the terminal or stdin
    Add {
        name: String,
        /// Store a website login (username, password, optional two-factor key)
        #[arg(long, requires = "sites")]
        login: bool,
        /// Website the login may be typed into (repeatable): a host, or *.host for its subdomains
        #[arg(long = "site", requires = "login")]
        sites: Vec<String>,
        /// 1 log, 2 notify, 3 approve, 4 biometric
        #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=4))]
        level: u8,
        /// Field to store (repeatable); defaults to a single field named "value"
        #[arg(short, long = "field")]
        fields: Vec<String>,
        /// Command pattern this secret is expected to be used with (repeatable, `*` wildcard)
        #[arg(short, long = "allow")]
        allow: Vec<String>,
        /// Longest an approval may stay valid, in seconds; 0 asks every time
        #[arg(long, default_value_t = 900)]
        max_grant: u64,
    },
    /// List secrets
    Ls,
    /// Delete a secret
    Rm { name: String },
    /// Show the audit log
    Log {
        #[arg(short, default_value_t = 20)]
        n: usize,
    },
    /// Serve requests, asking for approval in this terminal
    Serve {
        /// Also accept paired machines on this address, e.g. 0.0.0.0:7462
        #[arg(long)]
        listen: Option<String>,
    },
}

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn home() -> PathBuf {
    std::env::var_os("MAYI_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".mayi")
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn load_keys(confirm: impl Fn(&str) -> bool + Send + Sync + 'static) -> Res<SoftwareKeys> {
    let path = home().join("dev-keys.bin");
    let bytes = Zeroizing::new(
        fs::read(&path).map_err(|e| format!("{}: {e} (run `mayi-devd init` first)", path.display()))?,
    );
    Ok(SoftwareKeys::from_bytes(&bytes, confirm)?)
}

fn open_vault(confirm: impl Fn(&str) -> bool + Send + Sync + 'static) -> Res<Vault> {
    Ok(Vault::open(&home().join("vault.db"), Arc::new(load_keys(confirm)?))?)
}

/// Generates this device's software keys and stores them in the home directory.
fn new_keys() -> Res<(PathBuf, SoftwareKeys)> {
    let dir = home();
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    let keys = SoftwareKeys::generate(|_| false);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join("dev-keys.bin"))
        .map_err(|e| format!("cannot create dev-keys.bin in {}: {e}", dir.display()))?;
    file.write_all(&keys.to_bytes())?;
    Ok((dir, keys))
}

fn recover(key: String) -> Res<()> {
    let dir = home();
    // The old keys are of no use; keep them aside rather than deleting them.
    let old = dir.join("dev-keys.bin");
    if old.exists() {
        fs::rename(&old, dir.join("dev-keys.bin.lost"))?;
    }
    let (dir, keys) = new_keys()?;
    let vault = Vault::recover(&dir.join("vault.db"), Arc::new(keys), "recovered", &key)?;
    println!("Recovered the vault: {} secret(s) readable again.", vault.list()?.len());
    Ok(())
}

fn join(token: Option<String>, name: String) -> Res<()> {
    let (dir, keys) = new_keys()?;
    let path = dir.join("vault.db");
    let vault = match token {
        Some(token) => mayi_core::server::join_vault(&path, Arc::new(keys), &name, &token)?,
        None => {
            let code = mayi_core::server::JoinCode::open(advertised(), 0, 600)?;
            eprintln!("on a device with the vault, choose Add a Device and enter this code within 10 minutes:");
            println!("{}", code.token());
            code.wait(&path, Arc::new(keys), &name, &std::sync::atomic::AtomicBool::new(false))?
        }
    };
    println!("Joined the vault as {name}; received {} secret(s).", vault.list()?.len());
    Ok(())
}

fn init() -> Res<()> {
    let (dir, keys) = new_keys()?;
    Vault::create(&dir.join("vault.db"), Arc::new(keys), "dev")?;
    println!("Created a development vault in {}", dir.display());
    println!("Its keys are stored in a plain file: do not put real secrets in it.");
    Ok(())
}

fn read_value(name: &str, field: &str) -> Res<Zeroizing<String>> {
    let value = read_optional(name, field)?;
    if value.is_empty() {
        return Err(format!("empty value for {name}/{field}").into());
    }
    Ok(value)
}

fn read_optional(name: &str, field: &str) -> Res<Zeroizing<String>> {
    let value = if io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password(format!("{name}/{field}: "))?)
    } else {
        // One line per field, so values can be piped in.
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string())
    };
    Ok(value)
}

struct AddArgs {
    name: String,
    login: bool,
    sites: Vec<String>,
    level: u8,
    fields: Vec<String>,
    allow: Vec<String>,
    max_grant: u64,
}

fn add(args: AddArgs) -> Res<()> {
    let AddArgs { name, login, sites, level, fields, allow, max_grant } = args;
    let vault = open_vault(|_| false)?;
    let mut values = SecretValues::new();
    if login {
        // The username and the two-factor key may be left empty.
        for field in [FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOTP] {
            let value = if field == FIELD_PASSWORD { read_value(&name, field)? } else { read_optional(&name, field)? };
            values.insert(field.to_string(), value);
        }
    } else {
        let fields = if fields.is_empty() { vec![DEFAULT_FIELD.to_string()] } else { fields };
        for field in fields {
            let value = read_value(&name, &field)?;
            values.insert(field, value);
        }
    }
    let level = Level::try_from(level)?;
    let kind = if login { Kind::Login } else { Kind::Secret };
    let meta = vault.put(NewItem { name, level, values, allow, max_grant_secs: max_grant, kind, sites, folder: None })?;
    let sites = if meta.sites.is_empty() { String::new() } else { format!(" for {}", meta.sites.join(", ")) };
    println!("Saved {}{sites} at level {} (version {})", meta.name, meta.level as u8, meta.version);
    Ok(())
}

fn format_time(ts_ms: u64) -> String {
    // UTC, without pulling in a date library.
    let secs = ts_ms / 1000;
    let (h, m, s) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
    let mut days = secs / 86400;
    let mut year = 1970;
    let leap = |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    while days >= if leap(year) { 366 } else { 365 } {
        days -= if leap(year) { 366 } else { 365 };
        year += 1;
    }
    let lengths = [31, if leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    while days >= lengths[month] {
        days -= lengths[month];
        month += 1;
    }
    format!("{year}-{:02}-{:02} {h:02}:{m:02}:{s:02}Z", month + 1, days + 1)
}

fn log(n: usize) -> Res<()> {
    let vault = open_vault(|_| false)?;
    for e in vault.audit_tail(n)? {
        print!("{}  #{}  {:<7}  {}", format_time(e.ts_ms), e.run_id, e.event, e.outcome);
        if e.event == "request" {
            let secrets: Vec<String> =
                e.secrets.iter().map(|s| format!("{}(L{},{})", s.name, s.level, s.via)).collect();
            let target = if e.site.is_empty() {
                format!("command: {}", command_line(&e.argv))
            } else {
                format!("sign in to: {}", e.site)
            };
            print!(
                "\n    {} [{}] on {} ({}, {})\n    reason: {}\n    {target}",
                secrets.join(" "),
                if e.remote { "remote" } else { "local" },
                e.requester,
                e.agent,
                e.session,
                e.reason,
            );
        }
        println!();
    }
    Ok(())
}

/// Prompts and notifications in the terminal. One thread owns stdin and hands
/// each line either to the prompt that is waiting or to the command handler.
struct Terminal {
    waiter: Mutex<Option<mpsc::Sender<String>>>,
    /// The run whose approval prompt is waiting for an answer.
    asking_for: Mutex<Option<u64>>,
    one_prompt: Mutex<()>,
    closed: AtomicBool,
}

impl Terminal {
    /// Prints `text` and waits for a line. Returns an empty answer, which
    /// every caller treats as "no", when there is nobody to ask.
    fn ask(&self, text: &str) -> String {
        let _guard = lock(&self.one_prompt);
        if self.closed.load(Ordering::SeqCst) {
            return String::new();
        }
        let (tx, rx) = mpsc::channel();
        *lock(&self.waiter) = Some(tx);
        eprint!("{text}");
        let _ = io::stderr().flush();
        rx.recv().unwrap_or_default().trim().to_lowercase()
    }
}

fn describe(request: &RunRequest, requester: &Requester) -> String {
    let target = match &request.site {
        Some(site) => {
            let fields: Vec<&str> = request.bindings.iter().map(|b| b.field.as_str()).collect();
            format!("sign in: {site}  (types {})", fields.join(", "))
        }
        None => format!("command : {}", command_line(&request.shown_argv())),
    };
    format!(
        "  {target}\n  cwd     : {}\n  machine : {} ({})\n  claims  : agent {:?}, session {:?}, host {:?}\n  reason  : {:?}  (written by the agent)\n",
        request.cwd,
        requester.id,
        if requester.remote { "remote" } else { "this machine" },
        request.agent,
        request.session,
        request.host,
        request.reason,
    )
}

impl Ui for Terminal {
    fn approve(&self, prompt: &Prompt) -> Approval {
        let secrets: Vec<String> = prompt
            .secrets
            .iter()
            .map(|s| {
                let note = if s.needs_approval { ", needs approval" } else { "" };
                format!("{} (level {}{note})", s.name, s.level as u8)
            })
            .collect();
        *lock(&self.asking_for) = Some(prompt.run_id);
        let answer = self.ask(&format!(
            "\n── approval needed ──\n{}  secrets : {}\n[o]nce  [s]ession, this command  [a]ny command this session  [d]eny > ",
            describe(prompt.request, prompt.requester),
            secrets.join(", "),
        ));
        *lock(&self.asking_for) = None;
        match answer.as_str() {
            "o" | "once" => Approval::Allow(GrantScope::Once),
            "s" | "session" => Approval::Allow(GrantScope::SessionCommand),
            "a" | "any" => Approval::Allow(GrantScope::SessionAny),
            _ => Approval::Deny,
        }
    }

    fn withdraw(&self, run_id: u64) {
        if *lock(&self.asking_for) == Some(run_id) {
            // Dropping the sender answers the prompt with "no".
            lock(&self.waiter).take();
            eprintln!("\n(the requester went away; request #{run_id} withdrawn)");
        }
    }

    fn paired(&self, name: &str, id: &str) {
        eprintln!("\npaired with {name} ({id})");
    }

    fn device_added(&self, name: &str) {
        eprintln!("\n{name} joined the vault");
    }

    fn synced(&self, changed: usize) {
        eprintln!("\nsynced: {changed} record(s) updated");
    }

    fn notify(&self, notice: &Notice) {
        eprintln!(
            "\n── released #{} ──\n{}  secrets : {}\n  type `stop {}` to kill the command and revoke the session",
            notice.run_id,
            describe(notice.request, notice.requester),
            notice.secrets.join(", "),
            notice.run_id,
        );
    }
}

fn rotate_advice(what: &str, names: &[String]) {
    if names.is_empty() {
        eprintln!("nothing to rotate: no secret {what}");
    } else {
        eprintln!("rotate the secrets {what}: {}", names.join(", "));
    }
}

/// The addresses to tell other machines and devices to use for this one.
fn advertised() -> Vec<String> {
    std::env::var("MAYI_ADVERTISE")
        .map(|a| a.split(',').map(String::from).collect())
        .unwrap_or_else(|_| mayi_core::server::local_addresses())
}

fn report_sync(server: &Server) {
    match server.sync_all() {
        Ok(results) => {
            for (name, outcome) in results {
                match outcome {
                    Ok(changed) => eprintln!("synced with {name}: {changed} record(s) updated here"),
                    Err(e) => eprintln!("could not sync with {name}: {e}"),
                }
            }
        }
        Err(e) => eprintln!("sync failed: {e}"),
    }
}

fn serve(listen: Option<String>) -> Res<()> {
    let terminal = Arc::new(Terminal {
        waiter: Mutex::new(None),
        asking_for: Mutex::new(None),
        one_prompt: Mutex::new(()),
        closed: AtomicBool::new(false),
    });
    let biometric = terminal.clone();
    let vault = open_vault(move |prompt| {
        let answer = biometric.ask(&format!(
            "\n── biometric check (simulated) ──\n  {prompt}\n  type `yes` to stand in for a fingerprint > "
        ));
        answer == "yes"
    })?;
    let server = Server::new(Broker::new(vault, terminal.clone(), Rules::default()));

    let socket = std::env::var_os("MAYI_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join("mayi.sock"));
    let listener = Server::bind(&socket)?;
    eprintln!("mayi-devd (development only, not secure) listening on {}", socket.display());
    eprintln!("Commands: `stop <run>`, `pair`, `machines`, `revoke <id>`, `add-device [code]`, `devices`, `sync`.");

    let mut port = None;
    if let Some(address) = listen {
        let tcp = std::net::TcpListener::bind(&address)?;
        port = Some(tcp.local_addr()?.port());
        eprintln!("accepting paired machines and devices on {}", tcp.local_addr()?);
        server.announce(port.expect("set above"), advertised())?;
        thread::spawn({
            let server = server.clone();
            move || server.serve_tcp(tcp)
        });
        report_sync(&server);
    }

    thread::spawn({
        let (terminal, server) = (terminal.clone(), server.clone());
        move || {
            for line in io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if let Some(waiter) = lock(&terminal.waiter).take() {
                    let _ = waiter.send(line);
                    continue;
                }
                match line.trim().split_once(' ') {
                    Some(("stop", id)) if id.trim().parse::<u64>().is_ok() => {
                        let id: u64 = id.trim().parse().expect("checked");
                        if server.stop(id) {
                            eprintln!("stop sent to #{id}");
                        } else {
                            eprintln!("no running command #{id}");
                        }
                    }
                    Some(("revoke", id)) => match server.broker().vault().revoke_requester(id.trim()) {
                        Ok(Some(released)) => {
                            eprintln!("revoked {}", id.trim());
                            rotate_advice("it was given", &released);
                        }
                        Ok(None) => eprintln!("no machine with id {}", id.trim()),
                        Err(e) => eprintln!("revoke failed: {e}"),
                    },
                    Some(("remove-device", id)) => match server.broker().vault().remove_device(id.trim()) {
                        Ok(Some(exposed)) => {
                            eprintln!("removed {}", id.trim());
                            rotate_advice("it could read", &exposed);
                        }
                        Ok(None) => eprintln!("no device with id {}", id.trim()),
                        Err(e) => eprintln!("remove failed: {e}"),
                    },
                    _ if line.trim() == "recovery-key" => {
                        // On its own thread: it may ask for the (simulated)
                        // fingerprint, and the answer arrives on this one.
                        let server = server.clone();
                        thread::spawn(move || {
                            match server.broker().vault().create_recovery_key("Create a recovery key") {
                                Ok(key) => {
                                    eprintln!("write this down and keep it offline; it is not stored and will not be shown again:");
                                    println!("{key}");
                                }
                                Err(e) => eprintln!("could not create a recovery key: {e}"),
                            }
                        });
                    }
                    _ if line.trim() == "pair" => match port {
                        None => eprintln!("start with `serve --listen <address>` to pair machines"),
                        Some(port) => {
                            match server.start_pairing(advertised(), port, 600) {
                                // On stdout, alone, so scripts can capture it.
                                Ok(token) => {
                                    eprintln!("run on the other machine within 10 minutes:  mayi pair <token>");
                                    println!("{token}");
                                }
                                Err(e) => eprintln!("pairing failed: {e}"),
                            }
                        }
                    },
                    _ if line.trim() == "add-device" => match port {
                        None => eprintln!("start with `serve --listen <address>` to add devices"),
                        Some(port) => match server.start_enrolment(advertised(), port, 600) {
                            Ok(token) => {
                                eprintln!("run on the new device within 10 minutes:  mayi-devd join <token>");
                                println!("{token}");
                            }
                            Err(e) => eprintln!("could not open an invitation: {e}"),
                        },
                    },
                    _ if line.trim().starts_with("add-device ") => {
                        let code = line.trim()["add-device ".len()..].trim().to_string();
                        // Admitting may wait for a typed fingerprint answer on this same stdin.
                        let server = server.clone();
                        thread::spawn(move || match server.add_device_by_code(&code) {
                            Ok(name) => eprintln!("added {name} to the vault"),
                            Err(e) => eprintln!("could not add the device: {e}"),
                        });
                    }
                    _ if line.trim() == "sync" => report_sync(&server),
                    _ if line.trim() == "devices" => {
                        for d in server.broker().vault().devices().unwrap_or_default() {
                            eprintln!(
                                "{}\t{}\t{}:{}{}",
                                d.id,
                                d.name,
                                d.addresses.join(","),
                                d.port,
                                if d.removed { "\tremoved" } else { "" }
                            );
                        }
                    }
                    _ if line.trim() == "machines" => {
                        for m in server.broker().vault().requesters().unwrap_or_default() {
                            eprintln!("{}\t{}{}", m.id, m.name, if m.revoked { "\trevoked" } else { "" });
                        }
                    }
                    _ if line.trim().is_empty() => {}
                    _ => eprintln!(
                        "unknown command; try `stop <run>`, `pair`, `machines`, `revoke <id>`, `add-device [code]`, `devices`, `remove-device <id>`, `recovery-key`, `sync`"
                    ),
                }
            }
            // Nobody left to answer: pending and future prompts are denied.
            terminal.closed.store(true, Ordering::SeqCst);
            lock(&terminal.waiter).take();
        }
    });

    Ok(server.serve(listener)?)
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Cmd::Init => init(),
        Cmd::Join { token, name } => join(token, name),
        Cmd::Recover { key } => recover(key),
        Cmd::Add { name, login, sites, level, fields, allow, max_grant } => {
            add(AddArgs { name, login, sites, level, fields, allow, max_grant })
        }
        Cmd::Ls => open_vault(|_| false).and_then(|vault| {
            for m in vault.list()? {
                let allow = if m.allow.is_empty() { String::new() } else { format!("\tallow: {}", m.allow.join(" | ")) };
                let allow = if m.sites.is_empty() { allow } else { format!("\tlogin for: {}", m.sites.join(", ")) };
                println!("{}\tlevel {}\t{}\tgrant ≤ {}s{allow}", m.name, m.level as u8, m.fields.join(","), m.max_grant_secs);
            }
            Ok(())
        }),
        Cmd::Rm { name } => open_vault(|_| false).and_then(|vault| Ok(vault.remove(&name)?)),
        Cmd::Log { n } => log(n),
        Cmd::Serve { listen } => serve(listen),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mayi-devd: {e}");
            ExitCode::FAILURE
        }
    }
}
