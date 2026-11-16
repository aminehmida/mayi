//! Finding the vault devices and asking them.
//!
//! A request goes to every device of the vault this machine can reach: the
//! one on this machine through its socket, and paired ones through a tunnel.
//! A device that cannot be reached is tried again every few seconds, so a
//! phone that is off or out of range can still answer when it comes back;
//! the wait for the owner's answer starts only once a device has the request.
//!
//! The device the owner is using right now is asked first, and the others a
//! little later, so the owner is not asked twice and a release that needs no
//! answer does not happen on two devices. The first decision wins; closing
//! the other connections takes their prompts down.

use std::io::{self, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mayi_proto::noise::{self, PrivateKey, MODE_SESSION};
use mayi_proto::{read_frame, write_frame, ClientMsg, Peer, RunRequest, ServerMsg};

use crate::config::{self, Config, Device};
use crate::{hostname, Channel, Failure, EXIT_TIMEOUT, EXIT_UNAVAILABLE};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// How often an unreachable device is tried: often at first, then less.
const RETRY_SOON: Duration = Duration::from_secs(5);
const RETRY_LATER: Duration = Duration::from_secs(15);
const SOON: Duration = Duration::from_secs(60);
/// After the first device answers the call, how long to wait for others
/// before choosing which to ask first.
const GATHER: Duration = Duration::from_secs(1);
/// How long the device in use has the request to itself.
const IN_USE_FIRST: Duration = Duration::from_secs(30);
/// How long the first device asked has it otherwise: enough for a release
/// that needs no answer.
const FIRST: Duration = Duration::from_secs(2);
/// A decision this quick needs no word to the agent about who was asked.
const QUIET: Duration = Duration::from_secs(1);

pub fn socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("MAYI_SOCKET") {
        return path.into();
    }
    let home = std::env::var_os("MAYI_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".mayi")
    });
    home.join("mayi.sock")
}

pub fn tcp_connect(address: &str, port: u16) -> io::Result<TcpStream> {
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

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A local time of day, for telling the agent when something happened.
pub fn clock(unix_secs: u64) -> String {
    let t = unix_secs as libc::time_t;
    // SAFETY: both pointers are valid for the call; localtime_r is reentrant.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return unix_secs.to_string();
    }
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

fn minutes(d: Duration) -> String {
    match d.as_secs() {
        s if s < 120 => format!("{s}s"),
        s => format!("{} min", s / 60),
    }
}

/// Closes a connection from outside its reader, which makes the device take
/// down a prompt it is showing.
enum Closer {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Closer {
    fn close(&self) {
        let _ = match self {
            Closer::Tcp(s) => s.shutdown(Shutdown::Both),
            Closer::Unix(s) => s.shutdown(Shutdown::Both),
        };
    }
}

/// A device that took the call, before anything was asked of it.
struct Open {
    channel: Channel,
    closer: Closer,
    peers: Vec<Peer>,
    /// The device's own tunnel key, as it says.
    sender: Option<String>,
    /// Whether its owner is using it right now.
    active: bool,
    /// For a paired device, the address and port that worked.
    address: Option<String>,
}

/// Opens the vault device on this machine and asks it for the vault's devices.
fn open_local(path: &PathBuf) -> io::Result<Open> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    let (mut reader, mut writer) = (stream.try_clone()?, stream.try_clone()?);
    write_frame(&mut writer, &ClientMsg::Peers)?;
    let (peers, sender, active) = match read_frame::<_, ServerMsg>(&mut reader)? {
        Some(ServerMsg::Peers { devices, sender, sender_active }) => (devices, sender, sender_active),
        Some(ServerMsg::Error { message }) => return Err(io::Error::other(message)),
        _ => return Err(io::Error::other("unexpected reply from the vault device")),
    };
    stream.set_read_timeout(None)?;
    Ok(Open {
        channel: Channel { reader: Box::new(reader), writer: Box::new(writer) },
        closer: Closer::Unix(stream),
        peers,
        sender,
        active,
        address: None,
    })
}

/// Opens a session tunnel to a paired device through one address, and asks
/// it for the vault's devices.
fn open_at(address: String, port: u16, private: &[u8; 32], device: &Device) -> io::Result<Open> {
    let public = device.public()?;
    let mut stream = tcp_connect(&address, port)?;
    // Bound the handshake and the first exchange; afterwards the device may
    // take minutes to decide.
    stream.set_read_timeout(Some(CONNECT_TIMEOUT))?;
    let closer = Closer::Tcp(stream.try_clone()?);
    let transport = noise::connect(&mut stream, MODE_SESSION, private, &public, None)?;
    let (mut reader, mut writer) = noise::split(transport, stream.try_clone()?, stream.try_clone()?);
    write_frame(&mut writer, &ClientMsg::Peers)?;
    let (peers, active) = match read_frame::<_, ServerMsg>(&mut reader)? {
        Some(ServerMsg::Peers { devices, sender_active, .. }) => (devices, sender_active),
        Some(ServerMsg::Error { message }) => return Err(io::Error::other(message)),
        _ => return Err(io::Error::other("unexpected reply from the vault device")),
    };
    stream.set_read_timeout(None)?;
    let shown = if address.contains(':') { format!("[{address}]") } else { address };
    Ok(Open {
        channel: Channel { reader: Box::new(reader), writer: Box::new(writer) },
        closer,
        peers,
        sender: Some(device.public_key.clone()),
        active,
        address: Some(format!("{shown}:{port}")),
    })
}

/// How long each further address waits before it is tried too.
const STAGGER: Duration = Duration::from_millis(250);

/// Opens a session tunnel to a paired device through whichever of its
/// addresses answers first: the one that worked last at once, each other a
/// moment later. At home the local network usually wins, away a VPN such as
/// Tailscale, and either may be down. Tunnels that complete later are dropped.
fn open_remote(device: &Device, private: &[u8; 32]) -> io::Result<Open> {
    let (found, results) = mpsc::channel();
    for (i, (address, port)) in device.candidates().into_iter().enumerate() {
        let (found, device, private) = (found.clone(), device.clone(), zeroize::Zeroizing::new(*private));
        thread::spawn(move || {
            thread::sleep(STAGGER * i as u32);
            let _ = found.send(open_at(address, port, &private, &device));
        });
    }
    drop(found);
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address known");
    for result in results {
        match result {
            Ok(open) => return Ok(open),
            Err(e) => last = e,
        }
    }
    Err(last)
}

#[derive(Clone)]
enum Target {
    Local(PathBuf),
    Remote(Device),
}

enum Event {
    Connected(usize, Open),
    Unreached(usize, String),
    /// A message from an asked device, or `None` once its connection closed.
    Reply(usize, Option<ServerMsg>),
}

/// What is known about one device during a search.
struct Slot {
    target: Target,
    name: String,
    key: Option<String>,
    /// Tried at least once.
    tried: bool,
    last_error: Option<String>,
    /// Gave an error or turned out to be another slot's device: not used.
    out: bool,
    conn: Option<Conn>,
}

struct Conn {
    channel: Option<Channel>,
    closer: Closer,
    active: bool,
    asked: bool,
}

impl Slot {
    fn local(&self) -> bool {
        matches!(self.target, Target::Local(_))
    }

    fn seen(&self) -> Option<u64> {
        match &self.target {
            Target::Remote(d) => d.seen,
            Target::Local(_) => None,
        }
    }

    /// For the agent: the device, and when this machine last reached it.
    fn described(&self) -> String {
        match self.seen() {
            Some(t) => format!("{} last reached {}", self.name, clock(t)),
            None if self.local() => self.name.clone(),
            None => format!("{} not reached yet", self.name),
        }
    }
}

/// Every device that could answer, each tried on its own thread.
struct Search {
    slots: Vec<Slot>,
    config: Config,
    private: Option<Arc<PrivateKey>>,
    events: mpsc::Receiver<Event>,
    sender: mpsc::Sender<Event>,
    stop: Arc<AtomicBool>,
    started: Instant,
    /// The tunnel key of the device on this machine.
    local_key: Option<String>,
}

impl Drop for Search {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Search {
    /// The vault device on this machine, unless `remote_only`, and every
    /// paired device. Fails at once if there is none at all.
    fn start(remote_only: bool) -> Result<Search, Failure> {
        let socket = socket_path();
        let pinned = std::env::var_os("MAYI_SOCKET").is_some();
        let (sender, events) = mpsc::channel();
        let mut search = Search {
            slots: Vec::new(),
            config: Config::default(),
            private: None,
            events,
            sender,
            stop: Arc::new(AtomicBool::new(false)),
            started: Instant::now(),
            local_key: None,
        };
        // A device on this machine answers at once, and tells which of the
        // paired devices it is.
        let mut local = None;
        if !remote_only && (pinned || socket.exists()) {
            search.slots.push(Slot {
                target: Target::Local(socket.clone()),
                name: "the vault device on this machine".into(),
                key: None,
                tried: true,
                last_error: None,
                out: false,
                conn: None,
            });
            match open_local(&socket) {
                Ok(open) => local = Some(open),
                Err(e) => search.slots[0].last_error = Some(e.to_string()),
            }
        }
        if !pinned {
            search.config = Config::load().map_err(|e| (EXIT_UNAVAILABLE, format!("{}: {e}", config::path().display())))?;
            for device in search.config.devices.clone() {
                search.add_remote(device);
            }
        }
        if search.slots.is_empty() {
            return Err((
                EXIT_UNAVAILABLE,
                "no vault device: none runs on this machine, and this machine is not paired (see `mayi pair`)".into(),
            ));
        }
        // Devices learnt from the local device's list are tried as they
        // are added; the paired ones from the config, here.
        let paired = search.slots.len();
        match local {
            Some(open) => search.connected(0, open),
            None if search.slots[0].local() => search.dial(0),
            None => {}
        }
        for idx in 0..paired {
            if !search.slots[idx].local() && !search.slots[idx].out {
                search.dial(idx);
            }
        }
        Ok(search)
    }

    fn add_remote(&mut self, device: Device) {
        let known = self.slots.iter().any(|s| s.key.as_deref() == Some(device.public_key.as_str()));
        if known || self.local_key.as_deref() == Some(device.public_key.as_str()) {
            return;
        }
        self.slots.push(Slot {
            name: device.name.clone(),
            key: Some(device.public_key.clone()),
            target: Target::Remote(device),
            tried: false,
            last_error: None,
            out: false,
            conn: None,
        });
    }

    fn private(&mut self) -> Result<Arc<PrivateKey>, String> {
        if self.private.is_none() {
            let key = self.config.private_key().map_err(|e| e.to_string())?;
            self.private = Some(Arc::new(key));
        }
        Ok(self.private.clone().expect("set above"))
    }

    /// Tries a device on its own thread until it answers or the search ends.
    fn dial(&mut self, idx: usize) {
        let target = self.slots[idx].target.clone();
        let private = match &target {
            Target::Remote(_) => match self.private() {
                Ok(key) => Some(key),
                Err(e) => {
                    self.slots[idx].last_error = Some(e);
                    self.slots[idx].out = true;
                    return;
                }
            },
            Target::Local(_) => None,
        };
        let (events, stop, started) = (self.sender.clone(), self.stop.clone(), self.started);
        thread::spawn(move || loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            let result = match (&target, &private) {
                (Target::Local(path), _) => open_local(path),
                (Target::Remote(device), Some(key)) => open_remote(device, key),
                (Target::Remote(_), None) => return,
            };
            let event = match result {
                Ok(open) => Event::Connected(idx, open),
                Err(e) => Event::Unreached(idx, e.to_string()),
            };
            let done = matches!(event, Event::Connected(..));
            if events.send(event).is_err() || done {
                return;
            }
            let pause = if started.elapsed() < SOON { RETRY_SOON } else { RETRY_LATER };
            let until = Instant::now() + pause;
            while Instant::now() < until {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
    }

    /// Takes a device that answered the call: learns the vault's devices
    /// from it and, for the device on this machine, pairs this machine with
    /// the vault if it is not yet, so the others can be asked too.
    fn connected(&mut self, idx: usize, mut open: Open) {
        self.slots[idx].tried = true;
        if let Some(sender) = &open.sender {
            if let Some(me) = open.peers.iter().find(|p| &p.public_key == sender) {
                self.slots[idx].name = me.name.clone();
            }
        }
        let mut changed = false;
        if self.slots[idx].local() {
            self.local_key = open.sender.clone();
            self.slots[idx].key = open.sender.clone();
            // The same device paired over the network is reached here instead.
            for other in 0..self.slots.len() {
                if other != idx && self.slots[other].key.is_some() && self.slots[other].key == self.local_key {
                    self.drop_slot(other);
                }
            }
            changed = self.enrol_here(&mut open);
        } else {
            let key = self.slots[idx].key.clone();
            if key.is_some() && key == self.local_key {
                open.closer.close();
                self.slots[idx].out = true;
                return;
            }
            if let Target::Remote(device) = self.slots[idx].target.clone() {
                if let Some(known) = self.config.devices.iter_mut().find(|d| d.public_key == device.public_key) {
                    known.reached = open.address.clone();
                    known.seen = Some(now_secs());
                    changed = true;
                }
                changed |= self.config.update_peers(&device, open.peers.clone());
            }
        }
        if changed {
            let _ = self.config.save();
            // Devices learnt from the list are tried too.
            let before = self.slots.len();
            for device in self.config.devices.clone() {
                self.add_remote(device);
            }
            for new in before..self.slots.len() {
                self.dial(new);
            }
        }
        self.slots[idx].conn = Some(Conn {
            channel: Some(open.channel),
            closer: open.closer,
            active: open.active,
            asked: false,
        });
    }

    /// Pairs this machine with the vault of the device it runs on, when that
    /// vault has other devices, and records them. Returns whether the
    /// config changed.
    fn enrol_here(&mut self, open: &mut Open) -> bool {
        let Some(sender) = open.sender.clone() else { return false };
        let Some(me) = open.peers.iter().find(|p| p.public_key == sender) else { return false };
        if !open.peers.iter().any(|p| p.public_key != sender) {
            return false;
        }
        let via = self.config.devices.iter().find(|d| d.public_key == sender).cloned().unwrap_or(Device {
            name: me.name.clone(),
            public_key: sender.clone(),
            port: me.port,
            addresses: me.addresses.clone(),
            vault: None,
            reached: None,
            seen: None,
        });
        if !self.config.knows_any(&open.peers) {
            let Ok(private) = self.private() else { return false };
            let public = hex::encode(noise::public_key(&private));
            let enrol = ClientMsg::EnrolLocal { name: hostname(), public };
            let reply = write_frame(&mut open.channel.writer, &enrol)
                .and_then(|()| read_frame::<_, ServerMsg>(&mut open.channel.reader));
            if !matches!(reply, Ok(Some(ServerMsg::Paired { .. }))) {
                // Turned off on that device, or an older one: ask it alone.
                return false;
            }
        }
        self.config.update_peers(&via, open.peers.clone())
    }

    fn drop_slot(&mut self, idx: usize) {
        self.slots[idx].out = true;
        if let Some(conn) = self.slots[idx].conn.take() {
            conn.closer.close();
        }
    }

    fn reachable(&self) -> bool {
        self.slots.iter().any(|s| !s.out)
    }

    /// Why nothing could be reached, device by device.
    fn unreachable(&self) -> String {
        self.slots
            .iter()
            .map(|s| match &s.last_error {
                Some(e) => format!("{} ({e})", s.described()),
                None => s.described(),
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn waiting_line(&self, until: Instant) -> String {
        let until = now_secs() + until.saturating_duration_since(Instant::now()).as_secs();
        let devices: Vec<String> = self.slots.iter().filter(|s| !s.out).map(Slot::described).collect();
        format!("waiting for your devices ({}) until {}", devices.join(", "), clock(until))
    }

    fn close_all_but(&mut self, keep: Option<usize>) {
        self.stop.store(true, Ordering::SeqCst);
        for (idx, slot) in self.slots.iter_mut().enumerate() {
            if Some(idx) != keep {
                if let Some(conn) = slot.conn.take() {
                    conn.closer.close();
                }
            }
        }
    }
}

/// Whether a denial is a device withdrawing on its own rather than an
/// answer. Older devices said "the requester went away".
fn withdrawn(reason: &str) -> bool {
    reason.starts_with("withdrawn") || reason == "the requester went away"
}

/// The device that took a request and its decision. For a release, the
/// connection stays open: `replies` carries a Stop, `writer` the exit.
pub struct Answer {
    pub reply: ServerMsg,
    pub replies: mpsc::Receiver<ServerMsg>,
    pub writer: Box<dyn Write + Send>,
}

/// Sends `request` to the vault's devices as described at the top. Waits up
/// to `wait` for a device to take it, then up to `timeout` for a decision.
pub fn ask(request: &RunRequest, remote_only: bool, wait: Duration, timeout: Duration) -> Result<Answer, Failure> {
    let mut search = Search::start(remote_only)?;
    let find_by = search.started + wait;
    let mut first_connected: Option<Instant> = None;
    // When the first device was asked, how long it has the request alone,
    // and the decision deadline.
    let mut asked_at: Option<Instant> = None;
    let mut alone_for = FIRST;
    let mut waiting_said = false;
    // Who was asked, to tell the agent once the decision takes a moment.
    let mut to_say: Vec<(Instant, String)> = Vec::new();
    let mut asked_names: Vec<String> = Vec::new();

    loop {
        let event = search.events.recv_timeout(Duration::from_millis(100));
        let now = Instant::now();
        match event {
            Ok(Event::Connected(idx, open)) => {
                if search.slots[idx].out {
                    open.closer.close();
                } else {
                    search.connected(idx, open);
                    first_connected.get_or_insert(now);
                }
            }
            Ok(Event::Unreached(idx, error)) => {
                search.slots[idx].tried = true;
                search.slots[idx].last_error = Some(error);
            }
            // A device that dropped the request on its own (it lost track of
            // the connection, say while the phone slept) has not answered:
            // ask it again rather than end the request.
            Ok(Event::Reply(idx, Some(ServerMsg::Denied { reason }))) if withdrawn(&reason) => {
                if let Some(conn) = search.slots[idx].conn.take() {
                    conn.closer.close();
                }
                search.slots[idx].last_error = Some("dropped the request; asking again".into());
                search.dial(idx);
            }
            Ok(Event::Reply(idx, Some(reply @ (ServerMsg::Released { .. } | ServerMsg::Denied { .. })))) => {
                let conn = search.slots[idx].conn.take().expect("asked devices are connected");
                search.close_all_but(None);
                let Some(Channel { writer, .. }) = conn.channel else { unreachable!("asked devices keep their writer") };
                // The winning device's later messages, the others dropped.
                let (tx, replies) = mpsc::channel();
                let events = std::mem::replace(&mut search.events, mpsc::channel().1);
                thread::spawn(move || {
                    for event in events {
                        match event {
                            Event::Reply(i, Some(msg)) if i == idx => {
                                if tx.send(msg).is_err() {
                                    return;
                                }
                            }
                            Event::Reply(i, None) if i == idx => return,
                            Event::Connected(_, open) => open.closer.close(),
                            _ => {}
                        }
                    }
                });
                return Ok(Answer { reply, replies, writer });
            }
            Ok(Event::Reply(idx, Some(ServerMsg::Error { message }))) => {
                search.slots[idx].last_error = Some(message.clone());
                search.drop_slot(idx);
                if !search.reachable() {
                    return Err((EXIT_UNAVAILABLE, message));
                }
            }
            Ok(Event::Reply(_, Some(_))) => {}
            Ok(Event::Reply(idx, None)) => {
                // The device went away before deciding: try it again.
                if search.slots[idx].conn.take().is_some() && !search.slots[idx].out {
                    search.slots[idx].last_error = Some("closed the connection before deciding".into());
                    search.dial(idx);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => unreachable!("the search holds a sender"),
        }

        // Choose whom to ask first, once the devices that answer quickly
        // have answered.
        let everyone_tried = search.slots.iter().all(|s| s.tried || s.out);
        let connected: Vec<usize> = (0..search.slots.len())
            .filter(|&i| search.slots[i].conn.as_ref().is_some_and(|c| !c.asked))
            .collect();
        let mut to_ask: Vec<usize> = Vec::new();
        match asked_at {
            None if !connected.is_empty() && (everyone_tried || first_connected.is_some_and(|t| now >= t + GATHER)) => {
                let active: Vec<usize> =
                    connected.iter().copied().filter(|&i| search.slots[i].conn.as_ref().is_some_and(|c| c.active)).collect();
                to_ask = if !active.is_empty() {
                    alone_for = IN_USE_FIRST;
                    active
                } else if let Some(&local) = connected.iter().find(|&&i| search.slots[i].local()) {
                    vec![local]
                } else {
                    let latest = connected.iter().copied().max_by_key(|&i| search.slots[i].seen()).expect("not empty");
                    vec![latest]
                };
                asked_at = Some(now);
            }
            Some(first) => {
                for &i in &connected {
                    let active = search.slots[i].conn.as_ref().is_some_and(|c| c.active);
                    if active || now >= first + alone_for {
                        to_ask.push(i);
                    }
                }
            }
            None => {}
        }
        for idx in to_ask {
            let conn = search.slots[idx].conn.as_mut().expect("connected");
            let mut channel = conn.channel.take().expect("not asked yet");
            if write_frame(&mut channel.writer, &ClientMsg::Run(request.clone())).is_err() {
                conn.closer.close();
                search.slots[idx].conn = None;
                search.slots[idx].last_error = Some("connection lost".into());
                search.dial(idx);
                continue;
            }
            conn.asked = true;
            conn.channel = Some(Channel { reader: Box::new(io::empty()), writer: channel.writer });
            let (events, mut reader) = (search.sender.clone(), channel.reader);
            thread::spawn(move || {
                while let Ok(Some(msg)) = read_frame::<_, ServerMsg>(&mut reader) {
                    if events.send(Event::Reply(idx, Some(msg))).is_err() {
                        return;
                    }
                }
                let _ = events.send(Event::Reply(idx, None));
            });
            let name = search.slots[idx].name.clone();
            let line = if asked_names.is_empty() {
                format!("asked {name}; waiting up to {} for your answer", minutes(timeout))
            } else {
                format!("also asked {name}")
            };
            asked_names.push(name);
            to_say.push((now + QUIET, line));
        }

        // Tell the agent only what changed, and not about a quick decision.
        to_say.retain(|(when, line)| {
            if now >= *when {
                eprintln!("mayi: {line}");
                false
            } else {
                true
            }
        });
        let nothing_up = search.slots.iter().all(|s| s.conn.is_none());
        if asked_at.is_none() && nothing_up && !waiting_said && (everyone_tried || now >= search.started + CONNECT_TIMEOUT) {
            eprintln!("mayi: {}", search.waiting_line(find_by));
            waiting_said = true;
        }

        match asked_at {
            Some(first) if now >= first + timeout => {
                return Err((
                    EXIT_TIMEOUT,
                    format!("no decision within {} (asked {})", minutes(timeout), asked_names.join(", ")),
                ));
            }
            None if now >= find_by => {
                return Err((
                    EXIT_UNAVAILABLE,
                    format!("none of your devices could be reached within {}: {}", minutes(wait), search.unreachable()),
                ));
            }
            None if !search.reachable() => {
                return Err((EXIT_UNAVAILABLE, format!("no vault device can take the request: {}", search.unreachable())));
            }
            _ => {}
        }
    }
}

/// The first device to take the call, for a question any of them can
/// answer, such as the list of secrets. Waits up to `wait`.
pub fn any(remote_only: bool, wait: Duration) -> Result<Channel, Failure> {
    let mut search = Search::start(remote_only)?;
    let find_by = search.started + wait;
    let mut waiting_said = false;
    loop {
        if let Some(idx) = search.slots.iter().position(|s| s.conn.is_some()) {
            let conn = search.slots[idx].conn.take().expect("checked");
            search.close_all_but(None);
            return Ok(conn.channel.expect("not asked"));
        }
        match search.events.recv_timeout(Duration::from_millis(100)) {
            Ok(Event::Connected(idx, open)) => search.connected(idx, open),
            Ok(Event::Unreached(idx, error)) => {
                search.slots[idx].tried = true;
                search.slots[idx].last_error = Some(error);
            }
            _ => {}
        }
        let everyone_tried = search.slots.iter().all(|s| s.tried || s.out);
        if !waiting_said && everyone_tried && search.slots.iter().all(|s| s.conn.is_none()) {
            eprintln!("mayi: {}", search.waiting_line(find_by));
            waiting_said = true;
        }
        if Instant::now() >= find_by || !search.reachable() {
            return Err((EXIT_UNAVAILABLE, format!("no vault device reachable: {}", search.unreachable())));
        }
    }
}
