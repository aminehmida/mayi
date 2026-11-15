//! Serves requesters: this machine's over a unix socket, other machines'
//! over a Noise tunnel on TCP.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use mayi_proto::noise::{self, PairingToken, TokenKind, MODE_DEVICE, MODE_ENROL, MODE_PAIRING, MODE_SESSION};
use mayi_proto::{read_frame, write_frame, ClientMsg, Peer, RunRequest, ServerMsg};

use crate::broker::{Broker, Outcome, Requester};
use crate::now_ms;
use crate::sync::{self, DeviceMsg};
use crate::vault::NewDevice;

/// How long a peer may take over the handshake before it is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_NAME_LEN: usize = 64;

type SharedWriter = Arc<Mutex<Box<dyn Write + Send>>>;

/// The socket under a connection, for noticing that the peer hung up while
/// nothing is expected from it.
trait RawSocket: Read + Send {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl RawSocket for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }
}

impl RawSocket for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
}

struct Connection {
    reader: Box<dyn Read + Send>,
    writer: SharedWriter,
    raw: Box<dyn RawSocket>,
    requester: Requester,
}

pub struct Server {
    broker: Broker,
    /// Connections of runs in progress, for sending Stop. Every write to a
    /// connection after its request was read goes through this lock.
    running: Mutex<HashMap<u64, RunConn>>,
    /// The pairing invitation currently open, if any.
    pairing: Mutex<Option<Pairing>>,
}

struct RunConn {
    writer: SharedWriter,
    released: bool,
    /// Stop was pressed before the release reached the requester.
    stop_pending: bool,
}

struct Pairing {
    kind: TokenKind,
    secret: [u8; 32],
    expires_at_ms: u64,
}

fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn send(writer: &SharedWriter, msg: &ServerMsg) -> io::Result<()> {
    write_frame(&mut *lock(writer), msg)
}

/// A name as given by another machine, made safe to show and store.
fn clean_name(name: &str) -> String {
    let cleaned: String = name.chars().filter(|c| !c.is_control()).take(MAX_NAME_LEN).collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() { "unnamed".to_string() } else { cleaned.to_string() }
}

/// This machine's IPv4 addresses that another machine could reach.
pub fn local_addresses() -> Vec<String> {
    let mut addresses = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `list` with a linked list that stays valid
    // until freeifaddrs; every pointer is checked before it is read.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return addresses;
        }
        let mut entry = list;
        while !entry.is_null() {
            let ifa = &*entry;
            entry = ifa.ifa_next;
            let up = ifa.ifa_flags & libc::IFF_UP as libc::c_uint != 0;
            let loopback = ifa.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint != 0;
            if !up || loopback || ifa.ifa_addr.is_null() {
                continue;
            }
            if i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET {
                let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                if !ip.is_link_local() {
                    addresses.push(ip.to_string());
                }
            }
        }
        libc::freeifaddrs(list);
    }
    addresses.sort();
    addresses.dedup();
    addresses
}

impl Server {
    pub fn new(broker: Broker) -> Arc<Self> {
        Arc::new(Self { broker, running: Mutex::default(), pairing: Mutex::default() })
    }

    pub fn broker(&self) -> &Broker {
        &self.broker
    }

    /// Revokes the session of a released run and tells its requester to kill
    /// the command. Returns false if the run is unknown or already finished.
    pub fn stop(&self, run_id: u64) -> bool {
        if !self.broker.stop(run_id) {
            return false;
        }
        if let Some(conn) = lock(&self.running).get_mut(&run_id) {
            if conn.released {
                let _ = send(&conn.writer, &ServerMsg::Stop);
            } else {
                conn.stop_pending = true;
            }
        }
        true
    }

    /// Binds the socket, readable and writable by the current user only.
    /// Replaces a stale socket file but refuses to take over a live one.
    pub fn bind(path: &Path) -> io::Result<UnixListener> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty() && !d.exists()) {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        if path.exists() {
            if UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another vault device is already serving {}", path.display()),
                ));
            }
            fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    /// Accepts local connections until the listener fails. One thread per
    /// requester.
    pub fn serve(self: &Arc<Self>, listener: UnixListener) -> io::Result<()> {
        for stream in listener.incoming() {
            let stream = stream?;
            let server = self.clone();
            thread::spawn(move || {
                let (Ok(reader), Ok(writer)) = (stream.try_clone(), stream.try_clone()) else { return };
                server.serve_connection(Connection {
                    reader: Box::new(reader),
                    writer: Arc::new(Mutex::new(Box::new(writer))),
                    raw: Box::new(stream),
                    // The socket is only reachable by this user on this machine.
                    requester: Requester { id: "local".into(), remote: false },
                });
            });
        }
        Ok(())
    }

    /// Opens a pairing invitation and returns the token to paste on the
    /// other machine. It can be used once, within `ttl_secs`, and replaces
    /// any invitation still open.
    pub fn start_pairing(&self, addresses: Vec<String>, port: u16, ttl_secs: u64) -> crate::Result<String> {
        self.invite(TokenKind::Machine, addresses, port, ttl_secs)
    }

    /// Like [`Server::start_pairing`], but the token admits a new vault
    /// device, which will receive the whole vault.
    pub fn start_enrolment(&self, addresses: Vec<String>, port: u16, ttl_secs: u64) -> crate::Result<String> {
        self.invite(TokenKind::Device, addresses, port, ttl_secs)
    }

    fn invite(&self, kind: TokenKind, addresses: Vec<String>, port: u16, ttl_secs: u64) -> crate::Result<String> {
        let (_, public) = self.broker.vault().noise_keypair()?;
        let token = PairingToken::new(kind, public, port, addresses);
        *lock(&self.pairing) =
            Some(Pairing { kind, secret: token.secret, expires_at_ms: now_ms() + ttl_secs * 1000 });
        Ok(token.encode())
    }

    /// The vault's devices that a machine can connect to.
    fn peers(&self) -> crate::Result<Vec<Peer>> {
        Ok(self
            .broker
            .vault()
            .devices()?
            .into_iter()
            .filter(|d| !d.removed && !d.noise_public.is_empty() && d.port != 0)
            .map(|d| Peer {
                name: d.name,
                public_key: d.noise_public,
                port: d.port,
                addresses: d.addresses,
                wake: d.wake,
            })
            .collect())
    }

    pub fn cancel_pairing(&self) {
        lock(&self.pairing).take();
    }

    /// Accepts connections from other machines until the listener fails.
    pub fn serve_tcp(self: &Arc<Self>, listener: TcpListener) -> io::Result<()> {
        for stream in listener.incoming() {
            let stream = stream?;
            let server = self.clone();
            thread::spawn(move || {
                // A failed handshake needs no reply: the peer is not one of ours.
                let _ = server.serve_tcp_connection(stream);
            });
        }
        Ok(())
    }

    fn serve_tcp_connection(&self, mut stream: TcpStream) -> io::Result<()> {
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let vault = self.broker.vault();
        let (private, _) = vault.noise_keypair().map_err(io::Error::other)?;

        let mode = noise::read_mode(&mut stream)?;
        let secret = match mode {
            MODE_SESSION | MODE_DEVICE => None,
            MODE_PAIRING | MODE_ENROL => {
                let wanted = if mode == MODE_PAIRING { TokenKind::Machine } else { TokenKind::Device };
                let pairing = lock(&self.pairing);
                match pairing.as_ref().filter(|p| p.kind == wanted && p.expires_at_ms > now_ms()) {
                    Some(open) => Some(open.secret),
                    None => return Ok(()),
                }
            }
            _ => return Ok(()),
        };
        let (transport, remote_key) = noise::accept(&mut stream, mode, &private, secret.as_ref())?;
        let (mut reader, writer) = noise::split(transport, stream.try_clone()?, stream.try_clone()?);
        let writer: SharedWriter = Arc::new(Mutex::new(Box::new(writer)));

        if let Some(secret) = secret {
            // The invitation is spent the moment a machine proves it holds it.
            let still_open = {
                let mut pairing = lock(&self.pairing);
                let matches = pairing.as_ref().is_some_and(|p| p.secret == secret);
                if matches {
                    pairing.take();
                }
                matches
            };
            if mode == MODE_ENROL {
                // Sharing level 4 keys may wait on the owner's fingerprint.
                stream.set_read_timeout(None)?;
                let reply = match read_frame::<_, DeviceMsg>(&mut reader)? {
                    Some(DeviceMsg::Enrol { name, device_pub, biometric_pub, noise_public }) if still_open => {
                        let name = clean_name(&name);
                        let new = (|| {
                            Some(NewDevice {
                                name: name.clone(),
                                device_pub: hex::decode(device_pub).ok()?,
                                biometric_pub: hex::decode(biometric_pub).ok()?,
                                noise_public: Some(hex::decode(noise_public).ok()?.try_into().ok()?),
                            })
                        })();
                        let prompt = format!("Add {name} as a device of this vault");
                        match new.map(|new| vault.enrol_device(new, &prompt)) {
                            Some(Ok(bootstrap)) => {
                                self.broker.ui().device_added(&name);
                                DeviceMsg::Enrolled {
                                    device_id: bootstrap.device_id,
                                    wrapped_vk: hex::encode(bootstrap.wrapped_vk),
                                }
                            }
                            Some(Err(e)) => DeviceMsg::Error { message: e.to_string() },
                            None => DeviceMsg::Error { message: "damaged enrolment request".into() },
                        }
                    }
                    _ => DeviceMsg::Error { message: "enrolment failed".into() },
                };
                return write_frame(&mut *lock(&writer), &reply);
            }
            let reply = match read_frame::<_, ClientMsg>(&mut reader)? {
                Some(ClientMsg::Pair { name }) if still_open => {
                    let record =
                        vault.add_requester(&clean_name(&name), remote_key).map_err(io::Error::other)?;
                    self.broker.ui().paired(&record.name, &record.id);
                    ServerMsg::Paired { device: vault.device_name().map_err(io::Error::other)? }
                }
                Some(_) | None => ServerMsg::Error { message: "pairing failed".into() },
            };
            return send(&writer, &reply);
        }

        if mode == MODE_DEVICE {
            if vault.device_by_noise_key(&remote_key).map_err(io::Error::other)?.is_none() {
                let refusal = DeviceMsg::Error { message: "not a device of this vault".into() };
                return write_frame(&mut *lock(&writer), &refusal);
            }
            let Some(DeviceMsg::Digest { entries }) = read_frame::<_, DeviceMsg>(&mut reader)? else {
                return Ok(());
            };
            let changed = sync::sync_as_callee(vault, &entries, &mut reader, &mut *lock(&writer))
                .map_err(io::Error::other)?;
            if changed > 0 {
                self.broker.ui().synced(changed);
            }
            return Ok(());
        }

        let Some(machine) = vault.requester_by_key(&remote_key).map_err(io::Error::other)? else {
            return send(&writer, &ServerMsg::Error { message: "this machine is not paired".into() });
        };
        // Approvals can take minutes; only the handshake is on a clock.
        stream.set_read_timeout(None)?;
        self.serve_connection(Connection {
            reader: Box::new(reader),
            writer,
            raw: Box::new(stream),
            requester: Requester { id: machine.label(), remote: true },
        });
        Ok(())
    }

    /// Runs a request while watching the connection, so that a requester
    /// that gives up (Ctrl-C, timeout) does not leave a prompt on screen.
    fn run_watched(&self, conn: &mut Connection, request: &RunRequest) -> Outcome {
        let run_id = self.broker.reserve_run();
        lock(&self.running)
            .insert(run_id, RunConn { writer: conn.writer.clone(), released: false, stop_pending: false });
        let decided = AtomicBool::new(false);
        let (raw, requester) = (&mut conn.raw, &conn.requester);
        let outcome = thread::scope(|scope| {
            scope.spawn(|| {
                // The requester sends nothing while it waits, so anything
                // readable on the socket is the end of the stream (or a
                // peer breaking the protocol, which is treated the same).
                let _ = raw.set_read_timeout(Some(Duration::from_millis(25)));
                let mut byte = [0u8; 1];
                while !decided.load(Ordering::SeqCst) {
                    match raw.read(&mut byte) {
                        Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                        _ => {
                            if !decided.load(Ordering::SeqCst) {
                                self.broker.withdraw(run_id);
                            }
                            break;
                        }
                    }
                }
                // The timeout is shared with the connection's reader.
                let _ = raw.set_read_timeout(None);
            });
            let outcome = self.broker.run_reserved(run_id, request, requester);
            decided.store(true, Ordering::SeqCst);
            outcome
        });
        if matches!(outcome, Outcome::Denied(_)) {
            lock(&self.running).remove(&run_id);
        }
        outcome
    }

    fn serve_connection(&self, mut conn: Connection) {
        let mut run: Option<u64> = None;
        while let Ok(Some(msg)) = read_frame::<_, ClientMsg>(&mut conn.reader) {
            let reply = match msg {
                ClientMsg::List => match self.broker.list() {
                    Ok(secrets) => ServerMsg::Secrets { secrets },
                    Err(e) => ServerMsg::Error { message: e.to_string() },
                },
                ClientMsg::Run(_) if run.is_some() => {
                    ServerMsg::Error { message: "one run per connection".into() }
                }
                ClientMsg::Run(request) => match self.run_watched(&mut conn, &request) {
                    Outcome::Released { run_id, env } => {
                        run = Some(run_id);
                        let released = ServerMsg::Released {
                            run_id,
                            env: env.iter().map(|(k, v)| (k.clone(), v.to_string())).collect(),
                        };
                        let mut running = lock(&self.running);
                        let mut sent = send(&conn.writer, &released);
                        if let Some(entry) = running.get_mut(&run_id) {
                            entry.released = true;
                            if sent.is_ok() && entry.stop_pending {
                                sent = send(&conn.writer, &ServerMsg::Stop);
                            }
                        }
                        drop(running);
                        if sent.is_err() {
                            break;
                        }
                        continue;
                    }
                    Outcome::Denied(reason) => ServerMsg::Denied { reason },
                },
                ClientMsg::Done { exit } => {
                    if let Some(run_id) = run.take() {
                        lock(&self.running).remove(&run_id);
                        self.broker.finished(run_id, exit);
                    }
                    continue;
                }
                ClientMsg::Pair { .. } => {
                    ServerMsg::Error { message: "pairing needs a pairing tunnel".into() }
                }
                ClientMsg::Peers => match self.peers() {
                    Ok(devices) => ServerMsg::Peers { devices },
                    Err(e) => ServerMsg::Error { message: e.to_string() },
                },
            };
            if send(&conn.writer, &reply).is_err() {
                break;
            }
        }
        if let Some(run_id) = run {
            lock(&self.running).remove(&run_id);
            self.broker.finished(run_id, None);
        }
    }
}

// --- This device calling other devices --------------------------------------

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Enrolment can wait for the owner's fingerprint on the other device.
const ENROL_TIMEOUT: Duration = Duration::from_secs(120);

type Tunnel = (noise::NoiseReader<TcpStream>, noise::NoiseWriter<TcpStream>);

/// Opens a tunnel to another device, trying each of its addresses.
fn dial(
    addresses: &[String],
    port: u16,
    mode: u8,
    private: &[u8; 32],
    public: &[u8; 32],
    psk: Option<&[u8; 32]>,
    reply_timeout: Duration,
) -> io::Result<Tunnel> {
    use std::net::ToSocketAddrs;
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address known");
    for address in addresses {
        let attempt = (address.as_str(), port).to_socket_addrs().and_then(|mut addrs| {
            let addr = addrs.next().ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "address did not resolve"))?;
            let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
            stream.set_nodelay(true)?;
            stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
            let transport = noise::connect(&mut stream, mode, private, public, psk)?;
            stream.set_read_timeout(Some(reply_timeout))?;
            Ok(noise::split(transport, stream.try_clone()?, stream))
        });
        match attempt {
            Ok(tunnel) => return Ok(tunnel),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn sync_over(
    vault: &crate::vault::Vault,
    addresses: &[String],
    port: u16,
    public: &[u8; 32],
) -> crate::Result<usize> {
    let (private, _) = vault.noise_keypair()?;
    let (mut reader, mut writer) =
        dial(addresses, port, MODE_DEVICE, &private, public, None, Duration::from_secs(30))?;
    sync::sync_as_caller(vault, &mut reader, &mut writer)
}

/// Redeems an enrolment token: asks the device that issued it to admit this
/// one, creates the local copy of the vault at `path`, and fills it with a
/// first sync.
pub fn join_vault(
    path: &Path,
    hw: Arc<dyn crate::hardware::HardwareKeys>,
    device_name: &str,
    token: &str,
) -> crate::Result<crate::vault::Vault> {
    use crate::vault::{Bootstrap, Vault};
    let token = PairingToken::decode(token)?;
    if token.kind != TokenKind::Device {
        return Err(crate::Error::Vault(
            "this token pairs a machine; a device needs the token from \"Add a device\"".into(),
        ));
    }
    if path.exists() {
        return Err(crate::Error::Vault("this device already has a vault".into()));
    }
    let (private, public) = noise::generate_keypair()?;
    let (mut reader, mut writer) = dial(
        &token.addresses,
        token.port,
        MODE_ENROL,
        &private,
        &token.device_public,
        Some(&token.secret),
        ENROL_TIMEOUT,
    )?;
    write_frame(
        &mut writer,
        &DeviceMsg::Enrol {
            name: device_name.to_string(),
            device_pub: hex::encode(hw.device_public()),
            biometric_pub: hex::encode(hw.biometric_public()),
            noise_public: hex::encode(public),
        },
    )?;
    let bootstrap = match read_frame::<_, DeviceMsg>(&mut reader)? {
        Some(DeviceMsg::Enrolled { device_id, wrapped_vk }) => Bootstrap {
            device_id,
            wrapped_vk: hex::decode(wrapped_vk).map_err(|_| crate::Error::Crypto)?,
        },
        Some(DeviceMsg::Error { message }) => return Err(crate::Error::Vault(message)),
        _ => return Err(crate::Error::Vault("the other device did not answer the enrolment".into())),
    };
    let vault = Vault::join(path, hw, device_name, &bootstrap, (&private, &public))?;
    sync_over(&vault, &token.addresses, token.port, &token.device_public)?;
    Ok(vault)
}

impl Server {
    /// Publishes where this device can be reached, for other devices and
    /// machines to find it. Returns whether that changed.
    pub fn announce(&self, port: u16, addresses: Vec<String>, wake: Option<mayi_proto::Wake>) -> crate::Result<bool> {
        self.broker.vault().set_info(port, addresses, wake)
    }

    /// Syncs with every other device of the vault that can be reached now.
    /// Returns, per device name, how many records changed here or why it
    /// could not be reached.
    pub fn sync_all(&self) -> crate::Result<Vec<(String, Result<usize, String>)>> {
        let vault = self.broker.vault();
        let mut results = Vec::new();
        let mut total = 0;
        for device in vault.devices()? {
            if device.id == vault.device_id() || device.removed || device.recovery || device.noise_public.is_empty() || device.port == 0 {
                continue;
            }
            let outcome = hex::decode(&device.noise_public)
                .ok()
                .and_then(|k| <[u8; 32]>::try_from(k).ok())
                .ok_or_else(|| "damaged device record".to_string())
                .and_then(|public| {
                    sync_over(vault, &device.addresses, device.port, &public).map_err(|e| e.to_string())
                });
            total += outcome.as_ref().copied().unwrap_or(0);
            results.push((device.name, outcome));
        }
        if total > 0 {
            self.broker.ui().synced(total);
        }
        Ok(results)
    }
}
