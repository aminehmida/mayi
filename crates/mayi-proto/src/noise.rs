//! The encrypted tunnel between a requester on another machine and a vault
//! device. See `docs/protocol.md`.
//!
//! Two handshakes, both from the Noise framework via the `snow` crate:
//! - pairing: `IKpsk2`, keyed by the one-time secret in a pairing token;
//! - session: `IK`, between static keys exchanged at pairing.
//!
//! In both, the requester is the initiator and already knows the vault
//! device's static key, so it never talks to an impostor.

use std::io::{self, Read, Write};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use snow::StatelessTransportState;
use zeroize::Zeroizing;

const SESSION_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PAIRING_PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

/// A paired machine sending requests.
pub const MODE_SESSION: u8 = 1;
/// A machine redeeming a pairing token.
pub const MODE_PAIRING: u8 = 2;
/// A new vault device redeeming an enrolment token.
pub const MODE_ENROL: u8 = 3;
/// Two vault devices of the same vault syncing.
pub const MODE_DEVICE: u8 = 4;

/// Default TCP port a vault device listens on for other machines.
pub const DEFAULT_PORT: u16 = 7462;

const MACHINE_PREFIX: &str = "mayi1.";
const DEVICE_PREFIX: &str = "mayid1.";
/// Largest Noise message, and the authentication tag inside it.
const MAX_MESSAGE: usize = 65535;
const TAG_LEN: usize = 16;

pub type PublicKey = [u8; 32];
pub type PrivateKey = Zeroizing<[u8; 32]>;

fn noise_error(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("encrypted tunnel: {e}"))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

pub fn generate_keypair() -> io::Result<(PrivateKey, PublicKey)> {
    let pair = snow::Builder::new(SESSION_PATTERN.parse().map_err(noise_error)?)
        .generate_keypair()
        .map_err(noise_error)?;
    let private: [u8; 32] = pair.private.as_slice().try_into().map_err(|_| invalid("key size"))?;
    let public: [u8; 32] = pair.public.as_slice().try_into().map_err(|_| invalid("key size"))?;
    Ok((Zeroizing::new(private), public))
}

/// Short identifier of a static key, used to name a paired machine.
pub fn fingerprint(public: &PublicKey) -> String {
    hex::encode(&Sha256::digest(public)[..8])
}

/// What a vault device hands to a machine that wants to pair: who the device
/// is, where to reach it, and a one-time secret proving the machine was
/// invited. It is pasted as text, so it carries a full 256-bit secret rather
/// than a short code that would need a PAKE.
/// What a token invites its holder to become.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenKind {
    /// A requester: may ask for secrets, stores none.
    Machine,
    /// A vault device: receives the whole vault.
    Device,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingToken {
    pub kind: TokenKind,
    pub device_public: PublicKey,
    pub secret: [u8; 32],
    pub port: u16,
    pub addresses: Vec<String>,
}

impl PairingToken {
    pub fn new(kind: TokenKind, device_public: PublicKey, port: u16, addresses: Vec<String>) -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self { kind, device_public, secret, port, addresses }
    }

    pub fn encode(&self) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.device_public);
        bytes.extend_from_slice(&self.secret);
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes.extend_from_slice(self.addresses.join(",").as_bytes());
        let prefix = match self.kind {
            TokenKind::Machine => MACHINE_PREFIX,
            TokenKind::Device => DEVICE_PREFIX,
        };
        format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(token: &str) -> io::Result<Self> {
        let token = token.trim();
        let (kind, body) = if let Some(body) = token.strip_prefix(MACHINE_PREFIX) {
            (TokenKind::Machine, body)
        } else if let Some(body) = token.strip_prefix(DEVICE_PREFIX) {
            (TokenKind::Device, body)
        } else {
            return Err(invalid("not a Mayi pairing token"));
        };
        let bytes = URL_SAFE_NO_PAD.decode(body).map_err(|_| invalid("damaged pairing token"))?;
        if bytes.len() < 66 {
            return Err(invalid("damaged pairing token"));
        }
        let addresses = std::str::from_utf8(&bytes[66..])
            .map_err(|_| invalid("damaged pairing token"))?
            .split(',')
            .filter(|a| !a.is_empty())
            .map(String::from)
            .collect();
        Ok(Self {
            kind,
            device_public: bytes[..32].try_into().expect("32 bytes"),
            secret: bytes[32..64].try_into().expect("32 bytes"),
            port: u16::from_be_bytes([bytes[64], bytes[65]]),
            addresses,
        })
    }
}

/// Binds the handshake to the protocol version and to its purpose, so a
/// pairing handshake cannot be replayed as a session or the reverse.
fn prologue(mode: u8) -> [u8; 7] {
    [b'm', b'a', b'y', b'i', b'/', b'1', mode]
}

fn write_message<W: Write>(w: &mut W, message: &[u8]) -> io::Result<()> {
    w.write_all(&(message.len() as u16).to_be_bytes())?;
    w.write_all(message)?;
    w.flush()
}

fn read_message<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let mut message = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut message)?;
    Ok(message)
}

fn builder<'a>(
    mode: u8,
    local_private: &'a [u8; 32],
    psk: Option<&'a [u8; 32]>,
) -> io::Result<snow::Builder<'a>> {
    let pattern = match (mode, psk) {
        (MODE_SESSION | MODE_DEVICE, None) => SESSION_PATTERN,
        (MODE_PAIRING | MODE_ENROL, Some(_)) => PAIRING_PATTERN,
        _ => return Err(invalid("unknown tunnel mode")),
    };
    let mut builder = snow::Builder::new(pattern.parse().map_err(noise_error)?)
        .local_private_key(local_private)
        .map_err(noise_error)?;
    if let Some(psk) = psk {
        builder = builder.psk(2, psk).map_err(noise_error)?;
    }
    Ok(builder)
}

/// Requester side. Fails unless the peer holds the private half of
/// `device_public` and, when pairing, knows the token's secret.
pub fn connect<S: Read + Write>(
    stream: &mut S,
    mode: u8,
    local_private: &[u8; 32],
    device_public: &PublicKey,
    psk: Option<&[u8; 32]>,
) -> io::Result<StatelessTransportState> {
    let prologue = prologue(mode);
    let mut handshake = builder(mode, local_private, psk)?
        .remote_public_key(device_public)
        .map_err(noise_error)?
        .prologue(&prologue)
        .map_err(noise_error)?
        .build_initiator()
        .map_err(noise_error)?;
    let mut buf = vec![0u8; MAX_MESSAGE];
    stream.write_all(&[mode])?;
    let n = handshake.write_message(&[], &mut buf).map_err(noise_error)?;
    write_message(stream, &buf[..n])?;
    let reply = read_message(stream)?;
    handshake.read_message(&reply, &mut buf).map_err(noise_error)?;
    handshake.into_stateless_transport_mode().map_err(noise_error)
}

/// Vault device side, first step: which kind of tunnel is being opened.
pub fn read_mode<S: Read>(stream: &mut S) -> io::Result<u8> {
    let mut mode = [0u8; 1];
    stream.read_exact(&mut mode)?;
    Ok(mode[0])
}

/// Vault device side, after [`read_mode`]. Returns the tunnel and the
/// requester's static key, which the caller must check against the machines
/// it has paired before trusting anything sent through a session tunnel.
pub fn accept<S: Read + Write>(
    stream: &mut S,
    mode: u8,
    local_private: &[u8; 32],
    psk: Option<&[u8; 32]>,
) -> io::Result<(StatelessTransportState, PublicKey)> {
    let prologue = prologue(mode);
    let mut handshake = builder(mode, local_private, psk)?
        .prologue(&prologue)
        .map_err(noise_error)?
        .build_responder()
        .map_err(noise_error)?;
    let mut buf = vec![0u8; MAX_MESSAGE];
    let first = read_message(stream)?;
    handshake.read_message(&first, &mut buf).map_err(noise_error)?;
    let remote: PublicKey = handshake
        .get_remote_static()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| invalid("no requester key in handshake"))?;
    let n = handshake.write_message(&[], &mut buf).map_err(noise_error)?;
    write_message(stream, &buf[..n])?;
    Ok((handshake.into_stateless_transport_mode().map_err(noise_error)?, remote))
}

/// Splits an established tunnel into independent halves, so one thread can
/// wait for messages while another sends.
pub fn split<R: Read, W: Write>(
    transport: StatelessTransportState,
    reader: R,
    writer: W,
) -> (NoiseReader<R>, NoiseWriter<W>) {
    let transport = Arc::new(transport);
    (
        NoiseReader { inner: reader, transport: transport.clone(), nonce: 0, plain: Vec::new(), pos: 0 },
        NoiseWriter { inner: writer, transport, nonce: 0, pending: Vec::new() },
    )
}

/// Encrypts what is written to it. Data is sent on `flush`, as records of a
/// 2-byte length and one Noise message each.
pub struct NoiseWriter<W: Write> {
    inner: W,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
    pending: Vec<u8>,
}

impl<W: Write> Write for NoiseWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut record = vec![0u8; MAX_MESSAGE];
        for chunk in self.pending.chunks(MAX_MESSAGE - TAG_LEN) {
            let n = self
                .transport
                .write_message(self.nonce, chunk, &mut record)
                .map_err(noise_error)?;
            self.nonce += 1;
            self.inner.write_all(&(n as u16).to_be_bytes())?;
            self.inner.write_all(&record[..n])?;
        }
        self.pending.clear();
        self.inner.flush()
    }
}

/// Decrypts records written by a [`NoiseWriter`]. Records must arrive in
/// order: a replayed, dropped or reordered record fails authentication.
pub struct NoiseReader<R: Read> {
    inner: R,
    transport: Arc<StatelessTransportState>,
    nonce: u64,
    plain: Vec<u8>,
    pos: usize,
}

impl<R: Read> Read for NoiseReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos == self.plain.len() {
            let mut len = [0u8; 2];
            match self.inner.read_exact(&mut len) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(0),
                Err(e) => return Err(e),
            }
            let mut record = vec![0u8; u16::from_be_bytes(len) as usize];
            self.inner.read_exact(&mut record)?;
            self.plain.resize(record.len(), 0);
            let n = self
                .transport
                .read_message(self.nonce, &record, &mut self.plain)
                .map_err(noise_error)?;
            self.nonce += 1;
            self.plain.truncate(n);
            self.pos = 0;
        }
        let n = out.len().min(self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A one-way byte pipe; two of them make a connection.
    #[derive(Clone, Default)]
    struct Pipe(Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>);

    impl Write for Pipe {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Read for Pipe {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let mut queue = self.0.lock().unwrap();
            let n = out.len().min(queue.len());
            for byte in out.iter_mut().take(n) {
                *byte = queue.pop_front().unwrap();
            }
            Ok(n)
        }
    }

    struct Duplex {
        incoming: Pipe,
        outgoing: Pipe,
    }

    impl Read for Duplex {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(out)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.outgoing.write(data)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Runs both sides of a handshake on two threads over in-memory pipes.
    fn handshake(
        mode: u8,
        client_psk: Option<[u8; 32]>,
        server_psk: Option<[u8; 32]>,
        claimed_device: Option<PublicKey>,
    ) -> (io::Result<StatelessTransportState>, io::Result<(StatelessTransportState, PublicKey)>, PublicKey, Pipe, Pipe)
    {
        let (client_private, client_public) = generate_keypair().unwrap();
        let (device_private, device_public) = generate_keypair().unwrap();
        let (to_device, to_client) = (Pipe::default(), Pipe::default());
        let mut device_end = BlockingDuplex(Duplex { incoming: to_device.clone(), outgoing: to_client.clone() });
        let mut client_end = BlockingDuplex(Duplex { incoming: to_client.clone(), outgoing: to_device.clone() });
        let server = std::thread::spawn(move || {
            let mode = read_mode(&mut device_end)?;
            accept(&mut device_end, mode, &device_private, server_psk.as_ref())
        });
        let target = claimed_device.unwrap_or(device_public);
        let client = connect(&mut client_end, mode, &client_private, &target, client_psk.as_ref());
        if client.is_err() {
            // Unblock the server thread, which is waiting for more bytes.
            to_device.clone().write_all(&[0u8; 4]).unwrap();
        }
        let server = server.join().unwrap();
        (client, server, client_public, to_device, to_client)
    }

    /// Pipes return 0 when empty; handshakes need blocking reads.
    struct BlockingDuplex(Duplex);

    impl Read for BlockingDuplex {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            for _ in 0..2000 {
                let n = self.0.read(out)?;
                if n > 0 {
                    return Ok(n);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(io::Error::new(io::ErrorKind::TimedOut, "no data"))
        }
    }

    impl Write for BlockingDuplex {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.write(data)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn token_round_trip() {
        let token = PairingToken::new(TokenKind::Machine, [7u8; 32], 7462, vec!["192.168.1.5".into(), "mac.tail.ts.net".into()]);
        let text = token.encode();
        assert!(text.starts_with("mayi1."));
        assert_eq!(PairingToken::decode(&format!("  {text}\n")).unwrap(), token);
        assert!(PairingToken::decode("hello").is_err());
        assert!(PairingToken::decode("mayi1.AAAA").is_err());
        let empty = PairingToken::new(TokenKind::Device, [1u8; 32], 1, vec![]);
        assert!(empty.encode().starts_with("mayid1."));
        assert_eq!(PairingToken::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn session_tunnel_carries_data_both_ways() {
        let (client, server, client_public, to_device, to_client) = handshake(MODE_SESSION, None, None, None);
        let (server, seen_public) = server.unwrap();
        assert_eq!(seen_public, client_public, "the device learns who is calling");

        let (mut client_reader, mut client_writer) = split(client.unwrap(), to_client.clone(), to_device.clone());
        let (mut device_reader, mut device_writer) = split(server, to_device.clone(), to_client);

        // Larger than one Noise message, to exercise chunking.
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        client_writer.write_all(&big).unwrap();
        client_writer.flush().unwrap();
        assert!(!to_device.0.lock().unwrap().iter().copied().collect::<Vec<u8>>().windows(64).any(|w| w == &big[..64]));
        let mut got = vec![0u8; big.len()];
        device_reader.read_exact(&mut got).unwrap();
        assert_eq!(got, big);

        device_writer.write_all(b"reply").unwrap();
        device_writer.flush().unwrap();
        let mut reply = [0u8; 5];
        client_reader.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"reply");
        assert_eq!(client_reader.read(&mut reply).unwrap(), 0, "clean end of stream");
    }

    #[test]
    fn tampered_or_replayed_records_are_rejected() {
        let (client, server, _, _, _) = handshake(MODE_SESSION, None, None, None);
        let mut wire = Vec::new();
        let (_, mut writer) = split(client.unwrap(), io::empty(), &mut wire);
        writer.write_all(b"one").unwrap();
        writer.flush().unwrap();
        drop(writer);

        let server = Arc::new(server.unwrap().0);
        let reader = |bytes: Vec<u8>| NoiseReader {
            inner: Cursor::new(bytes),
            transport: server.clone(),
            nonce: 0,
            plain: Vec::new(),
            pos: 0,
        };
        let mut out = [0u8; 3];
        reader(wire.clone()).read_exact(&mut out).unwrap();
        assert_eq!(&out, b"one");

        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(reader(tampered).read_exact(&mut out).is_err());

        // The same record twice: the second copy is out of sequence.
        let mut replay = reader([wire.clone(), wire].concat());
        replay.read_exact(&mut out).unwrap();
        assert!(replay.read_exact(&mut out).is_err());
    }

    #[test]
    fn pairing_needs_the_token_secret() {
        let secret = [9u8; 32];
        let (client, server, _, _, _) = handshake(MODE_PAIRING, Some(secret), Some(secret), None);
        assert!(client.is_ok() && server.is_ok());
        let (client, server, _, _, _) = handshake(MODE_PAIRING, Some([1u8; 32]), Some(secret), None);
        assert!(client.is_err() || server.is_err());
    }

    #[test]
    fn wrong_device_key_fails() {
        let (_, impostor) = generate_keypair().unwrap();
        let (client, server, _, _, _) = handshake(MODE_SESSION, None, None, Some(impostor));
        assert!(client.is_err() || server.is_err());
    }

    #[test]
    fn mode_and_secret_must_agree() {
        let key = [0u8; 32];
        assert!(builder(MODE_SESSION, &key, Some(&key)).is_err());
        assert!(builder(MODE_PAIRING, &key, None).is_err());
        assert!(builder(9, &key, None).is_err());
    }
}
