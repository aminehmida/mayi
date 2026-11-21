//! A requester on "another machine" (a TCP connection to this process)
//! pairing with a vault device and using it through the encrypted tunnel.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use mayi_core::broker::{Approval, Broker, Notice, Prompt, Ui};
use mayi_core::hardware::SoftwareKeys;
use mayi_core::model::{Destination, Level, NewItem};
use mayi_core::policy::Rules;
use mayi_core::server::Server;
use mayi_core::vault::Vault;
use mayi_proto::noise::{self, NoiseReader, NoiseWriter, PairingToken, PrivateKey, PublicKey, MODE_PAIRING, MODE_SESSION};
use mayi_proto::{read_frame, write_frame, Binding, ClientMsg, RunRequest, ServerMsg};
use zeroize::Zeroizing;

/// Never answers a prompt; only a withdrawal ends it.
#[derive(Default)]
struct WaitingUi {
    withdrawn: Mutex<Vec<u64>>,
    changed: Condvar,
    prompts: AtomicUsize,
    notices: AtomicUsize,
    paired: Mutex<Vec<String>>,
}

impl Ui for WaitingUi {
    fn approve(&self, prompt: &Prompt) -> Approval {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        let guard = self.withdrawn.lock().unwrap();
        let _guard = self
            .changed
            .wait_timeout_while(guard, Duration::from_secs(10), |w| !w.contains(&prompt.run_id))
            .unwrap();
        Approval::Deny
    }

    fn withdraw(&self, run_id: u64) {
        self.withdrawn.lock().unwrap().push(run_id);
        self.changed.notify_all();
    }

    fn notify(&self, _: &Notice) {
        self.notices.fetch_add(1, Ordering::SeqCst);
    }

    fn paired(&self, name: &str, _id: &str) {
        self.paired.lock().unwrap().push(name.to_string());
    }
}

struct Device {
    server: Arc<Server>,
    ui: Arc<WaitingUi>,
    addr: SocketAddr,
    _dir: tempfile::TempDir,
}

fn device() -> Device {
    let dir = tempfile::tempdir().unwrap();
    let vault =
        Vault::create(&dir.path().join("v.db"), Arc::new(SoftwareKeys::generate(|_| true)), "test-mac").unwrap();
    for (name, level) in [("L1", Level::Log), ("L3", Level::Approve)] {
        vault
            .put(NewItem {
                name: name.into(),
                level,
                values: [("value".to_string(), Zeroizing::new(format!("{name}-secret")))].into_iter().collect(),
                allow: vec![],
                max_grant_secs: 600,
                destination: Destination::Command,
                sites: vec![],
                folder: None,
            })
            .unwrap();
    }
    let ui = Arc::new(WaitingUi::default());
    let server = Server::new(Broker::new(vault, ui.clone(), Rules::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn({
        let server = server.clone();
        move || server.serve_tcp(listener)
    });
    Device { server, ui, addr, _dir: dir }
}

type Tunnel = (NoiseReader<TcpStream>, NoiseWriter<TcpStream>);

fn tunnel(
    addr: SocketAddr,
    mode: u8,
    private: &PrivateKey,
    device_public: &PublicKey,
    psk: Option<&[u8; 32]>,
) -> io::Result<Tunnel> {
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let transport = noise::connect(&mut stream, mode, private, device_public, psk)?;
    Ok(noise::split(transport, stream.try_clone()?, stream))
}

fn ask(tunnel: &mut Tunnel, msg: &ClientMsg) -> Option<ServerMsg> {
    write_frame(&mut tunnel.1, msg).unwrap();
    read_frame(&mut tunnel.0).unwrap()
}

/// Pairs a fresh machine and returns its key and the device's.
fn pair(device: &Device, name: &str) -> (PrivateKey, PublicKey) {
    let token = PairingToken::decode(
        &device.server.start_pairing(vec!["127.0.0.1".into()], device.addr.port(), 60).unwrap(),
    )
    .unwrap();
    let (private, _) = noise::generate_keypair().unwrap();
    let mut t = tunnel(device.addr, MODE_PAIRING, &private, &token.device_public, Some(&token.secret)).unwrap();
    match ask(&mut t, &ClientMsg::Pair { name: name.into() }) {
        Some(ServerMsg::Paired { device }) => assert_eq!(device, "test-mac"),
        other => panic!("unexpected reply: {other:?}"),
    }
    (private, token.device_public)
}

fn run_request(item: &str) -> ClientMsg {
    ClientMsg::Run(RunRequest {
        bindings: vec![Binding { env: "TOKEN".into(), item: item.into(), field: "value".into() }],
        argv: vec!["make".into(), "deploy".into()],
        reason: "remote test".into(),
        session: "s".into(),
        ..Default::default()
    })
}

#[test]
fn paired_machine_gets_secrets_through_the_tunnel() {
    let device = device();
    let (private, device_public) = pair(&device, "build-vm\u{7}\n");
    assert_eq!(*device.ui.paired.lock().unwrap(), ["build-vm"], "control characters are dropped");

    let mut t = tunnel(device.addr, MODE_SESSION, &private, &device_public, None).unwrap();
    match ask(&mut t, &ClientMsg::List) {
        Some(ServerMsg::Secrets { secrets }) => {
            assert_eq!(secrets.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["L1", "L3"])
        }
        other => panic!("unexpected reply: {other:?}"),
    }
    match ask(&mut t, &run_request("L1")) {
        Some(ServerMsg::Released { env, .. }) => assert_eq!(env["TOKEN"], "L1-secret"),
        other => panic!("unexpected reply: {other:?}"),
    }
    // A silent secret is raised to a notification when the request is remote.
    assert_eq!(device.ui.notices.load(Ordering::SeqCst), 1);
    write_frame(&mut t.1, &ClientMsg::Done { exit: Some(0) }).unwrap();

    let log = device.server.broker().vault().audit_tail(1).unwrap();
    let machine = &device.server.broker().vault().requesters().unwrap()[0];
    assert!(log[0].remote);
    assert_eq!(log[0].requester, machine.label());
    assert!(machine.label().starts_with("build-vm ("));
}

#[test]
fn a_token_works_once_and_expires() {
    let device = device();
    let text = device.server.start_pairing(vec![], device.addr.port(), 60).unwrap();
    let token = PairingToken::decode(&text).unwrap();
    let (first, _) = noise::generate_keypair().unwrap();
    let mut t = tunnel(device.addr, MODE_PAIRING, &first, &token.device_public, Some(&token.secret)).unwrap();
    assert!(matches!(ask(&mut t, &ClientMsg::Pair { name: "a".into() }), Some(ServerMsg::Paired { .. })));

    let (second, _) = noise::generate_keypair().unwrap();
    assert!(tunnel(device.addr, MODE_PAIRING, &second, &token.device_public, Some(&token.secret)).is_err());

    let expired = PairingToken::decode(&device.server.start_pairing(vec![], device.addr.port(), 0).unwrap()).unwrap();
    assert!(tunnel(device.addr, MODE_PAIRING, &second, &expired.device_public, Some(&expired.secret)).is_err());

    let open = PairingToken::decode(&device.server.start_pairing(vec![], device.addr.port(), 60).unwrap()).unwrap();
    assert!(
        tunnel(device.addr, MODE_PAIRING, &second, &open.device_public, Some(&[0u8; 32])).is_err(),
        "a wrong secret does not pair"
    );
    device.server.cancel_pairing();
    assert!(tunnel(device.addr, MODE_PAIRING, &second, &open.device_public, Some(&open.secret)).is_err());
    assert_eq!(device.server.broker().vault().requesters().unwrap().len(), 1);
}

#[test]
fn unknown_and_revoked_machines_are_refused() {
    let device = device();
    let (private, device_public) = pair(&device, "vm");

    let (stranger, _) = noise::generate_keypair().unwrap();
    let mut t = tunnel(device.addr, MODE_SESSION, &stranger, &device_public, None).unwrap();
    match read_frame::<_, ServerMsg>(&mut t.0).unwrap() {
        Some(ServerMsg::Error { message }) => assert_eq!(message, "this machine is not paired"),
        other => panic!("unexpected reply: {other:?}"),
    }
    assert!(ask(&mut t, &ClientMsg::List).is_none(), "the connection is closed");

    let id = device.server.broker().vault().requesters().unwrap()[0].id.clone();
    assert!(device.server.broker().vault().revoke_requester(&id).unwrap().is_some());
    let mut t = tunnel(device.addr, MODE_SESSION, &private, &device_public, None).unwrap();
    assert!(matches!(read_frame::<_, ServerMsg>(&mut t.0).unwrap(), Some(ServerMsg::Error { .. })));
}

#[test]
fn hanging_up_withdraws_the_prompt() {
    let device = device();
    let (private, device_public) = pair(&device, "vm");
    let mut t = tunnel(device.addr, MODE_SESSION, &private, &device_public, None).unwrap();
    write_frame(&mut t.1, &run_request("L3")).unwrap();
    while device.ui.prompts.load(Ordering::SeqCst) == 0 {
        thread::sleep(Duration::from_millis(5));
    }
    drop(t);
    for _ in 0..400 {
        let log = device.server.broker().vault().audit_tail(1).unwrap();
        if log.first().is_some_and(|e| e.outcome == "withdrawn") {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("the prompt was not withdrawn");
}

#[test]
fn local_addresses_are_plain_ipv4() {
    for address in mayi_core::server::local_addresses() {
        let ip: std::net::Ipv4Addr = address.parse().unwrap();
        assert!(!ip.is_loopback());
    }
}
