//! Two vault devices over real TCP connections: a second device joins with
//! an enrolment token or by showing a join code, they sync, and a machine
//! paired with one is accepted by the other.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mayi_core::broker::{Approval, Broker, Notice, Prompt, Ui};
use mayi_core::hardware::SoftwareKeys;
use mayi_core::model::{Destination, Level, NewItem};
use mayi_core::policy::Rules;
use mayi_core::server::{join_vault, JoinCode, Server};
use mayi_core::vault::Vault;
use mayi_proto::noise::{self, PairingToken, MODE_PAIRING, MODE_SESSION};
use mayi_proto::{read_frame, write_frame, Binding, ClientMsg, RunRequest, ServerMsg};
use zeroize::Zeroizing;

#[derive(Default)]
struct CountingUi {
    added: AtomicUsize,
    synced: AtomicUsize,
    active: AtomicBool,
}

impl Ui for CountingUi {
    fn approve(&self, _: &Prompt) -> Approval {
        Approval::Deny
    }
    fn notify(&self, _: &Notice) {}
    fn device_added(&self, _: &str) {
        self.added.fetch_add(1, Ordering::SeqCst);
    }
    fn synced(&self, changed: usize) {
        self.synced.fetch_add(changed, Ordering::SeqCst);
    }
    fn user_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}

struct Device {
    server: Arc<Server>,
    ui: Arc<CountingUi>,
    addr: SocketAddr,
}

fn serve(vault: Vault) -> Device {
    let ui = Arc::new(CountingUi::default());
    let server = Server::new(Broker::new(vault, ui.clone(), Rules::default()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    server.announce(addr.port(), vec!["127.0.0.1".into()]).unwrap();
    thread::spawn({
        let server = server.clone();
        move || server.serve_tcp(listener)
    });
    Device { server, ui, addr }
}

fn item(name: &str, level: Level) -> NewItem {
    NewItem {
        name: name.into(),
        level,
        values: [("value".to_string(), Zeroizing::new(format!("{name}-value")))].into_iter().collect(),
        allow: vec![],
        max_grant_secs: 600,
        destination: Destination::Command,
        sites: vec![],
        folder: None,
    }
}

fn request(addr: SocketAddr, private: &[u8; 32], device: &[u8; 32], msg: &ClientMsg) -> Option<ServerMsg> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let transport = noise::connect(&mut stream, MODE_SESSION, private, device, None).unwrap();
    let (mut reader, mut writer) = noise::split(transport, stream.try_clone().unwrap(), stream);
    write_frame(&mut writer, msg).unwrap();
    read_frame(&mut reader).unwrap()
}

#[test]
fn a_second_device_joins_syncs_and_serves_the_same_machines() {
    let dir = tempfile::tempdir().unwrap();
    let mac_vault =
        Vault::create(&dir.path().join("mac.db"), Arc::new(SoftwareKeys::generate(|_| true)), "mac").unwrap();
    mac_vault.put(item("L1", Level::Log)).unwrap();
    mac_vault.put(item("L4", Level::Biometric)).unwrap();
    let mac = serve(mac_vault);

    // A machine pairs with the Mac before the phone exists.
    let machine_token =
        PairingToken::decode(&mac.server.start_pairing(vec!["127.0.0.1".into()], mac.addr.port(), 60).unwrap()).unwrap();
    let (machine_key, _) = noise::generate_keypair().unwrap();
    {
        let mut stream = TcpStream::connect(mac.addr).unwrap();
        let transport = noise::connect(
            &mut stream, MODE_PAIRING, &machine_key, &machine_token.device_public, Some(&machine_token.secret),
        )
        .unwrap();
        let (mut reader, mut writer) = noise::split(transport, stream.try_clone().unwrap(), stream);
        write_frame(&mut writer, &ClientMsg::Pair { name: "vm".into() }).unwrap();
        assert!(matches!(read_frame(&mut reader).unwrap(), Some(ServerMsg::Paired { .. })));
    }

    // A machine token does not admit a device, and the reverse.
    let phone_keys = Arc::new(SoftwareKeys::generate(|_| true));
    let phone_path = dir.path().join("phone.db");
    assert!(join_vault(&phone_path, phone_keys.clone(), "phone", &machine_token.encode()).is_err());

    let token = mac.server.start_enrolment(vec!["127.0.0.1".into()], mac.addr.port(), 60).unwrap();
    assert!(token.starts_with("mayid1."));
    let phone_vault = join_vault(&phone_path, phone_keys.clone(), "phone", &token).unwrap();
    assert_eq!(mac.ui.added.load(Ordering::SeqCst), 1);
    assert_eq!(
        phone_vault.list().unwrap().iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
        ["L1", "L4"],
        "the first sync happens as part of joining"
    );
    let l4 = phone_vault.meta("L4").unwrap();
    assert_eq!(&**phone_vault.reveal(&[&l4], "p").unwrap()[0].get("value").unwrap(), "L4-value");

    // The token is spent.
    let other = dir.path().join("other.db");
    assert!(join_vault(&other, Arc::new(SoftwareKeys::generate(|_| true)), "thief", &token).is_err());
    assert!(!other.exists());

    // The phone starts serving, announces itself, and both sync.
    let (_, phone_public) = phone_vault.noise_keypair().unwrap();
    phone_vault.put(item("FROM_PHONE", Level::Log)).unwrap();
    let phone = serve(phone_vault);
    let results = phone.server.sync_all().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "mac");
    assert!(results[0].1.is_ok(), "{:?}", results[0].1);
    // The Mac finishes its side just after the phone's call returns.
    for _ in 0..200 {
        if mac.ui.synced.load(Ordering::SeqCst) >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(mac.ui.synced.load(Ordering::SeqCst) >= 2, "the Mac learnt the new secret and the phone's address");
    assert!(mac.server.broker().vault().meta("FROM_PHONE").is_ok());

    // Syncing from the Mac's side reaches the phone at its announced address.
    mac.server.broker().vault().put(item("FROM_MAC", Level::Log)).unwrap();
    let results = mac.server.sync_all().unwrap();
    assert_eq!(results[0].0, "phone");
    assert!(results[0].1.is_ok(), "{:?}", results[0].1);
    assert!(phone.server.broker().vault().meta("FROM_MAC").is_ok());

    // The machine paired with the Mac learns about the phone and can use it.
    let Some(ServerMsg::Peers { devices, sender, sender_active }) =
        request(mac.addr, &machine_key, &machine_token.device_public, &ClientMsg::Peers)
    else {
        panic!("no peer list")
    };
    assert_eq!(sender, Some(hex::encode(machine_token.device_public)), "the list says who sent it");
    assert!(!sender_active);
    assert_eq!(devices.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["mac", "phone"]);
    let phone_peer = &devices[1];
    assert_eq!(phone_peer.public_key, hex::encode(phone_public));
    assert_eq!(phone_peer.port, phone.addr.port());
    let run = ClientMsg::Run(RunRequest {
        bindings: vec![Binding { env: "T".into(), item: "L1".into(), field: "value".into() }],
        argv: vec!["true".into()],
        reason: "via the phone".into(),
        session: "s".into(),
        ..Default::default()
    });
    match request(phone.addr, &machine_key, &phone_public, &run) {
        Some(ServerMsg::Released { env, .. }) => assert_eq!(env["T"], "L1-value"),
        other => panic!("unexpected reply: {other:?}"),
    }

    // A removed device is refused by sync.
    let phone_id = phone.server.broker().vault().device_id().to_string();
    assert!(mac.server.broker().vault().remove_device(&phone_id).unwrap().is_some());
    let results = phone.server.sync_all().unwrap();
    assert_eq!(results[0].1.as_ref().unwrap_err(), "vault: not a device of this vault");
}

fn names(vault: &Vault) -> Vec<String> {
    vault.list().unwrap().into_iter().map(|m| m.name).collect()
}

#[test]
fn a_new_device_shows_a_code_and_the_device_with_the_vault_adds_it() {
    let dir = tempfile::tempdir().unwrap();
    let phone_vault =
        Vault::create(&dir.path().join("phone.db"), Arc::new(SoftwareKeys::generate(|_| true)), "phone").unwrap();
    phone_vault.put(item("L1", Level::Log)).unwrap();
    phone_vault.put(item("L4", Level::Biometric)).unwrap();
    let phone = serve(phone_vault);

    let code = JoinCode::open(vec!["127.0.0.1".into()], 0, 60).unwrap();
    let token = code.token();
    assert!(token.starts_with("mayij1."));
    let port = PairingToken::decode(&token).unwrap().port;

    // Each kind of code works in one direction only.
    let wrong_way =
        join_vault(&dir.path().join("x.db"), Arc::new(SoftwareKeys::generate(|_| true)), "x", &token).map(|_| ());
    assert!(wrong_way.unwrap_err().to_string().contains("waiting to join"));
    let invitation = phone.server.start_enrolment(vec!["127.0.0.1".into()], phone.addr.port(), 60).unwrap();
    assert!(phone.server.add_device_by_code(&invitation).unwrap_err().to_string().contains("new device"));

    let mac_keys = Arc::new(SoftwareKeys::generate(|_| true));
    let mac_path = dir.path().join("mac.db");
    let cancelled = AtomicBool::new(false);
    let mac_vault = thread::scope(|scope| {
        let waiter = scope.spawn(|| code.wait(&mac_path, mac_keys.clone(), "mac", &cancelled));
        // Someone without the code's secret does not end the wait.
        let mut stranger = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stranger.write_all(&[5u8; 80]).unwrap();
        drop(stranger);
        assert_eq!(phone.server.add_device_by_code(&token).unwrap(), "mac");
        waiter.join().unwrap().map_err(|e| e.to_string())
    })
    .unwrap();
    drop(code);

    assert_eq!(phone.ui.added.load(Ordering::SeqCst), 1);
    assert_eq!(names(&mac_vault), ["L1", "L4"], "the vault arrives over the same tunnel");
    let l4 = mac_vault.meta("L4").unwrap();
    assert_eq!(&**mac_vault.reveal(&[&l4], "p").unwrap()[0].get("value").unwrap(), "L4-value");
    let devices: Vec<String> = mac_vault.devices().unwrap().into_iter().map(|d| d.name).collect();
    assert_eq!(devices, ["mac", "phone"]);

    // The code is gone with its listener.
    assert!(phone.server.add_device_by_code(&token).is_err());

    // From then on the two sync as any two devices do.
    phone.server.broker().vault().put(item("LATER", Level::Log)).unwrap();
    let mac = serve(mac_vault);
    let results = mac.server.sync_all().unwrap();
    assert_eq!(results[0].0, "phone");
    assert!(results[0].1.is_ok(), "{:?}", results[0].1);
    assert!(mac.server.broker().vault().meta("LATER").is_ok());
}

#[test]
fn a_join_code_can_be_cancelled_and_expires() {
    let dir = tempfile::tempdir().unwrap();
    let keys = || Arc::new(SoftwareKeys::generate(|_| true));
    let cancelled = AtomicBool::new(true);
    let code = JoinCode::open(vec!["127.0.0.1".into()], 0, 60).unwrap();
    let outcome = code.wait(&dir.path().join("a.db"), keys(), "a", &cancelled).map(|_| ());
    assert_eq!(outcome.unwrap_err().to_string(), "vault: cancelled");

    let expired = JoinCode::open(vec!["127.0.0.1".into()], 0, 0).unwrap();
    let outcome = expired.wait(&dir.path().join("b.db"), keys(), "b", &AtomicBool::new(false)).map(|_| ());
    assert_eq!(outcome.unwrap_err().to_string(), "vault: the code expired");
    assert!(!dir.path().join("b.db").exists());
}

/// Sends one message over a device's local socket and reads the reply.
fn local(socket: &std::path::Path, msg: &ClientMsg) -> Option<ServerMsg> {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write_frame(&mut stream, msg).unwrap();
    read_frame(&mut stream).unwrap()
}

/// `mayi` on a Mac with the app pairs itself through the app's socket, so its
/// requests can also go to the phone; the switch on the Mac undoes it.
#[test]
fn the_machine_a_device_runs_on_enrols_itself_through_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let mac_vault =
        Vault::create(&dir.path().join("mac.db"), Arc::new(SoftwareKeys::generate(|_| true)), "mac").unwrap();
    mac_vault.put(item("L1", Level::Log)).unwrap();
    let (_, mac_public) = mac_vault.noise_keypair().unwrap();
    let mac = serve(mac_vault);
    let socket = dir.path().join("mac.sock");
    let listener = Server::bind(&socket).unwrap();
    thread::spawn({
        let server = mac.server.clone();
        move || server.serve(listener)
    });
    let token = mac.server.start_enrolment(vec!["127.0.0.1".into()], mac.addr.port(), 60).unwrap();
    let phone_vault =
        join_vault(&dir.path().join("phone.db"), Arc::new(SoftwareKeys::generate(|_| true)), "phone", &token).unwrap();
    let (_, phone_public) = phone_vault.noise_keypair().unwrap();
    let phone = serve(phone_vault);
    phone.server.sync_all().unwrap();

    // The socket's list names the Mac, and says whether it is in use.
    mac.ui.active.store(true, Ordering::SeqCst);
    let Some(ServerMsg::Peers { devices, sender, sender_active }) = local(&socket, &ClientMsg::Peers) else {
        panic!("no peer list")
    };
    assert_eq!(devices.len(), 2);
    assert_eq!(sender, Some(hex::encode(mac_public)));
    assert!(sender_active);

    let (machine_key, machine_public) = noise::generate_keypair().unwrap();
    let enrol = ClientMsg::EnrolLocal { name: "macbook".into(), public: hex::encode(machine_public) };
    assert!(matches!(local(&socket, &enrol), Some(ServerMsg::Paired { device }) if device == "mac"));
    let machines = mac.server.broker().vault().requesters().unwrap();
    assert_eq!(machines[0].local_to.as_deref(), Some(mac.server.broker().vault().device_id()));

    // Not over the network, even with a paired key.
    match request(mac.addr, &machine_key, &mac_public, &enrol) {
        Some(ServerMsg::Error { message }) => assert!(message.contains("local socket"), "{message}"),
        other => panic!("unexpected reply: {other:?}"),
    }

    // Once synced, the phone takes requests from it.
    mac.server.sync_all().unwrap();
    let run = ClientMsg::Run(RunRequest {
        bindings: vec![Binding { env: "T".into(), item: "L1".into(), field: "value".into() }],
        argv: vec!["true".into()],
        reason: "from the Mac".into(),
        session: "s".into(),
        ..Default::default()
    });
    assert!(matches!(request(phone.addr, &machine_key, &phone_public, &run), Some(ServerMsg::Released { .. })));

    // Switched off on the Mac: revoked everywhere, and no new enrolment.
    mac.server.set_local_enrol(false).unwrap();
    mac.server.sync_all().unwrap();
    assert!(matches!(request(phone.addr, &machine_key, &phone_public, &run), Some(ServerMsg::Error { .. })));
    assert!(matches!(local(&socket, &enrol), Some(ServerMsg::Error { .. })));
}

/// Each device knows which secrets exist only on it: a new secret has one
/// copy until a sync, and a removed device stops counting.
#[test]
fn secrets_with_one_copy_are_known_until_they_sync() {
    let dir = tempfile::tempdir().unwrap();
    let mac_vault =
        Vault::create(&dir.path().join("mac.db"), Arc::new(SoftwareKeys::generate(|_| true)), "mac").unwrap();
    mac_vault.put(item("OLD", Level::Log)).unwrap();
    let copies = |vault: &Vault, name: &str| {
        let id = vault.meta(name).unwrap().id;
        vault.copies().unwrap()[&id]
    };
    assert_eq!(copies(&mac_vault, "OLD"), 1, "the only device");
    let mac = serve(mac_vault);
    let mac_vault = || mac.server.broker().vault();

    let token = mac.server.start_enrolment(vec!["127.0.0.1".into()], mac.addr.port(), 60).unwrap();
    let phone_vault =
        join_vault(&dir.path().join("phone.db"), Arc::new(SoftwareKeys::generate(|_| true)), "phone", &token).unwrap();
    let phone = serve(phone_vault);
    let phone_vault = || phone.server.broker().vault();
    // The Mac learns where the phone listens.
    assert!(phone.server.sync_all().unwrap()[0].1.is_ok());
    assert_eq!(copies(mac_vault(), "OLD"), 2, "the phone synced as it joined");
    assert_eq!(copies(phone_vault(), "OLD"), 2, "the Mac wrote it");

    mac_vault().put(item("NEW", Level::Log)).unwrap();
    assert_eq!(copies(mac_vault(), "NEW"), 1, "not synced yet");
    mac_vault().put(item("OLD", Level::Log)).unwrap();
    assert_eq!(copies(mac_vault(), "OLD"), 1, "an edit is a new version, on this Mac only");
    assert!(mac.server.sync_all().unwrap()[0].1.is_ok());
    assert_eq!((copies(mac_vault(), "NEW"), copies(mac_vault(), "OLD")), (2, 2));

    phone_vault().put(item("FROM_PHONE", Level::Log)).unwrap();
    assert_eq!(copies(phone_vault(), "FROM_PHONE"), 1);
    phone.server.sync_all().unwrap();
    assert_eq!(copies(phone_vault(), "FROM_PHONE"), 2);
    assert_eq!(copies(mac_vault(), "FROM_PHONE"), 2, "the side that was called knows too");

    let phone_id = phone_vault().device_id().to_string();
    mac_vault().remove_device(&phone_id).unwrap();
    assert_eq!(copies(mac_vault(), "FROM_PHONE"), 1, "a removed device holds no copy that counts");
}

#[test]
fn viewing_a_secret_is_logged_without_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::create(&dir.path().join("v.db"), Arc::new(SoftwareKeys::generate(|_| true)), "mac").unwrap();
    vault.put(item("TOKEN", Level::Approve)).unwrap();
    let (meta, values) = vault.view("TOKEN", "show TOKEN").unwrap();
    assert_eq!(meta.name, "TOKEN");
    assert_eq!(&**values.get("value").unwrap(), "TOKEN-value");
    let entry = vault.audit_tail(1).unwrap().pop().unwrap();
    assert_eq!((entry.event.as_str(), entry.secrets[0].name.as_str()), ("view", "TOKEN"));
    assert!(!serde_json::to_string(&entry).unwrap().contains("TOKEN-value"));
}
