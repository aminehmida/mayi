//! Two vault devices over real TCP connections: a second device joins with
//! an enrolment token, they sync, and a machine paired with one is accepted
//! by the other.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mayi_core::broker::{Approval, Broker, Notice, Prompt, Ui};
use mayi_core::hardware::SoftwareKeys;
use mayi_core::model::{Kind, Level, NewItem};
use mayi_core::policy::Rules;
use mayi_core::server::{join_vault, Server};
use mayi_core::vault::Vault;
use mayi_proto::noise::{self, PairingToken, MODE_PAIRING, MODE_SESSION};
use mayi_proto::{read_frame, write_frame, Binding, ClientMsg, RunRequest, ServerMsg};
use zeroize::Zeroizing;

#[derive(Default)]
struct CountingUi {
    added: AtomicUsize,
    synced: AtomicUsize,
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
    server.announce(addr.port(), vec!["127.0.0.1".into()], None).unwrap();
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
        kind: Kind::Secret,
        sites: vec![],
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
    assert!(mac.ui.synced.load(Ordering::SeqCst) >= 2, "the Mac learnt the new secret and the phone's address");
    assert!(mac.server.broker().vault().meta("FROM_PHONE").is_ok());

    // Syncing from the Mac's side reaches the phone at its announced address.
    mac.server.broker().vault().put(item("FROM_MAC", Level::Log)).unwrap();
    let results = mac.server.sync_all().unwrap();
    assert_eq!(results[0].0, "phone");
    assert!(results[0].1.is_ok(), "{:?}", results[0].1);
    assert!(phone.server.broker().vault().meta("FROM_MAC").is_ok());

    // The machine paired with the Mac learns about the phone and can use it.
    let Some(ServerMsg::Peers { devices }) =
        request(mac.addr, &machine_key, &machine_token.device_public, &ClientMsg::Peers)
    else {
        panic!("no peer list")
    };
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
