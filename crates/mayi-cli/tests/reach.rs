//! `mayi run` against two vault devices of one vault, a "mac" and a "phone",
//! served in this process over TCP: it waits for a device that is not up
//! yet, asks the device in use first, and takes the first answer.

use std::collections::HashSet;
use std::net::TcpListener;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use mayi_core::broker::{Approval, Broker, Notice, Prompt, Ui};
use mayi_core::grants::GrantScope;
use mayi_core::hardware::SoftwareKeys;
use mayi_core::model::{Kind, Level, NewItem};
use mayi_core::policy::Rules;
use mayi_core::server::{join_vault, Server};
use mayi_core::vault::Vault;
use mayi_proto::noise;
use serde_json::json;
use zeroize::Zeroizing;

const ALLOW: u8 = 1;

/// A device's owner: answers when told to, and can be using the device.
#[derive(Default)]
struct Owner {
    asked: AtomicUsize,
    withdrawn: AtomicUsize,
    answer: AtomicU8,
    active: AtomicBool,
    gone: Mutex<HashSet<u64>>,
}

impl Ui for Owner {
    fn approve(&self, prompt: &Prompt) -> Approval {
        self.asked.fetch_add(1, Ordering::SeqCst);
        loop {
            if self.gone.lock().unwrap().contains(&prompt.run_id) {
                return Approval::Deny;
            }
            if self.answer.load(Ordering::SeqCst) == ALLOW {
                return Approval::Allow(GrantScope::Once);
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fn withdraw(&self, run_id: u64) {
        self.gone.lock().unwrap().insert(run_id);
        self.withdrawn.fetch_add(1, Ordering::SeqCst);
    }
    fn notify(&self, _: &Notice) {}
    fn user_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}

struct Device {
    owner: Arc<Owner>,
    server: Arc<Server>,
}

fn serve(vault: Vault, port: u16) -> Device {
    let owner = Arc::new(Owner::default());
    let server = Server::new(Broker::new(vault, owner.clone(), Rules::default()));
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    server.announce(port, vec!["127.0.0.1".into()]).unwrap();
    thread::spawn({
        let server = server.clone();
        move || server.serve_tcp(listener)
    });
    Device { owner, server }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A vault on a "mac", serving, a "phone" that joined it but is not
/// serving yet, and a machine paired with both through a requester config.
struct Setup {
    dir: tempfile::TempDir,
    mac: Device,
    phone_vault: Option<Vault>,
    phone_port: u16,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let mac_vault =
        Vault::create(&dir.path().join("mac.db"), Arc::new(SoftwareKeys::generate(|_| true)), "mac").unwrap();
    let secret = NewItem {
        name: "TOKEN".into(),
        level: Level::Approve,
        values: [("value".to_string(), Zeroizing::new("s3cret".to_string()))].into_iter().collect(),
        allow: vec![],
        max_grant_secs: 600,
        kind: Kind::Secret,
        sites: vec![],
    };
    mac_vault.put(secret).unwrap();
    let (_, mac_public) = mac_vault.noise_keypair().unwrap();
    let mac_port = free_port();
    let (machine_private, machine_public) = noise::generate_keypair().unwrap();
    mac_vault.add_requester("vm", machine_public).unwrap();
    let mac = serve(mac_vault, mac_port);

    let token = mac.server.start_enrolment(vec!["127.0.0.1".into()], mac_port, 60).unwrap();
    let phone_vault =
        join_vault(&dir.path().join("phone.db"), Arc::new(SoftwareKeys::generate(|_| true)), "phone", &token).unwrap();
    let (_, phone_public) = phone_vault.noise_keypair().unwrap();
    let phone_port = free_port();
    phone_vault.set_info(phone_port, vec!["127.0.0.1".into()]).unwrap();

    let config = json!({
        "private_key": hex::encode(*machine_private),
        "devices": [
            {"name": "mac", "public_key": hex::encode(mac_public), "port": mac_port, "addresses": ["127.0.0.1"]},
            {"name": "phone", "public_key": hex::encode(phone_public), "port": phone_port, "addresses": ["127.0.0.1"]},
        ],
    });
    std::fs::write(dir.path().join("requester.json"), config.to_string()).unwrap();
    Setup { dir, mac, phone_vault: Some(phone_vault), phone_port }
}

impl Setup {
    /// Leaves only the phone in the requester config.
    fn only_phone(&self) {
        let path = self.dir.path().join("requester.json");
        let mut config: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        config["devices"].as_array_mut().unwrap().remove(0);
        std::fs::write(&path, config.to_string()).unwrap();
    }

    fn start_phone(&mut self) -> Device {
        serve(self.phone_vault.take().expect("not started yet"), self.phone_port)
    }

    fn run(&self, env: &[(&str, &str)]) -> Child {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mayi"));
        command
            .args(["run", "-s", "TOKEN", "-r", "a test", "--session", "s", "--", "sh", "-c", "test \"$TOKEN\" = s3cret && printf released"])
            .env("MAYI_CONFIG", self.dir.path().join("requester.json"))
            // No vault device on this machine.
            .env("MAYI_HOME", self.dir.path())
            .env_remove("MAYI_SOCKET")
            .env_remove("MAYI_WAIT")
            .env_remove("MAYI_TIMEOUT")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        command.spawn().unwrap()
    }
}

fn eventually(what: &str, within: Duration, check: impl Fn() -> bool) {
    let until = Instant::now() + within;
    while !check() {
        assert!(Instant::now() < until, "timed out waiting until {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

fn finish(child: Child) -> (Option<i32>, String, String) {
    let Output { status, stdout, stderr } = child.wait_with_output().unwrap();
    (status.code(), String::from_utf8_lossy(&stdout).into_owned(), String::from_utf8_lossy(&stderr).into_owned())
}

#[test]
fn a_request_waits_for_a_device_that_comes_online() {
    let mut setup = setup();
    // Only the phone, which is off for now.
    setup.only_phone();

    let started = Instant::now();
    let child = setup.run(&[("MAYI_TIMEOUT", "4")]);
    thread::sleep(Duration::from_secs(6));
    let phone = setup.start_phone();
    eventually("the phone is asked", Duration::from_secs(15), || phone.owner.asked.load(Ordering::SeqCst) == 1);
    // The answer timer started only now: the request is still waiting.
    thread::sleep(Duration::from_secs(1));
    phone.owner.answer.store(ALLOW, Ordering::SeqCst);
    let (code, out, err) = finish(child);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "released");
    assert!(err.contains("waiting for your devices (phone not reached yet)"), "{err}");
    assert!(started.elapsed() > Duration::from_secs(6));
}

#[test]
fn nothing_online_fails_once_the_wait_is_over() {
    let setup = setup();
    setup.only_phone();
    let started = Instant::now();
    let (code, _, err) = finish(setup.run(&[("MAYI_WAIT", "4")]));
    assert_eq!(code, Some(69), "{err}");
    assert!(err.contains("none of your devices could be reached within 4s"), "{err}");
    assert!(err.contains("phone not reached yet"), "{err}");
    assert!(started.elapsed() >= Duration::from_secs(4));
}

#[test]
fn the_first_answer_wins_and_the_other_prompt_comes_down() {
    let mut setup = setup();
    let phone = setup.start_phone();
    let child = setup.run(&[]);
    let mac = &setup.mac;
    // Neither in use: one is asked first, the other two seconds later.
    eventually("both are asked", Duration::from_secs(10), || {
        mac.owner.asked.load(Ordering::SeqCst) == 1 && phone.owner.asked.load(Ordering::SeqCst) == 1
    });
    // Long enough for mayi to tell the agent who it asked.
    thread::sleep(Duration::from_millis(1500));
    phone.owner.answer.store(ALLOW, Ordering::SeqCst);
    let (code, out, err) = finish(child);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "released");
    eventually("the Mac's prompt comes down", Duration::from_secs(5), || {
        mac.owner.withdrawn.load(Ordering::SeqCst) == 1
    });
    assert!(err.contains("also asked"), "{err}");
}

#[test]
fn the_device_in_use_is_asked_first() {
    let mut setup = setup();
    let phone = setup.start_phone();
    setup.mac.owner.active.store(true, Ordering::SeqCst);
    let child = setup.run(&[]);
    eventually("the Mac is asked", Duration::from_secs(10), || setup.mac.owner.asked.load(Ordering::SeqCst) == 1);
    thread::sleep(Duration::from_secs(4));
    assert_eq!(phone.owner.asked.load(Ordering::SeqCst), 0, "the phone waits while the Mac is in use");
    setup.mac.owner.answer.store(ALLOW, Ordering::SeqCst);
    let (code, out, err) = finish(child);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "released");
    assert_eq!(phone.owner.asked.load(Ordering::SeqCst), 0);
}

#[test]
fn no_answer_in_time_ends_the_request() {
    let mut setup = setup();
    let _phone = setup.start_phone();
    let (code, _, err) = finish(setup.run(&[("MAYI_TIMEOUT", "3")]));
    assert_eq!(code, Some(75), "{err}");
    assert!(err.contains("no decision within 3s"), "{err}");
    eventually("both prompts come down", Duration::from_secs(5), || {
        setup.mac.owner.withdrawn.load(Ordering::SeqCst) == 1
    });
}

/// An agent on the Mac itself: `mayi` pairs this machine through the Mac's
/// socket, so the phone, in use, is asked.
#[test]
fn a_machine_with_a_vault_device_also_asks_the_others() {
    let mut setup = setup();
    let phone = setup.start_phone();
    // The Mac learns where the phone is.
    phone.server.sync_all().unwrap();
    let listener = Server::bind(&setup.dir.path().join("mayi.sock")).unwrap();
    thread::spawn({
        let server = setup.mac.server.clone();
        move || server.serve(listener)
    });
    std::fs::write(setup.dir.path().join("requester.json"), "{}").unwrap();
    phone.owner.active.store(true, Ordering::SeqCst);

    let child = setup.run(&[]);
    eventually("the phone is asked", Duration::from_secs(10), || phone.owner.asked.load(Ordering::SeqCst) == 1);
    assert_eq!(setup.mac.owner.asked.load(Ordering::SeqCst), 0, "the device in use first");
    phone.owner.answer.store(ALLOW, Ordering::SeqCst);
    let (code, out, err) = finish(child);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, "released");
    let machines = setup.mac.server.broker().vault().requesters().unwrap();
    assert!(machines.iter().any(|m| m.local_to.is_some()), "paired through the socket");
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(setup.dir.path().join("requester.json")).unwrap()).unwrap();
    assert_eq!(config["devices"].as_array().unwrap().len(), 2);
}

/// An MCP client that sent a progress token hears what mayi is waiting for.
#[test]
fn mcp_calls_report_progress_while_waiting() {
    use std::io::{BufRead, BufReader, Write};
    let setup = setup();
    setup.only_phone();
    let mut server = Command::new(env!("CARGO_BIN_EXE_mayi"))
        .arg("mcp")
        .env("MAYI_CONFIG", setup.dir.path().join("requester.json"))
        .env("MAYI_HOME", setup.dir.path())
        .env_remove("MAYI_SOCKET")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = server.stdin.take().unwrap();
    let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "run_with_secrets", "_meta": {"progressToken": "t1"},
        "arguments": {"command": ["true"], "secrets": ["TOKEN"], "reason": "a test", "wait_seconds": 5},
    }});
    writeln!(input, "{call}").unwrap();
    let mut lines = BufReader::new(server.stdout.take().unwrap()).lines();
    let first: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(first["method"], "notifications/progress");
    assert_eq!(first["params"]["progressToken"], "t1");
    assert!(first["params"]["message"].as_str().unwrap().starts_with("waiting for your devices"), "{first}");
    let result: serde_json::Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(result["id"], 1);
    assert_eq!(result["result"]["isError"], true);
    assert!(result["result"]["content"][0]["text"].as_str().unwrap().contains("none of your devices could be reached"));
    drop(input);
    server.wait().unwrap();
}
