//! Messages exchanged between a requester (`mayi` CLI) and a vault device.
//!
//! Frames are a 4-byte big-endian length followed by JSON. The same messages
//! travel over the local unix socket and inside a Noise tunnel (see [`noise`]).

pub mod noise;
pub mod program;
pub mod site;

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Field used when a binding names only the item.
pub const DEFAULT_FIELD: &str = "value";

/// The fields a login may have. `totp` holds the two-factor key, which is
/// never released: a request for it is answered with the current code.
pub const FIELD_USERNAME: &str = "username";
pub const FIELD_PASSWORD: &str = "password";
pub const FIELD_TOTP: &str = "totp";

const MAX_FRAME: usize = 1 << 20;

/// One environment variable to fill from one field of one secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub env: String,
    pub item: String,
    pub field: String,
}

/// A request to run `argv` with secrets injected or, when `site` is set, to
/// type the fields of one login into a web page.
///
/// `reason`, `agent`, `session` and `host` are written by the requesting side
/// and must be treated as untrusted when shown to the user.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunRequest {
    pub bindings: Vec<Binding>,
    pub argv: Vec<String>,
    pub cwd: String,
    pub reason: String,
    pub agent: String,
    pub session: String,
    pub host: String,
    /// A sign-in: the origin of the page the login is to be typed into, as
    /// the requester read it from its browser, e.g. `https://github.com`.
    /// `argv` is then empty, every binding names the same login, and each
    /// binding's `env` is the key its value comes back under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// The absolute path the requester runs `argv[0]` from, which it looked
    /// up itself (see [`program`]). Shown in its place, so the owner sees
    /// which program will run. Absent from requesters before alpha.9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}

impl RunRequest {
    /// The command as it will run: `argv` with the program's full path.
    pub fn shown_argv(&self) -> Vec<String> {
        let mut argv = self.argv.clone();
        if let (Some(first), Some(program)) = (argv.first_mut(), &self.program) {
            first.clone_from(program);
        }
        argv
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    Run(RunRequest),
    List,
    /// The command started by a released run has ended.
    Done { exit: Option<i32> },
    /// Sent over a pairing tunnel: enrol this machine as a requester.
    Pair { name: String },
    /// Ask which vault devices hold this vault and where to find them.
    Peers,
    /// Over the local socket only: enrol this machine's tunnel key (hex) as
    /// a requester, so its requests can also reach the vault's other devices.
    EnrolLocal { name: String, public: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Released {
        run_id: u64,
        env: BTreeMap<String, String>,
    },
    Denied {
        reason: String,
    },
    Secrets {
        secrets: Vec<SecretInfo>,
    },
    /// The user pressed Stop: kill the running command.
    Stop,
    /// The machine is now enrolled with the vault device called `device`.
    Paired {
        device: String,
    },
    Peers {
        devices: Vec<Peer>,
        /// The tunnel key of the device replying, so a requester on the same
        /// machine can tell it apart from the others.
        #[serde(default)]
        sender: Option<String>,
        /// Whether its owner is using the replying device right now; that
        /// device is asked first.
        #[serde(default)]
        sender_active: bool,
    },
    Error {
        message: String,
    },
}

/// A vault device as a requester needs to know it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub name: String,
    /// Static tunnel key, hex.
    pub public_key: String,
    pub port: u16,
    pub addresses: Vec<String>,
}

/// What a requester may learn about a secret: never its value.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretInfo {
    pub name: String,
    pub level: u8,
    pub fields: Vec<String>,
    /// A login goes into the sign-in form of one of `sites` and nowhere else.
    #[serde(default)]
    pub login: bool,
    #[serde(default)]
    pub sites: Vec<String>,
}

pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

/// Reads one frame. Returns `None` when the peer closed the stream cleanly.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<Option<T>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(serde_json::from_slice(&body)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &ClientMsg::List).unwrap();
        write_frame(&mut buf, &ClientMsg::Done { exit: Some(3) }).unwrap();
        let mut r = buf.as_slice();
        assert!(matches!(read_frame(&mut r).unwrap(), Some(ClientMsg::List)));
        assert!(matches!(
            read_frame(&mut r).unwrap(),
            Some(ClientMsg::Done { exit: Some(3) })
        ));
        assert!(read_frame::<_, ClientMsg>(&mut r).unwrap().is_none());
    }

    #[test]
    fn requests_without_a_site_still_parse() {
        let old = r#"{"type":"run","bindings":[],"argv":["ls"],"cwd":"","reason":"r","agent":"a","session":"s","host":"h"}"#;
        let Ok(ClientMsg::Run(request)) = serde_json::from_str(old) else { panic!("did not parse") };
        assert_eq!(request.site, None);
        assert!(!serde_json::to_string(&request).unwrap().contains("site"));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let mut r: &[u8] = &[0xff, 0xff, 0xff, 0xff];
        assert!(read_frame::<_, ClientMsg>(&mut r).is_err());
    }
}
