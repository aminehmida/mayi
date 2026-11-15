//! What a requester keeps on disk: its own tunnel key and the vault devices
//! it is paired with. No secret from the vault is ever stored here.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

use mayi_proto::noise::{self, PrivateKey, PublicKey};
use mayi_proto::{Peer, Wake};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Default, Serialize, Deserialize)]
pub struct Config {
    /// This machine's static key for the tunnel, hex. Empty until first pairing.
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    pub devices: Vec<Device>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub public_key: String,
    pub port: u16,
    pub addresses: Vec<String>,
    /// How to wake the device if it does not answer (a phone).
    #[serde(default)]
    pub wake: Option<Wake>,
    /// Groups the devices of one vault: the key of the device first paired with.
    #[serde(default)]
    pub vault: Option<String>,
    /// The address and port that last reached this device, tried first. It
    /// may be one the device does not know of: a Tailscale name, a tunnel, a
    /// forwarded port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reached: Option<String>,
}

impl Device {
    pub fn public(&self) -> io::Result<PublicKey> {
        key_from_hex(&self.public_key)
    }

    /// Where to try, in order: the address that worked last, then every
    /// address the device announced, on its port.
    pub fn candidates(&self) -> Vec<(String, u16)> {
        let mut out: Vec<(String, u16)> = Vec::new();
        if let Some((host, port)) = self.reached.as_deref().and_then(|r| r.rsplit_once(':')) {
            if let Ok(port) = port.parse() {
                out.push((host.trim_start_matches('[').trim_end_matches(']').to_string(), port));
            }
        }
        for address in &self.addresses {
            let candidate = (address.clone(), self.port);
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
        out
    }
}

fn key_from_hex(text: &str) -> io::Result<[u8; 32]> {
    hex::decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "damaged key in the requester config"))
}

pub fn path() -> PathBuf {
    if let Some(path) = std::env::var_os("MAYI_CONFIG") {
        return path.into();
    }
    let base = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
    });
    base.join("mayi").join("requester.json")
}

impl Config {
    pub fn load() -> io::Result<Self> {
        match fs::read(path()) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes the config so that only this user can read it.
    pub fn save(&self) -> io::Result<()> {
        let path = path();
        if let Some(dir) = path.parent() {
            if !dir.exists() {
                fs::create_dir_all(dir)?;
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        let tmp = path.with_extension("tmp");
        let mut file =
            fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        fs::rename(tmp, path)
    }

    /// This machine's key, generated the first time it is needed.
    pub fn private_key(&mut self) -> io::Result<PrivateKey> {
        if self.private_key.is_empty() {
            let (private, _) = noise::generate_keypair()?;
            self.private_key = hex::encode(*private);
        }
        Ok(Zeroizing::new(key_from_hex(&self.private_key)?))
    }

    /// Replaces what is known about the vault `via` belongs to with the list
    /// a device of that vault just sent: its other devices, new addresses,
    /// and removals. Devices of other vaults are kept. Returns whether
    /// anything changed.
    pub fn update_peers(&mut self, via: &Device, peers: Vec<Peer>) -> bool {
        if !peers.iter().any(|p| p.public_key == via.public_key) {
            // A list that does not include its sender is not one to trust.
            return false;
        }
        let before = self.devices.clone();
        // Everything learnt through this device or its vault's earlier lists.
        let known: Vec<String> = peers.iter().map(|p| p.public_key.clone()).collect();
        let vault = via.vault.clone().unwrap_or_else(|| via.public_key.clone());
        self.devices.retain(|d| d.vault.as_deref().unwrap_or(&d.public_key) != vault && !known.contains(&d.public_key));
        self.devices.extend(peers.into_iter().map(|p| Device {
            // What worked before is kept: the announced addresses are only
            // the ones the device sees on its own network interfaces.
            reached: before.iter().find(|d| d.public_key == p.public_key).and_then(|d| d.reached.clone()),
            name: p.name,
            public_key: p.public_key,
            port: p.port,
            addresses: p.addresses,
            wake: p.wake,
            vault: Some(vault.clone()),
        }));
        self.devices != before
    }

    /// Adds a device, replacing an earlier pairing with the same device.
    pub fn remember(&mut self, device: Device) {
        self.devices.retain(|d| d.public_key != device.public_key);
        self.devices.push(device);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(name: &str, key: &str, vault: Option<&str>) -> Device {
        Device {
            name: name.into(),
            public_key: key.into(),
            port: 1,
            addresses: vec![],
            wake: None,
            vault: vault.map(String::from),
            reached: None,
        }
    }

    fn peer(name: &str, key: &str) -> Peer {
        Peer { name: name.into(), public_key: key.into(), port: 2, addresses: vec!["a".into()], wake: None }
    }

    #[test]
    fn peer_lists_add_update_and_remove_devices_of_one_vault() {
        let mut config = Config::default();
        config.remember(device("mac", "aa", None));
        config.remember(device("other-vault", "ff", None));

        let via = config.devices[0].clone();
        assert!(config.update_peers(&via, vec![peer("mac", "aa"), peer("phone", "bb")]));
        let names = |c: &Config| c.devices.iter().map(|d| d.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&config), ["other-vault", "mac", "phone"]);
        assert_eq!(config.devices[1].port, 2, "addresses are refreshed");

        // Asking the phone later: it reports the Mac was removed.
        let via = config.devices[2].clone();
        assert!(config.update_peers(&via, vec![peer("phone", "bb")]));
        assert_eq!(names(&config), ["other-vault", "phone"]);
        assert!(!config.update_peers(&via, vec![peer("phone", "bb")]), "no change, no write");

        // A list that leaves out its sender is ignored.
        assert!(!config.update_peers(&via, vec![peer("evil", "cc")]));
        assert_eq!(names(&config), ["other-vault", "phone"]);
    }

    #[test]
    fn the_address_that_worked_survives_a_peer_list() {
        let mut config = Config::default();
        let mut mac = device("mac", "aa", None);
        mac.addresses = vec!["192.168.1.10".into()];
        mac.reached = Some("macbook.tailnet.ts.net:7462".into());
        config.remember(mac);
        let via = config.devices[0].clone();
        config.update_peers(&via, vec![peer("mac", "aa")]);
        let mac = &config.devices[0];
        assert_eq!(mac.addresses, ["a"], "announced addresses are refreshed");
        assert_eq!(mac.reached.as_deref(), Some("macbook.tailnet.ts.net:7462"));
        assert_eq!(mac.candidates(), [("macbook.tailnet.ts.net".to_string(), 7462), ("a".to_string(), 2)]);

        let tunnel = Device { reached: Some("[::1]:17462".into()), ..device("x", "bb", None) };
        assert_eq!(tunnel.candidates(), [("::1".to_string(), 17462)]);
    }
}
