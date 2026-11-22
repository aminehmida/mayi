//! Encrypted storage for secrets, the vault's devices and paired machines,
//! and the audit log.
//!
//! Key hierarchy:
//! - The vault key is wrapped to each device's hardware key.
//! - Item metadata, device records and machine records are sealed under the
//!   vault key, so write access to the file is not enough to forge them.
//! - Item values are sealed under a per-item data key. For levels 1 to 3 the
//!   data key is wrapped by the vault key. For level 4 it is wrapped only to
//!   each device's biometric key, so the vault key alone cannot read it.
//!
//! Every synced record carries a [`Stamp`]. The higher stamp wins when two
//! devices changed the same record (see `sync`).

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};

use mayi_proto::site::normalize_site;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{self, Key};
use crate::hardware::HardwareKeys;
use crate::model::{AwsProfile, AwsSignIn, Destination, ItemMeta, Level, NewItem, RotateNote, SecretValues, Source};
use crate::provider::{self, NEEDS_NEWER};
use crate::{now_ms, Error, Result};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS members (
    id TEXT PRIMARY KEY,
    wrapped_vk BLOB NOT NULL,
    sealed BLOB NOT NULL,
    version INTEGER NOT NULL,
    author TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    author TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    meta BLOB NOT NULL,
    payload BLOB
);
CREATE TABLE IF NOT EXISTS wraps (
    item_id TEXT NOT NULL,
    recipient TEXT NOT NULL,
    wrapped BLOB NOT NULL,
    PRIMARY KEY (item_id, recipient)
);
CREATE TABLE IF NOT EXISTS history (
    item_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    author TEXT NOT NULL,
    deleted INTEGER NOT NULL,
    meta BLOB NOT NULL,
    payload BLOB,
    wraps TEXT NOT NULL,
    PRIMARY KEY (item_id, version, author)
);
CREATE TABLE IF NOT EXISTS requesters (
    id TEXT PRIMARY KEY,
    sealed BLOB NOT NULL,
    version INTEGER NOT NULL,
    author TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS local (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_ms INTEGER NOT NULL,
    entry TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shared_log (
    author TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts_ms INTEGER NOT NULL,
    entry TEXT NOT NULL,
    PRIMARY KEY (author, seq)
);
";

/// Recipient name of the wrap made with the vault key.
pub(crate) const VAULT_RECIPIENT: &str = "vault";

/// When a record was last changed and by which device. A hybrid clock:
/// wall-clock milliseconds, pushed past every version this device has seen,
/// so a slow clock cannot make a new change lose to an old one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Stamp {
    pub version: u64,
    pub author: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SecretUse {
    pub name: String,
    /// Level after context rules were applied.
    pub level: u8,
    /// Why it was released without asking, or what was asked.
    pub via: String,
}

/// One line of the audit log. Never contains a secret value.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts_ms: u64,
    pub run_id: u64,
    /// `request`, `stop` or `exit`.
    pub event: String,
    pub outcome: String,
    pub requester: String,
    pub remote: bool,
    pub agent: String,
    pub session: String,
    pub host: String,
    pub cwd: String,
    pub argv: Vec<String>,
    /// For a sign-in: the page's origin, as the requester reported it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub site: String,
    pub reason: String,
    pub secrets: Vec<SecretUse>,
    /// The device that wrote the entry, when another device of the vault did;
    /// empty for this one. Filled in when read, not stored.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
}

/// How long the activity log keeps an entry, on every device.
const LOG_KEPT_MS: u64 = 90 * 24 * 3600 * 1000;

/// The most activity entries one sync carries; the rest follow next time.
pub(crate) const LOG_BATCH: usize = 300;

pub(crate) fn log_aad(author: &str, seq: u64) -> Vec<u8> {
    format!("mayi/log/{author}/{seq}").into_bytes()
}

/// A folder name as kept: trimmed, and none when empty.
fn clean_folder(folder: Option<String>) -> Option<String> {
    folder.map(|f| f.trim().to_string()).filter(|f| !f.is_empty())
}

/// A device holding this vault. Keys are hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    #[serde(skip)]
    pub id: String,
    pub name: String,
    pub device_pub: String,
    pub biometric_pub: String,
    /// Static key for the encrypted tunnel; empty until the device says.
    #[serde(default)]
    pub noise_public: String,
    /// Where other devices and machines can reach it.
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub removed: bool,
    /// Not a device but the offline recovery key: it is given key wraps
    /// like a device, and never connects.
    #[serde(default)]
    pub recovery: bool,
    #[serde(skip)]
    pub version: u64,
}

const RECOVERY_PREFIX: &str = "mayi-recovery1.";

/// What a device brings when it asks to join a vault.
pub struct NewDevice {
    pub name: String,
    pub device_pub: Vec<u8>,
    pub biometric_pub: Vec<u8>,
    /// `None` for the recovery key, which never opens a tunnel.
    pub noise_public: Option<[u8; 32]>,
}

/// What a joining device needs to open the vault: the vault key wrapped to
/// its hardware key.
#[derive(Clone, Debug)]
pub struct Bootstrap {
    pub device_id: String,
    pub wrapped_vk: Vec<u8>,
}

/// A machine allowed to send requests over the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequesterRecord {
    /// Fingerprint of its static key.
    #[serde(skip)]
    pub id: String,
    /// The name it gave itself when pairing.
    pub name: String,
    /// Static tunnel key, hex.
    pub public: String,
    pub added_ms: u64,
    pub revoked: bool,
    /// The device whose machine this is, when it enrolled itself through
    /// that device's local socket rather than by pairing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_to: Option<String>,
}

impl RequesterRecord {
    /// How the machine is shown to the user and named in grants and logs.
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, &self.id[..8])
    }
}

pub struct Vault {
    pub(crate) conn: Mutex<Connection>,
    pub(crate) vk: Key,
    pub(crate) hw: Arc<dyn HardwareKeys>,
    pub(crate) device_id: String,
}

pub(crate) fn device_id(device_public: &[u8]) -> String {
    hex::encode(&Sha256::digest(device_public)[..8])
}

fn vk_aad(device_id: &str) -> Vec<u8> {
    format!("mayi/vk/{device_id}").into_bytes()
}

pub(crate) fn member_aad(id: &str) -> Vec<u8> {
    format!("mayi/member/{id}").into_bytes()
}

pub(crate) fn requester_aad(id: &str) -> Vec<u8> {
    format!("mayi/requester/{id}").into_bytes()
}

pub(crate) fn meta_aad(item_id: &str) -> Vec<u8> {
    format!("mayi/meta/{item_id}").into_bytes()
}

fn wrap_aad(item_id: &str) -> Vec<u8> {
    format!("mayi/wrap/{item_id}").into_bytes()
}

/// Binds the values to the item's level and destination, so a relabelled
/// item fails to open: a login turned into a plain secret could be put in a
/// command's environment. A destination or source this version does not
/// know is never opened.
fn payload_aad(meta: &ItemMeta) -> Result<Vec<u8>> {
    let (id, level) = (&meta.id, meta.level as u8);
    match (&meta.destination, &meta.source) {
        (Destination::Command, Source::Stored) => Ok(format!("mayi/payload/{id}/{level}").into_bytes()),
        (Destination::Website, Source::Stored) => Ok(format!("mayi/payload/{id}/{level}/login").into_bytes()),
        (Destination::Command, Source::AwsSso) => Ok(format!("mayi/payload/{id}/{level}/aws_sso").into_bytes()),
        _ => Err(Error::Vault(format!("{}: {NEEDS_NEWER}", meta.name))),
    }
}

/// Checks the rules that come with a destination: a login has websites and
/// no command allowlist, other secrets the reverse. Returns the websites,
/// normalized.
fn check_rules(destination: &Destination, allow: &[String], sites: &[String]) -> Result<Vec<String>> {
    match destination {
        Destination::Command if sites.is_empty() => Ok(vec![]),
        Destination::Command => Err(Error::Vault("only a login has websites".into())),
        Destination::Website if !allow.is_empty() => {
            Err(Error::Vault("a login is used on websites, not with commands".into()))
        }
        Destination::Website => {
            let mut normalized = Vec::new();
            for site in sites {
                let site = normalize_site(site).map_err(Error::Vault)?;
                if !normalized.contains(&site) {
                    normalized.push(site);
                }
            }
            if normalized.is_empty() {
                return Err(Error::Vault("a login needs at least one website".into()));
            }
            Ok(normalized)
        }
        Destination::Other(_) => Err(Error::Vault(NEEDS_NEWER.into())),
    }
}

fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(Error::Vault(format!(
            "invalid secret name {name:?}: use letters, digits, '_', '-' and '.'"
        )))
    }
}

fn unhex(text: &str) -> Result<Vec<u8>> {
    hex::decode(text).map_err(|_| Error::Vault("damaged key in a record".into()))
}

fn new_database(path: &Path) -> Result<Connection> {
    if path.exists() {
        return Err(Error::Vault(format!("{} already exists", path.display())));
    }
    let conn = Connection::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// The next version to stamp a change with.
pub(crate) fn next_version(conn: &Connection) -> Result<u64> {
    let version = now_ms().max(clock(conn)? + 1);
    set_clock(conn, version)?;
    Ok(version)
}

fn clock(conn: &Connection) -> Result<u64> {
    let stored: Option<Vec<u8>> = conn
        .query_row("SELECT value FROM local WHERE key = 'clock'", [], |r| r.get(0))
        .optional()?;
    Ok(stored
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0))
}

fn set_clock(conn: &Connection, version: u64) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO local (key, value) VALUES ('clock', ?1)",
        [version.to_be_bytes().to_vec()],
    )?;
    Ok(())
}

impl Vault {
    /// Creates a new vault with this device as its only member.
    pub fn create(path: &Path, hw: Arc<dyn HardwareKeys>, device_name: &str) -> Result<Self> {
        let device_pub = crypto::normalize_public(&hw.device_public())?;
        let biometric_pub = crypto::normalize_public(&hw.biometric_public())?;
        let id = device_id(&device_pub);
        let conn = new_database(path)?;
        let vk = crypto::random_key();
        let wrapped_vk = crypto::ecies_seal(&device_pub, &vk_aad(&id), &*vk)?;
        let vault = Self { conn: Mutex::new(conn), vk, hw, device_id: id.clone() };
        let record = DeviceRecord {
            id,
            name: device_name.to_string(),
            device_pub: hex::encode(device_pub),
            biometric_pub: hex::encode(biometric_pub),
            noise_public: String::new(),
            port: 0,
            addresses: vec![],
            removed: false,
            recovery: false,
            version: 0,
        };
        let conn = vault.conn();
        let version = next_version(&conn)?;
        vault.write_member(&conn, &record, &wrapped_vk, version)?;
        drop(conn);
        Ok(vault)
    }

    /// Creates this device's copy of a vault it was just enrolled in. The
    /// copy is empty until the first sync.
    pub fn join(
        path: &Path,
        hw: Arc<dyn HardwareKeys>,
        device_name: &str,
        bootstrap: &Bootstrap,
        noise: (&[u8; 32], &[u8; 32]),
    ) -> Result<Self> {
        let device_pub = crypto::normalize_public(&hw.device_public())?;
        let biometric_pub = crypto::normalize_public(&hw.biometric_public())?;
        let id = device_id(&device_pub);
        if id != bootstrap.device_id {
            return Err(Error::Vault("the enrolment was made for another device".into()));
        }
        let shared = hw.device_ecdh(crypto::ecies_ephemeral(&bootstrap.wrapped_vk)?)?;
        let vk = crypto::ecies_open(&shared, &device_pub, &vk_aad(&id), &bootstrap.wrapped_vk)?;
        let vk = crypto::key_from_slice(&vk)?;
        let conn = new_database(path)?;
        let vault = Self { conn: Mutex::new(conn), vk, hw, device_id: id.clone() };
        // Version 0: the record the enrolling device wrote replaces this one
        // at the first sync.
        let record = DeviceRecord {
            id,
            name: device_name.to_string(),
            device_pub: hex::encode(device_pub),
            biometric_pub: hex::encode(biometric_pub),
            noise_public: hex::encode(noise.1),
            port: 0,
            addresses: vec![],
            removed: false,
            recovery: false,
            version: 0,
        };
        let conn = vault.conn();
        vault.write_member(&conn, &record, &bootstrap.wrapped_vk, 0)?;
        drop(conn);
        vault.store_noise_keypair(noise.0, noise.1)?;
        Ok(vault)
    }

    /// Opens an existing vault by unwrapping the vault key with this device's key.
    pub fn open(path: &Path, hw: Arc<dyn HardwareKeys>) -> Result<Self> {
        if !path.exists() {
            return Err(Error::Vault(format!("no vault at {}", path.display())));
        }
        let conn = Connection::open(path)?;
        // Adds tables introduced since the vault was created.
        conn.execute_batch(SCHEMA)?;
        let device_pub = crypto::normalize_public(&hw.device_public())?;
        let id = device_id(&device_pub);
        let wrapped_vk: Vec<u8> = conn
            .query_row("SELECT wrapped_vk FROM members WHERE id = ?1", [&id], |r| r.get(0))
            .optional()?
            .ok_or_else(|| Error::Vault("this device is not enrolled in the vault".into()))?;
        let shared = hw.device_ecdh(crypto::ecies_ephemeral(&wrapped_vk)?)?;
        let vk = crypto::ecies_open(&shared, &device_pub, &vk_aad(&id), &wrapped_vk)?;
        let vk = crypto::key_from_slice(&vk)?;
        Ok(Self { conn: Mutex::new(conn), vk, hw, device_id: id })
    }

    pub(crate) fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Moves the clock past a version seen from another device.
    pub(crate) fn observe(&self, conn: &Connection, version: u64) -> Result<()> {
        if version > clock(conn)? {
            set_clock(conn, version)?;
        }
        Ok(())
    }

    pub(crate) fn open_meta(&self, id: &str, version: u64, sealed: &[u8]) -> Result<ItemMeta> {
        let plain = crypto::open(&self.vk, &meta_aad(id), sealed)?;
        let mut meta: ItemMeta = serde_json::from_slice(&plain)?;
        if meta.id != id {
            return Err(Error::Crypto);
        }
        meta.version = version;
        Ok(meta)
    }

    /// All secrets, sorted by name. Never touches a value.
    ///
    /// If two devices created a secret with the same name before syncing,
    /// the one changed last is shown; the other stays in the file.
    pub fn list(&self) -> Result<Vec<ItemMeta>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT id, version, meta FROM items WHERE deleted = 0")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?, r.get::<_, Vec<u8>>(2)?))
        })?;
        let mut metas = Vec::new();
        for row in rows {
            let (id, version, sealed) = row?;
            metas.push(self.open_meta(&id, version, &sealed)?);
        }
        metas.sort_by(|a, b| {
            a.name.cmp(&b.name).then(b.version.cmp(&a.version)).then(b.id.cmp(&a.id))
        });
        metas.dedup_by(|later, first| later.name == first.name);
        Ok(metas)
    }

    pub fn meta(&self, name: &str) -> Result<ItemMeta> {
        self.list()?
            .into_iter()
            .find(|m| m.name == name)
            .ok_or_else(|| Error::NotFound(name.to_string()))
    }

    /// Copies the current row of `id` into the history table.
    pub(crate) fn archive(tx: &Connection, id: &str) -> Result<()> {
        let wraps: Vec<(String, String)> = tx
            .prepare("SELECT recipient, wrapped FROM wraps WHERE item_id = ?1")?
            .query_map([id], |r| Ok((r.get(0)?, hex::encode(r.get::<_, Vec<u8>>(1)?))))?
            .collect::<rusqlite::Result<_>>()?;
        tx.execute(
            "INSERT OR IGNORE INTO history (item_id, version, author, deleted, meta, payload, wraps)
             SELECT id, version, author, deleted, meta, payload, ?2 FROM items WHERE id = ?1",
            params![id, serde_json::to_string(&wraps)?],
        )?;
        Ok(())
    }

    /// Creates the secret, or replaces the one with the same name. The
    /// previous version is kept in history. Replacing it with a lower level,
    /// or a login with a secret for commands, asks for the owner's
    /// fingerprint first (see [`Vault::confirm_presence`]).
    ///
    /// Needs only public keys, so writing a level 4 secret asks for no
    /// biometric check.
    pub fn put(&self, mut new: NewItem) -> Result<ItemMeta> {
        validate_name(&new.name)?;
        if new.values.is_empty() {
            return Err(Error::Vault("a secret needs at least one field".into()));
        }
        let sites = check_rules(&new.destination, &new.allow, &new.sites)?;
        provider::stored(&new.destination)
            .and_then(|p| p.check(&mut new.values))
            .map_err(Error::Vault)?;
        let existing = self.list()?.into_iter().find(|m| m.name == new.name);
        if let Some(old) = &existing {
            match &old.source {
                Source::Stored => {}
                Source::AwsSso => {
                    return Err(Error::Vault(format!("{} is an AWS sign-in: remove it first to reuse its name", old.name)))
                }
                Source::Other(_) => return Err(Error::Vault(format!("{}: {NEEDS_NEWER}", old.name))),
            }
            let to_commands = old.destination == Destination::Website && new.destination == Destination::Command;
            if new.level < old.level || to_commands {
                self.confirm_presence(&format!("Lower the protection of {}", old.name))?;
            }
        }
        let meta = ItemMeta {
            id: existing.as_ref().map(|m| m.id.clone()).unwrap_or_else(crypto::random_id),
            name: new.name,
            level: new.level,
            allow: new.allow,
            max_grant_secs: new.max_grant_secs,
            fields: new.values.keys().cloned().collect(),
            destination: new.destination,
            source: Source::Stored,
            sites,
            folder: clean_folder(new.folder),
            // A new value: whoever saw the old one no longer matters.
            rotate: Vec::new(),
            aws: None,
            unknown_fields: BTreeMap::new(),
            version: 0,
        };
        self.write_item(meta, &new.values, true)
    }

    /// Seals `values` under a new data key and stores them with `meta` as a
    /// new version, keeping the previous one in history if `archive`.
    fn write_item(&self, mut meta: ItemMeta, values: &SecretValues, archive: bool) -> Result<ItemMeta> {
        let id = meta.id.clone();
        let dk = crypto::random_key();
        // Level 4: one wrap per device, to its biometric key.
        let wraps: Vec<(String, Vec<u8>)> = if meta.level == Level::Biometric {
            self.devices()?
                .into_iter()
                .filter(|d| !d.removed)
                .map(|d| Ok((d.id, crypto::ecies_seal(&unhex(&d.biometric_pub)?, &wrap_aad(&id), &*dk)?)))
                .collect::<Result<_>>()?
        } else {
            vec![(VAULT_RECIPIENT.to_string(), crypto::seal(&self.vk, &wrap_aad(&id), &*dk))]
        };

        let mut conn = self.conn();
        let tx = conn.transaction()?;
        meta.version = next_version(&tx)?;
        let payload = crypto::seal(&dk, &payload_aad(&meta)?, &zeroize::Zeroizing::new(serde_json::to_vec(values)?));
        let sealed_meta = crypto::seal(&self.vk, &meta_aad(&id), &serde_json::to_vec(&meta)?);
        if archive {
            Self::archive(&tx, &id)?;
        }
        tx.execute("DELETE FROM wraps WHERE item_id = ?1", [&id])?;
        tx.execute(
            "INSERT OR REPLACE INTO items (id, version, author, deleted, meta, payload)
             VALUES (?1, ?2, ?3, 0, ?4, ?5)",
            params![id, meta.version, self.device_id, sealed_meta, payload],
        )?;
        for (recipient, wrapped) in &wraps {
            tx.execute(
                "INSERT INTO wraps (item_id, recipient, wrapped) VALUES (?1, ?2, ?3)",
                params![id, recipient, wrapped],
            )?;
        }
        tx.commit()?;
        Ok(meta)
    }

    /// Takes down a biometric check this vault is waiting on.
    pub fn cancel_biometric(&self) {
        self.hw.cancel_biometric();
    }

    /// Asks for the owner's fingerprint (Touch ID, Apple Watch or password
    /// on a Mac) through this device's level 4 key, showing `prompt`. Opens
    /// nothing: it proves the owner is there, in a way no program can fake.
    pub fn confirm_presence(&self, prompt: &str) -> Result<()> {
        let id = format!("presence-{}", crypto::random_id());
        let challenge = crypto::random_key();
        let public = crypto::normalize_public(&self.hw.biometric_public())?;
        let wrapped = crypto::ecies_seal(&public, &wrap_aad(&id), &*challenge)?;
        let opened = self.unwrap_biometric(&[&id], &[&wrapped], prompt)?;
        match opened.first() {
            Some(o) if o.as_slice() == &challenge[..] => Ok(()),
            _ => Err(Error::BiometricDenied),
        }
    }

    // --- AWS sign-ins ----------------------------------------------------

    fn aws_meta(&self, name: &str) -> Result<ItemMeta> {
        let meta = self.meta(name)?;
        match (&meta.source, &meta.aws) {
            (Source::AwsSso, Some(_)) => Ok(meta),
            _ => Err(Error::Vault(format!("{name} is not an AWS sign-in"))),
        }
    }

    /// Saves a new AWS sign-in: the session (`aws::Session::values`) as its
    /// values, the portal and profiles in its metadata. The sign-in itself
    /// is stored like a level 1 to 3 secret; each profile has its own level.
    pub fn put_aws(&self, name: &str, aws: AwsSignIn, values: SecretValues, folder: Option<String>) -> Result<ItemMeta> {
        validate_name(name)?;
        crate::aws::check_profiles(&aws.profiles).map_err(Error::Vault)?;
        crate::aws::Session::from_values(&values).map_err(Error::Vault)?;
        if self.list()?.iter().any(|m| m.name == name) {
            return Err(Error::Vault(format!("a secret called {name} already exists")));
        }
        let meta = ItemMeta {
            id: crypto::random_id(),
            name: name.to_string(),
            level: Level::Log,
            allow: vec![],
            max_grant_secs: 3600,
            fields: crate::aws::FIELDS.iter().map(|f| f.to_string()).collect(),
            destination: Destination::Command,
            source: Source::AwsSso,
            sites: vec![],
            folder: clean_folder(folder),
            rotate: vec![],
            aws: Some(aws),
            unknown_fields: BTreeMap::new(),
            version: 0,
        };
        self.write_item(meta, &values, false)
    }

    /// Replaces the session of an AWS sign-in after signing in again,
    /// keeping its profiles.
    pub fn renew_aws(&self, name: &str, values: SecretValues) -> Result<ItemMeta> {
        let meta = self.aws_meta(name)?;
        let session = crate::aws::Session::from_values(&values).map_err(Error::Vault)?;
        if meta.aws.as_ref().is_some_and(|a| a.start_url != session.start_url) {
            return Err(Error::Vault(format!("that sign-in was to {}, not {name}'s portal", session.start_url)));
        }
        self.write_item(meta, &values, false)
    }

    /// Changes the profiles of an AWS sign-in. Adding a profile, or lowering
    /// one's level, asks for the owner's fingerprint first: in a window left
    /// unlocked, an agent driving the screen could otherwise do it.
    pub fn update_aws_profiles(&self, name: &str, profiles: Vec<AwsProfile>) -> Result<ItemMeta> {
        let mut meta = self.aws_meta(name)?;
        crate::aws::check_profiles(&profiles).map_err(Error::Vault)?;
        let aws = meta.aws.as_mut().expect("checked above");
        let loosened = profiles.iter().any(|p| {
            match aws.profiles.iter().find(|o| o.account_id == p.account_id && o.role == p.role) {
                Some(old) => p.level < old.level,
                None => true,
            }
        });
        if loosened {
            self.confirm_presence(&format!("Lower the protection of {name}'s AWS profiles"))?;
        }
        aws.profiles = profiles;
        self.write_meta(meta)
    }

    /// Keeps the new session of an AWS sign-in whose refresh token AWS
    /// replaced. No history entry: it is the same sign-in.
    pub(crate) fn store_values(&self, meta: &ItemMeta, values: &SecretValues) -> Result<ItemMeta> {
        let current = self.aws_meta(&meta.name)?;
        if current.id != meta.id {
            return Err(Error::Vault(format!("{} changed meanwhile", meta.name)));
        }
        self.write_item(current, values, false)
    }

    /// Changes the allowlist, grant cap and websites of a secret without
    /// touching its values, so it needs no biometric check even at level 4.
    /// The level and destination cannot change this way: the values are
    /// bound to them. A secret this version cannot use cannot be changed.
    /// A change that asks less (a new expected command or website, a longer
    /// grant) needs the owner's fingerprint first.
    pub fn update_rules(
        &self,
        name: &str,
        allow: Vec<String>,
        max_grant_secs: u64,
        sites: Vec<String>,
        folder: Option<String>,
    ) -> Result<ItemMeta> {
        let mut meta = self.meta(name)?;
        provider::check_known(&meta).map_err(Error::Vault)?;
        if meta.source == Source::AwsSso && !allow.is_empty() {
            return Err(Error::Vault(format!("{name}'s profiles have their own levels: it takes no expected commands")));
        }
        let sites = check_rules(&meta.destination, &allow, &sites)?;
        let loosened = allow.iter().any(|p| !meta.allow.contains(p))
            || sites.iter().any(|s| !meta.sites.contains(s))
            || max_grant_secs > meta.max_grant_secs;
        if loosened {
            self.confirm_presence(&format!("Lower the protection of {name}"))?;
        }
        meta.sites = sites;
        meta.allow = allow;
        meta.max_grant_secs = max_grant_secs;
        meta.folder = clean_folder(folder);
        self.write_meta(meta)
    }

    /// Notes that whoever `note` names may still know these secrets' values.
    /// Each shows a warning on every device until its value is replaced or
    /// the owner dismisses it.
    pub fn flag_rotation(&self, names: &[String], note: RotateNote) -> Result<()> {
        for name in names {
            let Ok(mut meta) = self.meta(name) else { continue };
            if meta.rotate.iter().any(|n| n.who == note.who && n.why == note.why) {
                continue;
            }
            meta.rotate.push(note.clone());
            self.write_meta(meta)?;
        }
        Ok(())
    }

    /// The owner decided a secret needs no rotating after all.
    pub fn dismiss_rotation(&self, name: &str) -> Result<ItemMeta> {
        let mut meta = self.meta(name)?;
        meta.rotate.clear();
        self.write_meta(meta)
    }

    /// Stores changed metadata as a new version, the values untouched.
    pub(crate) fn write_meta(&self, mut meta: ItemMeta) -> Result<ItemMeta> {
        let sealed_meta = crypto::seal(&self.vk, &meta_aad(&meta.id), &serde_json::to_vec(&meta)?);
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        meta.version = next_version(&tx)?;
        Self::archive(&tx, &meta.id)?;
        tx.execute(
            "UPDATE items SET meta = ?2, version = ?3, author = ?4 WHERE id = ?1",
            params![meta.id, sealed_meta, meta.version, self.device_id],
        )?;
        tx.commit()?;
        Ok(meta)
    }

    /// Deletes a secret, leaving a tombstone and its history.
    pub fn remove(&self, name: &str) -> Result<()> {
        let meta = self.meta(name)?;
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        Self::archive(&tx, &meta.id)?;
        tx.execute("DELETE FROM wraps WHERE item_id = ?1", [&meta.id])?;
        tx.execute(
            "UPDATE items SET deleted = 1, payload = NULL, version = ?2, author = ?3 WHERE id = ?1",
            params![meta.id, next_version(&tx)?, self.device_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Decrypts the values of `items`. Level 4 items trigger one biometric
    /// check for the whole batch, showing `prompt`.
    pub fn reveal(&self, items: &[&ItemMeta], prompt: &str) -> Result<Vec<SecretValues>> {
        struct Sealed {
            payload: Vec<u8>,
            wrapped: Vec<u8>,
        }

        // Before any biometric check: this version could not open them.
        for meta in items {
            provider::check_known(meta).map_err(Error::Vault)?;
        }

        let sealed: Vec<Sealed> = {
            let conn = self.conn();
            items
                .iter()
                .map(|meta| {
                    let recipient = if meta.level == Level::Biometric {
                        self.device_id.as_str()
                    } else {
                        VAULT_RECIPIENT
                    };
                    conn.query_row(
                        "SELECT i.payload, w.wrapped FROM items i
                         JOIN wraps w ON w.item_id = i.id
                         WHERE i.id = ?1 AND i.version = ?2 AND i.deleted = 0
                           AND w.recipient = ?3",
                        params![meta.id, meta.version, recipient],
                        |r| Ok(Sealed { payload: r.get(0)?, wrapped: r.get(1)? }),
                    )
                    .optional()?
                    .ok_or_else(|| Error::NotFound(meta.name.clone()))
                })
                .collect::<Result<_>>()?
        };

        let biometric: Vec<usize> = (0..items.len())
            .filter(|&i| items[i].level == Level::Biometric)
            .collect();
        let wrapped: Vec<&[u8]> = biometric.iter().map(|&i| sealed[i].wrapped.as_slice()).collect();
        let ids: Vec<&str> = biometric.iter().map(|&i| items[i].id.as_str()).collect();
        let unlocked = self.unwrap_biometric(&ids, &wrapped, prompt)?;

        let mut out = Vec::with_capacity(items.len());
        for (i, meta) in items.iter().enumerate() {
            let dk = match biometric.iter().position(|&b| b == i) {
                Some(n) => crypto::key_from_slice(&unlocked[n])?,
                None => crypto::key_from_slice(&crypto::open(&self.vk, &wrap_aad(&meta.id), &sealed[i].wrapped)?)?,
            };
            let plain = crypto::open(&dk, &payload_aad(meta)?, &sealed[i].payload)?;
            out.push(serde_json::from_slice(&plain)?);
        }
        Ok(out)
    }

    /// Unwraps level 4 data keys with one hardware call, so the user is
    /// asked once however many there are.
    fn unwrap_biometric(
        &self,
        item_ids: &[&str],
        wrapped: &[&[u8]],
        prompt: &str,
    ) -> Result<Vec<zeroize::Zeroizing<Vec<u8>>>> {
        if wrapped.is_empty() {
            return Ok(vec![]);
        }
        let ephemerals: Vec<&[u8]> =
            wrapped.iter().map(|w| crypto::ecies_ephemeral(w)).collect::<Result<_>>()?;
        let shared = self.hw.biometric_ecdh(&ephemerals, prompt)?;
        if shared.len() != wrapped.len() {
            return Err(Error::Hardware("wrong number of ECDH results".into()));
        }
        let public = crypto::normalize_public(&self.hw.biometric_public())?;
        (0..wrapped.len())
            .map(|i| crypto::ecies_open(&shared[i], &public, &wrap_aad(item_ids[i]), wrapped[i]))
            .collect()
    }

    // --- Devices -----------------------------------------------------------

    fn write_member(&self, conn: &Connection, record: &DeviceRecord, wrapped_vk: &[u8], version: u64) -> Result<()> {
        let sealed = crypto::seal(&self.vk, &member_aad(&record.id), &serde_json::to_vec(record)?);
        conn.execute(
            "INSERT OR REPLACE INTO members (id, wrapped_vk, sealed, version, author)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![record.id, wrapped_vk, sealed, version, self.device_id],
        )?;
        Ok(())
    }

    /// Every device that ever held this vault, including removed ones.
    pub fn devices(&self) -> Result<Vec<DeviceRecord>> {
        let conn = self.conn();
        let mut records: Vec<DeviceRecord> = conn
            .prepare("SELECT id, sealed, version FROM members")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get(2)?)))?
            .map(|row| {
                let (id, sealed, version) = row?;
                let plain = crypto::open(&self.vk, &member_aad(&id), &sealed)?;
                let mut record: DeviceRecord = serde_json::from_slice(&plain)?;
                record.id = id;
                record.version = version;
                Ok(record)
            })
            .collect::<Result<_>>()?;
        records.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        Ok(records)
    }

    pub(crate) fn this_device(&self) -> Result<DeviceRecord> {
        self.devices()?
            .into_iter()
            .find(|d| d.id == self.device_id)
            .ok_or_else(|| Error::Vault("this device is not enrolled in the vault".into()))
    }

    /// The device's name, as given when it joined the vault.
    pub fn device_name(&self) -> Result<String> {
        Ok(self.this_device()?.name)
    }

    /// Rewrites a device record with a new version, keeping its wrapped key.
    fn save_device(&self, record: &DeviceRecord) -> Result<()> {
        let conn = self.conn();
        let wrapped_vk: Vec<u8> =
            conn.query_row("SELECT wrapped_vk FROM members WHERE id = ?1", [&record.id], |r| r.get(0))?;
        let version = next_version(&conn)?;
        self.write_member(&conn, record, &wrapped_vk, version)
    }

    /// Publishes where this device can be reached. Returns whether anything
    /// changed (and so needs syncing).
    pub fn set_info(&self, port: u16, addresses: Vec<String>) -> Result<bool> {
        let (_, noise_public) = self.noise_keypair()?;
        let mut record = self.this_device()?;
        let before = record.clone();
        record.noise_public = hex::encode(noise_public);
        record.port = port;
        record.addresses = addresses;
        if record == before {
            return Ok(false);
        }
        self.save_device(&record)?;
        Ok(true)
    }

    /// Admits a new device: wraps the vault key to its hardware key and
    /// every level 4 data key to its biometric key. The second part needs a
    /// biometric check on this device, showing `prompt`, if any level 4
    /// secret exists.
    pub fn enrol_device(&self, new: NewDevice, prompt: &str) -> Result<Bootstrap> {
        let device_pub = crypto::normalize_public(&new.device_pub)?;
        let biometric_pub = crypto::normalize_public(&new.biometric_pub)?;
        let id = device_id(&device_pub);
        let wrapped_vk = crypto::ecies_seal(&device_pub, &vk_aad(&id), &*self.vk)?;

        // Level 4 secrets this device can read, to share with the newcomer.
        let rows: Vec<(String, Vec<u8>)> = {
            let conn = self.conn();
            let rows = conn
                .prepare(
                    "SELECT w.item_id, w.wrapped FROM wraps w JOIN items i ON i.id = w.item_id
                     WHERE w.recipient = ?1 AND i.deleted = 0",
                )?
                .query_map([&self.device_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            rows
        };
        let ids: Vec<&str> = rows.iter().map(|(id, _)| id.as_str()).collect();
        let wrapped: Vec<&[u8]> = rows.iter().map(|(_, w)| w.as_slice()).collect();
        let keys = self.unwrap_biometric(&ids, &wrapped, prompt)?;

        let record = DeviceRecord {
            id: id.clone(),
            name: new.name,
            device_pub: hex::encode(&device_pub),
            biometric_pub: hex::encode(&biometric_pub),
            noise_public: new.noise_public.map(hex::encode).unwrap_or_default(),
            port: 0,
            addresses: vec![],
            removed: false,
            recovery: new.noise_public.is_none(),
            version: 0,
        };
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let version = next_version(&tx)?;
        self.write_member(&tx, &record, &wrapped_vk, version)?;
        for (item_id, dk) in ids.iter().zip(&keys) {
            tx.execute(
                "INSERT OR REPLACE INTO wraps (item_id, recipient, wrapped) VALUES (?1, ?2, ?3)",
                params![item_id, id, crypto::ecies_seal(&biometric_pub, &wrap_aad(item_id), dk)?],
            )?;
        }
        tx.commit()?;
        Ok(Bootstrap { device_id: id, wrapped_vk })
    }

    /// Marks a device as removed: it is no longer synced with, accepted, or
    /// given new level 4 secrets. It keeps what it could already decrypt, so
    /// those secrets should be rotated: their names are returned. `None` if
    /// the device is unknown.
    pub fn remove_device(&self, id: &str) -> Result<Option<Vec<String>>> {
        if id == self.device_id {
            return Err(Error::Vault("a device cannot remove itself".into()));
        }
        let Some(mut record) = self.devices()?.into_iter().find(|d| d.id == id) else {
            return Ok(None);
        };
        // The vault key opened every secret below level 4; at level 4, only
        // those whose key was wrapped to the device.
        let wrapped: Vec<String> = self
            .conn()
            .prepare("SELECT item_id FROM wraps WHERE recipient = ?1")?
            .query_map([id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let exposed: Vec<String> = self
            .list()?
            .into_iter()
            .filter(|m| m.level != Level::Biometric || wrapped.contains(&m.id))
            .map(|m| m.name)
            .collect();
        record.removed = true;
        self.save_device(&record)?;
        self.conn().execute("DELETE FROM wraps WHERE recipient = ?1", [id])?;
        if !record.recovery {
            let note = RotateNote { who: record.name.clone(), why: "removed".into(), at_ms: now_ms() };
            self.flag_rotation(&exposed, note)?;
        }
        Ok(Some(exposed))
    }

    /// Creates the offline recovery key and returns it, once: it is not
    /// stored. The vault keeps only its public half, as one more recipient
    /// of the vault key and of every level 4 data key, which needs a
    /// biometric check here (showing `prompt`) if level 4 secrets exist.
    ///
    /// Whoever holds the recovery key and a copy of the vault file can read
    /// everything, with no device and no fingerprint. Creating a new one
    /// replaces the old.
    pub fn create_recovery_key(&self, prompt: &str) -> Result<String> {
        let keys = crate::hardware::SoftwareKeys::single(|_| true);
        let public = keys.device_public();
        self.enrol_device(
            NewDevice {
                name: "Recovery key".into(),
                device_pub: public.clone(),
                biometric_pub: public.clone(),
                noise_public: None,
            },
            prompt,
        )?;
        let id = device_id(&crypto::normalize_public(&public)?);
        for old in self.devices()?.into_iter().filter(|d| d.recovery && !d.removed && d.id != id) {
            self.remove_device(&old.id)?;
        }
        Ok(format!("{RECOVERY_PREFIX}{}", hex::encode(keys.secret())))
    }

    /// Restores this device's access to the vault file at `path` with the
    /// recovery key: after the device's keys were lost or replaced (for
    /// example its fingerprints changed), or on a new device given a copy of
    /// the file. The device becomes a member with fresh wraps of the vault
    /// key and of every level 4 data key.
    pub fn recover(path: &Path, hw: Arc<dyn HardwareKeys>, device_name: &str, recovery_key: &str) -> Result<Self> {
        let secret = recovery_key
            .trim()
            .strip_prefix(RECOVERY_PREFIX)
            .and_then(|h| hex::decode(h.replace(['-', ' '], "")).ok())
            .ok_or_else(|| Error::Vault("not a Mayi recovery key".into()))?;
        let recovery = crate::hardware::SoftwareKeys::from_single(&secret, |_| true)
            .map_err(|_| Error::Vault("not a Mayi recovery key".into()))?;
        // Open the vault as the recovery key, then admit this device the
        // way any device admits another.
        let view = Self::open(path, Arc::new(recovery))
            .map_err(|_| Error::Vault("this recovery key does not belong to this vault".into()))?;
        let (_, noise_public) = view.noise_keypair()?;
        view.enrol_device(
            NewDevice {
                name: device_name.to_string(),
                device_pub: hw.device_public(),
                biometric_pub: hw.biometric_public(),
                noise_public: Some(noise_public),
            },
            "",
        )?;
        drop(view);
        Self::open(path, hw)
    }

    /// The enrolled, unremoved device holding this tunnel key, if any.
    pub fn device_by_noise_key(&self, public: &[u8; 32]) -> Result<Option<DeviceRecord>> {
        let wanted = hex::encode(public);
        Ok(self.devices()?.into_iter().find(|d| d.noise_public == wanted && !d.removed))
    }

    // --- Tunnel identity ---------------------------------------------------

    fn store_noise_keypair(&self, private: &[u8; 32], public: &[u8; 32]) -> Result<()> {
        let pair = zeroize::Zeroizing::new([private.as_slice(), public].concat());
        self.conn().execute(
            "INSERT OR REPLACE INTO local (key, value) VALUES ('noise_static', ?1)",
            [crypto::seal(&self.vk, b"mayi/local/noise_static", &pair)],
        )?;
        Ok(())
    }

    /// This device's static key for the encrypted tunnel, created on first
    /// use. It identifies the device to paired machines and other devices;
    /// it protects no secret at rest, so it is a software key sealed under
    /// the vault key. It stays on this device and is never synced.
    pub fn noise_keypair(&self) -> Result<(Key, [u8; 32])> {
        let stored: Option<Vec<u8>> = self
            .conn()
            .query_row("SELECT value FROM local WHERE key = 'noise_static'", [], |r| r.get(0))
            .optional()?;
        let pair = match stored {
            Some(sealed) => crypto::open(&self.vk, b"mayi/local/noise_static", &sealed)?,
            None => {
                let (private, public) = mayi_proto::noise::generate_keypair()?;
                self.store_noise_keypair(&private, &public)?;
                zeroize::Zeroizing::new([private.as_slice(), &public].concat())
            }
        };
        if pair.len() != 64 {
            return Err(Error::Crypto);
        }
        Ok((crypto::key_from_slice(&pair[..32])?, pair[32..].try_into().expect("32 bytes")))
    }

    // --- Paired machines ---------------------------------------------------

    fn put_requester(&self, record: &RequesterRecord) -> Result<()> {
        let sealed = crypto::seal(&self.vk, &requester_aad(&record.id), &serde_json::to_vec(record)?);
        let conn = self.conn();
        conn.execute(
            "INSERT OR REPLACE INTO requesters (id, sealed, version, author) VALUES (?1, ?2, ?3, ?4)",
            params![record.id, sealed, next_version(&conn)?, self.device_id],
        )?;
        Ok(())
    }

    /// Enrols a machine by its static key. Pairing the same key again
    /// renames it and lifts a revocation.
    pub fn add_requester(&self, name: &str, public: [u8; 32]) -> Result<RequesterRecord> {
        self.enrol_requester(name, public, None)
    }

    /// Enrols the machine this device runs on, so that requests made on it
    /// can also reach the vault's other devices.
    pub fn add_local_requester(&self, name: &str, public: [u8; 32]) -> Result<RequesterRecord> {
        self.enrol_requester(name, public, Some(self.device_id.clone()))
    }

    fn enrol_requester(&self, name: &str, public: [u8; 32], local_to: Option<String>) -> Result<RequesterRecord> {
        let record = RequesterRecord {
            id: mayi_proto::noise::fingerprint(&public),
            name: name.to_string(),
            public: hex::encode(public),
            added_ms: now_ms(),
            revoked: false,
            local_to,
        };
        self.put_requester(&record)?;
        Ok(record)
    }

    /// Revokes the machines that enrolled themselves through this device's
    /// local socket. Returns how many there were.
    pub fn revoke_local_requesters(&self) -> Result<usize> {
        let mine: Vec<RequesterRecord> = self
            .requesters()?
            .into_iter()
            .filter(|r| !r.revoked && r.local_to.as_deref() == Some(self.device_id.as_str()))
            .collect();
        for mut record in mine.clone() {
            record.revoked = true;
            self.put_requester(&record)?;
        }
        Ok(mine.len())
    }

    /// Every machine ever paired, including revoked ones, by name.
    pub fn requesters(&self) -> Result<Vec<RequesterRecord>> {
        let conn = self.conn();
        let mut records: Vec<RequesterRecord> = conn
            .prepare("SELECT id, sealed FROM requesters")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?
            .map(|row| {
                let (id, sealed) = row?;
                let plain = crypto::open(&self.vk, &requester_aad(&id), &sealed)?;
                let mut record: RequesterRecord = serde_json::from_slice(&plain)?;
                record.id = id;
                Ok(record)
            })
            .collect::<Result<_>>()?;
        records.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        Ok(records)
    }

    /// The paired, unrevoked machine holding this static key, if any.
    pub fn requester_by_key(&self, public: &[u8; 32]) -> Result<Option<RequesterRecord>> {
        let wanted = hex::encode(public);
        Ok(self.requesters()?.into_iter().find(|r| r.public == wanted && !r.revoked))
    }

    /// Stops accepting requests from a machine. Returns the names of the
    /// secrets released to it, by any device whose activity has reached this
    /// one, which its processes have seen and which should be rotated; each
    /// is flagged for rotation. `None` if unknown.
    pub fn revoke_requester(&self, id: &str) -> Result<Option<Vec<String>>> {
        let Some(mut record) = self.requesters()?.into_iter().find(|r| r.id == id) else {
            return Ok(None);
        };
        record.revoked = true;
        self.put_requester(&record)?;
        let label = record.label();
        let mut released: Vec<String> = self
            .audit_tail(usize::MAX >> 1)?
            .into_iter()
            .filter(|e| e.event == "request" && e.outcome == "released" && e.requester == label)
            .flat_map(|e| e.secrets.into_iter().map(|s| s.name))
            .collect();
        released.sort();
        released.dedup();
        let note = RotateNote { who: record.name.clone(), why: "revoked".into(), at_ms: now_ms() };
        self.flag_rotation(&released, note)?;
        Ok(Some(released))
    }

    // --- Showing values to the owner and counting copies ---------------------

    /// Decrypts a secret's values to show them to the owner in the app. The
    /// app confirms the owner is present first; a level 4 secret also asks
    /// for the biometric check that unlocks it, showing `prompt`. Recorded
    /// in the audit log as a `view`.
    pub fn view(&self, name: &str, prompt: &str) -> Result<(ItemMeta, SecretValues)> {
        let meta = self.meta(name)?;
        let values = self.reveal(&[&meta], prompt)?.pop().ok_or_else(|| Error::NotFound(name.to_string()))?;
        self.audit(&AuditEntry {
            ts_ms: now_ms(),
            event: "view".into(),
            outcome: "shown".into(),
            requester: "local".into(),
            secrets: vec![SecretUse { name: meta.name.clone(), level: meta.level as u8, via: "owner".into() }],
            ..Default::default()
        })?;
        Ok((meta, values))
    }

    /// Records, after a sync with the device whose tunnel key is `peer`, that
    /// it now holds every item at the version this device holds.
    pub fn note_synced(&self, peer: &[u8; 32]) -> Result<()> {
        let Some(device) = self.device_by_noise_key(peer)? else { return Ok(()) };
        if device.id == self.device_id {
            return Ok(());
        }
        let conn = self.conn();
        let held: BTreeMap<String, Stamp> = conn
            .prepare("SELECT id, version, author FROM items")?
            .query_map([], |r| Ok((r.get(0)?, Stamp { version: r.get(1)?, author: r.get(2)? })))?
            .collect::<rusqlite::Result<_>>()?;
        conn.execute(
            "INSERT OR REPLACE INTO local (key, value) VALUES (?1, ?2)",
            params![format!("holds:{}", device.id), serde_json::to_vec(&held)?],
        )?;
        Ok(())
    }

    /// How many devices hold each secret's current version, by item id, as
    /// far as this device knows: itself, the device that wrote that version,
    /// and every device it has synced with since. Removed devices and the
    /// recovery key do not count. A secret with one copy is lost with its
    /// device.
    pub fn copies(&self) -> Result<HashMap<String, u32>> {
        let others: Vec<String> = self
            .devices()?
            .into_iter()
            .filter(|d| !d.removed && !d.recovery && d.id != self.device_id)
            .map(|d| d.id)
            .collect();
        let conn = self.conn();
        let mut holds: HashMap<&str, BTreeMap<String, Stamp>> = HashMap::new();
        for id in &others {
            let stored: Option<Vec<u8>> = conn
                .query_row("SELECT value FROM local WHERE key = ?1", [format!("holds:{id}")], |r| r.get(0))
                .optional()?;
            if let Some(bytes) = stored {
                holds.insert(id, serde_json::from_slice(&bytes).unwrap_or_default());
            }
        }
        let items: Vec<(String, Stamp)> = conn
            .prepare("SELECT id, version, author FROM items WHERE deleted = 0")?
            .query_map([], |r| Ok((r.get(0)?, Stamp { version: r.get(1)?, author: r.get(2)? })))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(items
            .into_iter()
            .map(|(id, stamp)| {
                let elsewhere = others
                    .iter()
                    .filter(|d| **d == stamp.author || holds.get(d.as_str()).and_then(|h| h.get(&id)) == Some(&stamp))
                    .count();
                (id, 1 + elsewhere as u32)
            })
            .collect())
    }

    // --- Audit log ---------------------------------------------------------

    pub fn audit(&self, entry: &AuditEntry) -> Result<()> {
        let conn = self.conn();
        conn.execute(
            "INSERT INTO audit (ts_ms, entry) VALUES (?1, ?2)",
            params![entry.ts_ms, serde_json::to_string(entry)?],
        )?;
        // Kept for 90 days, here and as received from the other devices.
        let cutoff = now_ms().saturating_sub(LOG_KEPT_MS);
        conn.execute("DELETE FROM audit WHERE ts_ms < ?1", [cutoff])?;
        conn.execute("DELETE FROM shared_log WHERE ts_ms < ?1", [cutoff])?;
        Ok(())
    }

    /// The last `n` entries of the vault's activity, oldest first: this
    /// device's and those received from the others, which carry `device`.
    pub fn audit_tail(&self, n: usize) -> Result<Vec<AuditEntry>> {
        let conn = self.conn();
        // By time, and within a millisecond in the order each device wrote them.
        let mut rows: Vec<(u64, u64, String, String)> = conn
            .prepare(
                "SELECT ts_ms, id, '', entry FROM audit
                 UNION ALL SELECT ts_ms, seq, author, entry FROM shared_log
                 ORDER BY 1 DESC, 2 DESC LIMIT ?1",
            )?
            .query_map([n as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        rows.reverse();
        rows.into_iter()
            .map(|(_, _, author, entry)| {
                let mut entry: AuditEntry = serde_json::from_str(&entry)?;
                entry.device = author;
                Ok(entry)
            })
            .collect()
    }

    /// For sync: the newest activity entry held from each device of the
    /// vault, by device id, 0 for none. Listing them tells a peer this device
    /// takes activity.
    pub(crate) fn log_marks(&self) -> Result<BTreeMap<String, u64>> {
        let conn = self.conn();
        let mut marks: BTreeMap<String, u64> = conn
            .prepare("SELECT author, MAX(seq) FROM shared_log GROUP BY author")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let own: Option<u64> = conn.query_row("SELECT MAX(id) FROM audit", [], |r| r.get(0))?;
        marks.insert(self.device_id.clone(), own.unwrap_or(0));
        // Every device of the vault, so that two devices in step list the same.
        let members: Vec<String> =
            conn.prepare("SELECT id FROM members")?.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        for id in members {
            marks.entry(id).or_insert(0);
        }
        Ok(marks)
    }

    /// For sync: up to `limit` activity entries of `author` after `after`,
    /// oldest first, as (seq, ts_ms, sealed under the vault key).
    pub(crate) fn log_after(&self, author: &str, after: u64, limit: usize) -> Result<Vec<(u64, u64, Vec<u8>)>> {
        let conn = self.conn();
        let rows: Vec<(u64, u64, String)> = if author == self.device_id {
            conn.prepare("SELECT id, ts_ms, entry FROM audit WHERE id > ?1 ORDER BY id LIMIT ?2")?
                .query_map(params![after, limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<rusqlite::Result<_>>()?
        } else {
            conn.prepare(
                "SELECT seq, ts_ms, entry FROM shared_log WHERE author = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
            )?
            .query_map(params![author, after, limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?
        };
        Ok(rows
            .into_iter()
            .map(|(seq, ts, entry)| (seq, ts, crypto::seal(&self.vk, &log_aad(author, seq), entry.as_bytes())))
            .collect())
    }

    /// For sync: keeps an activity entry another device wrote. Returns whether
    /// it was new. One that does not open under the vault key is refused.
    pub(crate) fn keep_log(&self, conn: &Connection, author: &str, seq: u64, ts_ms: u64, sealed: &[u8]) -> Result<bool> {
        if author == self.device_id {
            return Ok(false);
        }
        let plain = crypto::open(&self.vk, &log_aad(author, seq), sealed)?;
        let entry: AuditEntry = serde_json::from_slice(&plain)?;
        if ts_ms < now_ms().saturating_sub(LOG_KEPT_MS) {
            return Ok(false);
        }
        let added = conn.execute(
            "INSERT OR IGNORE INTO shared_log (author, seq, ts_ms, entry) VALUES (?1, ?2, ?3, ?4)",
            params![author, seq, ts_ms, serde_json::to_string(&entry)?],
        )?;
        Ok(added > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::SoftwareKeys;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zeroize::Zeroizing;

    fn values(pairs: &[(&str, &str)]) -> SecretValues {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string())))
            .collect()
    }

    fn item(name: &str, level: Level, value: &str) -> NewItem {
        NewItem {
            name: name.into(),
            level,
            values: values(&[("value", value)]),
            allow: vec![],
            max_grant_secs: 600,
            destination: Destination::Command,
            sites: vec![],
            folder: None,
        }
    }

    fn login(name: &str, fields: &[(&str, &str)], sites: &[&str]) -> NewItem {
        NewItem {
            name: name.into(),
            level: Level::Approve,
            values: values(fields),
            allow: vec![],
            max_grant_secs: 600,
            destination: Destination::Website,
            sites: sites.iter().map(|s| s.to_string()).collect(),
            folder: None,
        }
    }

    fn vault(dir: &tempfile::TempDir) -> Vault {
        Vault::create(&dir.path().join("v.db"), Arc::new(SoftwareKeys::generate(|_| true)), "test").unwrap()
    }

    #[test]
    fn put_list_reveal_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let keys = SoftwareKeys::generate(|_| true);
        let key_bytes = keys.to_bytes();
        let vault = Vault::create(&path, Arc::new(keys), "test").unwrap();
        vault.put(item("B_TOKEN", Level::Log, "bbb")).unwrap();
        vault.put(item("A_TOKEN", Level::Approve, "aaa")).unwrap();
        drop(vault);

        let keys = SoftwareKeys::from_bytes(&key_bytes, |_| true).unwrap();
        let vault = Vault::open(&path, Arc::new(keys)).unwrap();
        let metas = vault.list().unwrap();
        assert_eq!(
            metas.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
            ["A_TOKEN", "B_TOKEN"]
        );
        let revealed = vault.reveal(&[&metas[0], &metas[1]], "").unwrap();
        assert_eq!(&**revealed[0].get("value").unwrap(), "aaa");
        assert_eq!(&**revealed[1].get("value").unwrap(), "bbb");

        // A different device key cannot open the vault.
        let stranger = SoftwareKeys::generate(|_| true);
        assert!(Vault::open(&path, Arc::new(stranger)).is_err());
    }

    #[test]
    fn replace_keeps_history_and_remove_hides() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        let first = vault.put(item("TOKEN", Level::Log, "one")).unwrap();
        let second = vault.put(item("TOKEN", Level::Notify, "two")).unwrap();
        assert_eq!(first.id, second.id);
        assert!(second.version > first.version, "versions always move forward");
        assert_eq!(&**vault.reveal(&[&second], "").unwrap()[0].get("value").unwrap(), "two");
        // A stale handle does not silently read the newer value.
        assert!(vault.reveal(&[&first], "").is_err());

        vault.remove("TOKEN").unwrap();
        assert!(vault.list().unwrap().is_empty());
        assert!(matches!(vault.meta("TOKEN"), Err(Error::NotFound(_))));
        let history: i64 = vault
            .conn()
            .query_row("SELECT COUNT(*) FROM history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(history, 2);
    }

    #[test]
    fn level_4_needs_the_biometric_key() {
        let dir = tempfile::tempdir().unwrap();
        let allow = Arc::new(AtomicBool::new(false));
        let asked = Arc::new(AtomicUsize::new(0));
        let (allow2, asked2) = (allow.clone(), asked.clone());
        let keys = SoftwareKeys::generate(move |_| {
            asked2.fetch_add(1, Ordering::SeqCst);
            allow2.load(Ordering::SeqCst)
        });
        let vault = Vault::create(&dir.path().join("v.db"), Arc::new(keys), "test").unwrap();

        // Writing asks for nothing.
        let a = vault.put(item("PROD_A", Level::Biometric, "alpha")).unwrap();
        let b = vault.put(item("PROD_B", Level::Biometric, "beta")).unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 0);

        assert!(matches!(vault.reveal(&[&a], "p"), Err(Error::BiometricDenied)));
        allow.store(true, Ordering::SeqCst);
        asked.store(0, Ordering::SeqCst);
        let revealed = vault.reveal(&[&a, &b], "p").unwrap();
        assert_eq!(&**revealed[0].get("value").unwrap(), "alpha");
        assert_eq!(&**revealed[1].get("value").unwrap(), "beta");
        assert_eq!(asked.load(Ordering::SeqCst), 1, "one check for the batch");

        // The data key is wrapped only to the device's biometric key: there
        // is no vault-key wrap, and the vault key does not open the one there is.
        let conn = vault.conn();
        let recipients: Vec<String> = conn
            .prepare("SELECT recipient FROM wraps WHERE item_id = ?1")
            .unwrap()
            .query_map([&a.id], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(recipients, [vault.device_id.as_str()]);
        let (payload, wrapped): (Vec<u8>, Vec<u8>) = conn
            .query_row(
                "SELECT i.payload, w.wrapped FROM items i JOIN wraps w ON w.item_id = i.id
                 WHERE i.id = ?1",
                [&a.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(crypto::open(&vault.vk, &wrap_aad(&a.id), &wrapped).is_err());
        assert!(crypto::open(&vault.vk, &payload_aad(&a).unwrap(), &payload).is_err());
    }

    #[test]
    fn update_rules_keeps_values() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        let first = vault.put(item("TOKEN", Level::Biometric, "x")).unwrap();
        let meta = vault.update_rules("TOKEN", vec!["make *".into()], 60, vec![], Some(" Work ".into())).unwrap();
        assert!(meta.version > first.version);
        assert_eq!(meta.max_grant_secs, 60);
        let stored = vault.meta("TOKEN").unwrap();
        assert_eq!(stored.allow, ["make *"]);
        assert_eq!(stored.level, Level::Biometric);
        assert_eq!(&**vault.reveal(&[&stored], "p").unwrap()[0].get("value").unwrap(), "x");
    }

    #[test]
    fn relabelled_level_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        let mut meta = vault.put(item("TOKEN", Level::Approve, "x")).unwrap();
        meta.level = Level::Log;
        assert!(vault.reveal(&[&meta], "").is_err());
    }

    #[test]
    fn logins_are_checked_and_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let meta = vault
            .put(login(
                "github",
                &[("username", "amine"), ("password", "pw"), ("totp", key)],
                &["https://GitHub.com/login", "github.com", "*.github.com"],
            ))
            .unwrap();
        assert_eq!(meta.destination, Destination::Website);
        assert_eq!(meta.sites, ["github.com", "*.github.com"], "normalized, without repeats");
        assert_eq!(meta.fields, ["password", "totp", "username"]);
        let stored = vault.meta("github").unwrap();
        assert_eq!(stored.sites, meta.sites);
        assert_eq!(&**vault.reveal(&[&stored], "").unwrap()[0].get("totp").unwrap(), key);

        // Empty optional fields are dropped rather than stored.
        let bare = vault.put(login("bare", &[("username", ""), ("password", "pw"), ("totp", " ")], &["a.com"]));
        assert_eq!(bare.unwrap().fields, ["password"]);

        let refused = [
            login("nopw", &[("username", "u")], &["a.com"]),
            login("emptypw", &[("password", "")], &["a.com"]),
            login("nosite", &[("password", "pw")], &[]),
            login("badsite", &[("password", "pw")], &["*.com"]),
            login("badkey", &[("password", "pw"), ("totp", "not a key!")], &["a.com"]),
            login("extra", &[("password", "pw"), ("value", "x")], &["a.com"]),
            NewItem { allow: vec!["curl *".into()], ..login("cmd", &[("password", "pw")], &["a.com"]) },
            NewItem { sites: vec!["a.com".into()], ..item("SECRET", Level::Log, "x") },
        ];
        for new in refused {
            let name = new.name.clone();
            assert!(vault.put(new).is_err(), "{name}");
        }

        // Websites change without the values, and stay checked.
        let moved = vault.update_rules("github", vec![], 60, vec!["gitlab.com".into()], None).unwrap();
        assert_eq!(moved.sites, ["gitlab.com"]);
        assert!(vault.update_rules("github", vec![], 60, vec![], None).is_err());
        assert!(vault.update_rules("github", vec!["x".into()], 60, vec!["a.com".into()], None).is_err());
        vault.put(item("TOKEN", Level::Log, "x")).unwrap();
        assert!(vault.update_rules("TOKEN", vec![], 60, vec!["a.com".into()], None).is_err());
    }

    #[test]
    fn a_login_relabelled_as_a_secret_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        let mut meta = vault.put(login("github", &[("password", "pw")], &["github.com"])).unwrap();
        meta.destination = Destination::Command;
        assert!(vault.reveal(&[&meta], "").is_err());
    }

    /// What a newer device wrote, as a device of this version sees it.
    fn from_a_newer_version(vault: &Vault, name: &str, edit: impl FnOnce(&mut ItemMeta)) -> ItemMeta {
        let mut meta = vault.put(item(name, Level::Biometric, "x")).unwrap();
        edit(&mut meta);
        meta.unknown_fields.insert("targets".into(), serde_json::json!(["ReadOnly"]));
        vault.write_meta(meta).unwrap()
    }

    #[test]
    fn a_secret_from_a_newer_version_is_listed_kept_and_never_opened() {
        let dir = tempfile::tempdir().unwrap();
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let keys = SoftwareKeys::generate(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            true
        });
        let vault = Vault::create(&dir.path().join("v.db"), Arc::new(keys), "test").unwrap();
        from_a_newer_version(&vault, "FILE", |m| m.destination = Destination::Other("file".into()));
        from_a_newer_version(&vault, "AWS", |m| m.source = Source::Other("gcloud".into()));

        for name in ["FILE", "AWS"] {
            let meta = vault.meta(name).unwrap();
            let refused = vault.reveal(&[&meta], "p").err().map(|e| e.to_string()).unwrap_or_default();
            assert!(refused.contains("newer version of Mayi"), "{name}: {refused}");
            assert!(vault.update_rules(name, vec![], 60, vec![], None).is_err(), "{name}");

            // Rotation warnings still apply, and keep what this version does not know.
            let note = RotateNote { who: "old-vm".into(), why: "revoked".into(), at_ms: 1 };
            vault.flag_rotation(&[name.to_string()], note).unwrap();
            let flagged = vault.meta(name).unwrap();
            assert_eq!(flagged.rotate.len(), 1);
            assert_eq!(flagged.destination, meta.destination);
            assert_eq!(flagged.source, meta.source);
            assert_eq!(flagged.unknown_fields.get("targets"), Some(&serde_json::json!(["ReadOnly"])));
        }
        assert_eq!(asked.load(Ordering::SeqCst), 0, "refused before any fingerprint");
    }

    fn counting_vault(dir: &tempfile::TempDir, ok: bool) -> (Vault, Arc<AtomicUsize>) {
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let keys = SoftwareKeys::generate(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            ok
        });
        (Vault::create(&dir.path().join("v.db"), Arc::new(keys), "test").unwrap(), asked)
    }

    #[test]
    fn asking_less_needs_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, asked) = counting_vault(&dir, true);
        let count = || asked.load(Ordering::SeqCst);
        vault.put(item("TOKEN", Level::Approve, "a")).unwrap();
        vault.put(item("TOKEN", Level::Biometric, "b")).unwrap();
        assert_eq!(count(), 0, "new, and raised: nothing asked");
        vault.put(item("TOKEN", Level::Notify, "c")).unwrap();
        assert_eq!(count(), 1, "lowered");
        vault.update_rules("TOKEN", vec!["make *".into()], 600, vec![], None).unwrap();
        assert_eq!(count(), 2, "an expected command added");
        vault.update_rules("TOKEN", vec![], 60, vec![], Some("Work".into())).unwrap();
        assert_eq!(count(), 2, "removing and moving ask nothing");
        vault.update_rules("TOKEN", vec![], 3600, vec![], None).unwrap();
        assert_eq!(count(), 3, "a longer grant");

        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = counting_vault(&dir, false);
        vault.put(item("TOKEN", Level::Approve, "a")).unwrap();
        assert!(vault.put(item("TOKEN", Level::Log, "b")).is_err());
        let meta = vault.meta("TOKEN").unwrap();
        assert_eq!(meta.level, Level::Approve, "unchanged when refused");
        assert_eq!(&**vault.reveal(&[&meta], "").unwrap()[0].get("value").unwrap(), "a");
        assert!(vault.update_rules("TOKEN", vec!["*".into()], 600, vec![], None).is_err());
    }

    fn aws_sign_in(vault: &Vault) -> ItemMeta {
        use crate::aws::{fake::FakeAws, suggest_profiles, SignIn};
        let api = FakeAws::default();
        let session = SignIn::start(&api, "https://mawaqit.awsapps.com/start", "eu-west-3")
            .unwrap()
            .wait(&api, &AtomicBool::new(false))
            .unwrap();
        let profiles = suggest_profiles(&session.accounts(&api).unwrap());
        let aws = AwsSignIn { start_url: session.start_url.clone(), region: "eu-west-3".into(), profiles };
        vault.put_aws("mawaqit", aws, session.values(), None).unwrap()
    }

    #[test]
    fn aws_profiles_are_loosened_only_with_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, asked) = counting_vault(&dir, true);
        let count = || asked.load(Ordering::SeqCst);
        let meta = aws_sign_in(&vault);
        assert_eq!(meta.source, Source::AwsSso);
        assert!(vault.reveal(&[&meta], "").unwrap()[0].contains_key("refresh_token"));
        let mut profiles = meta.aws.clone().unwrap().profiles;

        profiles[0].level = Level::Biometric;
        profiles[1].name = "prod-admin".into();
        vault.update_aws_profiles("mawaqit", profiles.clone()).unwrap();
        assert_eq!(count(), 0, "raised and renamed");
        profiles[0].level = Level::Log;
        vault.update_aws_profiles("mawaqit", profiles.clone()).unwrap();
        assert_eq!(count(), 1, "lowered");
        let removed: Vec<AwsProfile> = profiles[1..].to_vec();
        vault.update_aws_profiles("mawaqit", removed).unwrap();
        assert_eq!(count(), 1, "removed");
        vault.update_aws_profiles("mawaqit", profiles.clone()).unwrap();
        assert_eq!(count(), 2, "added back");

        // Not a plain secret, and not to be turned into one.
        assert!(vault.put(item("mawaqit", Level::Log, "x")).is_err());
        assert!(vault.update_rules("mawaqit", vec!["aws *".into()], 600, vec![], None).is_err());
        assert!(vault.update_aws_profiles("TOKEN", vec![]).is_err());
        let mut bad = profiles.clone();
        bad[0].name = bad[1].name.clone();
        assert!(vault.update_aws_profiles("mawaqit", bad).is_err());

        // Signing in again keeps the profiles; another portal is refused.
        let fresh = vault.reveal(&[&vault.meta("mawaqit").unwrap()], "").unwrap().remove(0);
        let renewed = vault.renew_aws("mawaqit", fresh.clone()).unwrap();
        assert_eq!(renewed.aws.unwrap().profiles, profiles);
        let mut other = fresh;
        other.insert("start_url".into(), Zeroizing::new("https://other.awsapps.com/start".into()));
        assert!(vault.renew_aws("mawaqit", other).is_err());

        let dir = tempfile::tempdir().unwrap();
        let (vault, _) = counting_vault(&dir, false);
        let meta = aws_sign_in(&vault);
        let mut profiles = meta.aws.unwrap().profiles;
        profiles[0].level = Level::Log;
        profiles[1].level = Level::Log;
        assert!(vault.update_aws_profiles("mawaqit", profiles).is_err());
    }

    #[test]
    fn requesters_and_noise_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let keys = SoftwareKeys::generate(|_| true);
        let key_bytes = keys.to_bytes();
        let vault = Vault::create(&path, Arc::new(keys), "mac").unwrap();
        assert_eq!(vault.device_name().unwrap(), "mac");
        let (private, public) = vault.noise_keypair().unwrap();
        let machine = vault.add_requester("build-vm", [5u8; 32]).unwrap();
        assert_eq!(machine.label(), format!("build-vm ({})", &machine.id[..8]));
        assert!(vault.requester_by_key(&[5u8; 32]).unwrap().is_some());
        assert!(vault.requester_by_key(&[6u8; 32]).unwrap().is_none());

        // Tampering with the stored row is detected.
        vault
            .conn()
            .execute("UPDATE requesters SET id = 'other' WHERE id = ?1", [&machine.id])
            .unwrap();
        assert!(vault.requesters().is_err());
        vault
            .conn()
            .execute("UPDATE requesters SET id = ?1 WHERE id = 'other'", [&machine.id])
            .unwrap();

        assert_eq!(vault.revoke_requester(&machine.id).unwrap(), Some(vec![]));
        assert_eq!(vault.revoke_requester("nope").unwrap(), None);
        assert!(vault.requester_by_key(&[5u8; 32]).unwrap().is_none());
        assert!(vault.requesters().unwrap()[0].revoked);
        drop(vault);

        let keys = SoftwareKeys::from_bytes(&key_bytes, |_| true).unwrap();
        let vault = Vault::open(&path, Arc::new(keys)).unwrap();
        let (private2, public2) = vault.noise_keypair().unwrap();
        assert_eq!((&*private, public), (&*private2, public2), "the tunnel key is stable");
        // Pairing the same key again lifts the revocation.
        vault.add_requester("build-vm", [5u8; 32]).unwrap();
        assert!(vault.requester_by_key(&[5u8; 32]).unwrap().is_some());
    }

    #[test]
    fn device_info_is_published_once() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        assert!(vault.set_info(7462, vec!["10.0.0.2".into()]).unwrap());
        assert!(!vault.set_info(7462, vec!["10.0.0.2".into()]).unwrap(), "unchanged");
        let me = &vault.devices().unwrap()[0];
        assert_eq!((me.port, me.addresses.as_slice()), (7462, &["10.0.0.2".to_string()][..]));
        let (_, public) = vault.noise_keypair().unwrap();
        assert_eq!(vault.device_by_noise_key(&public).unwrap().unwrap().id, vault.device_id());
        assert!(vault.remove_device(vault.device_id()).is_err());
    }

    /// Device records written when phones still had a wake-up address.
    #[test]
    fn device_records_with_a_wake_up_address_still_load() {
        let old = r#"{"name":"Pixel","device_pub":"04","biometric_pub":"04","noise_public":"ab",
            "port":7462,"addresses":["100.64.0.2"],"wake":{"url":"https://w.example/wake","id":"x"},
            "removed":false,"recovery":false}"#;
        let record: DeviceRecord = serde_json::from_str(old).unwrap();
        assert_eq!((record.name.as_str(), record.port), ("Pixel", 7462));
    }

    #[test]
    fn recovery_key_restores_a_device_whose_keys_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let vault = Vault::create(&path, Arc::new(SoftwareKeys::generate(|_| true)), "mac").unwrap();
        vault.put(item("L1", Level::Log, "one")).unwrap();
        vault.put(item("L4", Level::Biometric, "four")).unwrap();
        let key = vault.create_recovery_key("make a recovery key").unwrap();
        assert!(key.starts_with("mayi-recovery1."));
        // Secrets written afterwards are covered too.
        vault.put(item("LATER", Level::Biometric, "later")).unwrap();
        let listed = vault.devices().unwrap();
        assert_eq!(listed.iter().filter(|d| d.recovery).count(), 1);
        assert!(!serde_json::to_string(&listed).unwrap().contains(&key[15..]), "only the public half is kept");
        drop(vault);

        // The Mac's keys are gone (new fingerprints, or a new Mac with a
        // copy of the file). Without the recovery key there is no way in.
        let new_keys = Arc::new(SoftwareKeys::generate(|_| true));
        assert!(Vault::open(&path, new_keys.clone()).is_err());
        assert!(Vault::recover(&path, new_keys.clone(), "mac", "mayi-recovery1.00").is_err());
        let other = SoftwareKeys::single(|_| true);
        let wrong = format!("mayi-recovery1.{}", hex::encode(other.secret()));
        assert!(Vault::recover(&path, new_keys.clone(), "mac", &wrong).is_err());

        let restored = Vault::recover(&path, new_keys.clone(), "new mac", &format!(" {key}\n")).unwrap();
        for (name, value) in [("L1", "one"), ("L4", "four"), ("LATER", "later")] {
            let meta = restored.meta(name).unwrap();
            assert_eq!(&**restored.reveal(&[&meta], "p").unwrap()[0].get("value").unwrap(), value);
        }
        drop(restored);
        assert!(Vault::open(&path, new_keys).is_ok(), "and it stays restored");
    }

    #[test]
    fn a_new_recovery_key_replaces_the_old_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.db");
        let vault = Vault::create(&path, Arc::new(SoftwareKeys::generate(|_| true)), "mac").unwrap();
        let first = vault.create_recovery_key("p").unwrap();
        let second = vault.create_recovery_key("p").unwrap();
        vault.put(item("L4", Level::Biometric, "four")).unwrap();
        drop(vault);
        let keys = Arc::new(SoftwareKeys::generate(|_| true));
        // The old key still opens the vault key it was given, but gets no
        // new level 4 secrets.
        let via_old = Vault::recover(&path, keys.clone(), "x", &first).unwrap();
        let meta = via_old.meta("L4").unwrap();
        assert!(via_old.reveal(&[&meta], "p").is_err());
        drop(via_old);
        let via_new = Vault::recover(&path, Arc::new(SoftwareKeys::generate(|_| true)), "y", &second).unwrap();
        let meta = via_new.meta("L4").unwrap();
        assert!(via_new.reveal(&[&meta], "p").is_ok());
    }

    #[test]
    fn removing_and_revoking_say_what_to_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        vault.put(item("L1", Level::Log, "one")).unwrap();
        vault.put(item("BEFORE", Level::Biometric, "b")).unwrap();
        let phone = SoftwareKeys::generate(|_| true);
        let bootstrap = vault
            .enrol_device(
                NewDevice {
                    name: "phone".into(),
                    device_pub: phone.device_public(),
                    biometric_pub: phone.biometric_public(),
                    noise_public: Some([1u8; 32]),
                },
                "p",
            )
            .unwrap();
        assert_eq!(vault.remove_device(&bootstrap.device_id).unwrap(), Some(vec!["BEFORE".to_string(), "L1".to_string()]));
        assert_eq!(vault.remove_device("nope").unwrap(), None);

        let machine = vault.add_requester("vm", [2u8; 32]).unwrap();
        for (name, outcome, requester) in [
            ("L1", "released", machine.label()),
            ("L1", "released", machine.label()),
            ("BEFORE", "denied: denied by the user", machine.label()),
            ("BEFORE", "released", "local".to_string()),
        ] {
            vault
                .audit(&AuditEntry {
                    ts_ms: now_ms(),
                    event: "request".into(),
                    outcome: outcome.into(),
                    requester,
                    secrets: vec![SecretUse { name: name.into(), level: 1, via: "level".into() }],
                    ..Default::default()
                })
                .unwrap();
        }
        assert_eq!(vault.revoke_requester(&machine.id).unwrap(), Some(vec!["L1".to_string()]));
        let notes: Vec<(String, String)> =
            vault.meta("L1").unwrap().rotate.into_iter().map(|n| (n.who, n.why)).collect();
        assert_eq!(notes, [("phone".into(), "removed".into()), ("vm".into(), "revoked".into())], "flagged for both");
    }

    #[test]
    fn the_clock_never_goes_back() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        let conn = vault.conn();
        let far = now_ms() + 1_000_000;
        vault.observe(&conn, far).unwrap();
        assert_eq!(next_version(&conn).unwrap(), far + 1);
        vault.observe(&conn, 5).unwrap();
        assert_eq!(next_version(&conn).unwrap(), far + 2);
    }

    #[test]
    fn bad_names_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(&dir);
        for name in ["", "a/b", "a=b", "a b"] {
            assert!(vault.put(item(name, Level::Log, "x")).is_err(), "{name:?}");
        }
    }
}
