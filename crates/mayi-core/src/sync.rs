//! Keeping the copies of a vault on different devices the same.
//!
//! There is no server: two devices that can reach each other compare what
//! they have and exchange what the other lacks. For each record the copy
//! with the higher [`Stamp`] wins; the losing version of a secret is kept in
//! history. Records are accepted only if they open under the vault key, so a
//! device that is not a member cannot inject anything.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use mayi_proto::{read_frame, write_frame};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::vault::{device_id, member_aad, requester_aad, DeviceRecord, Stamp, Vault};
use crate::{Error, Result};

/// One synced row. Binary fields are hex.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Member { id: String, stamp: Stamp, wrapped_vk: String, sealed: String },
    Item {
        id: String,
        stamp: Stamp,
        deleted: bool,
        meta: String,
        payload: Option<String>,
        /// Data key wraps: (recipient, wrapped key).
        wraps: Vec<(String, String)>,
    },
    Requester { id: String, stamp: Stamp, sealed: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestEntry {
    pub stamp: Stamp,
    /// For items: who the data key is wrapped to. A device joining later
    /// adds wraps without changing the item's stamp.
    #[serde(default)]
    pub wraps: BTreeSet<String>,
}

/// What a device has, by `kind:id`.
pub type Digest = BTreeMap<String, DigestEntry>;

/// Messages between two vault devices.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DeviceMsg {
    /// A new device asks to join, over an enrolment tunnel. Keys are hex.
    Enrol { name: String, device_pub: String, biometric_pub: String, noise_public: String },
    Enrolled { device_id: String, wrapped_vk: String },
    /// Sync, step 1: what the caller has.
    Digest { entries: Digest },
    /// Step 2: what the callee has, and the records the caller lacks.
    Reply { entries: Digest, records: Vec<Record> },
    /// Step 3: the records the callee lacks.
    Records { records: Vec<Record> },
    Done,
    Error { message: String },
}

/// id, version, author, deleted, meta, payload.
type ItemRow = (String, u64, String, bool, Vec<u8>, Option<Vec<u8>>);

fn unhex(text: &str) -> Result<Vec<u8>> {
    hex::decode(text).map_err(|_| Error::Vault("damaged record received".into()))
}

fn key(kind: &str, id: &str) -> String {
    format!("{kind}:{id}")
}

impl Vault {
    /// Every synced record this device holds.
    fn records(&self) -> Result<Vec<Record>> {
        let conn = self.conn();
        let mut records: Vec<Record> = conn
            .prepare("SELECT id, version, author, wrapped_vk, sealed FROM members")?
            .query_map([], |r| {
                Ok(Record::Member {
                    id: r.get(0)?,
                    stamp: Stamp { version: r.get(1)?, author: r.get(2)? },
                    wrapped_vk: hex::encode(r.get::<_, Vec<u8>>(3)?),
                    sealed: hex::encode(r.get::<_, Vec<u8>>(4)?),
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let requesters: Vec<Record> = conn
            .prepare("SELECT id, version, author, sealed FROM requesters")?
            .query_map([], |r| {
                Ok(Record::Requester {
                    id: r.get(0)?,
                    stamp: Stamp { version: r.get(1)?, author: r.get(2)? },
                    sealed: hex::encode(r.get::<_, Vec<u8>>(3)?),
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        records.extend(requesters);
        let items: Vec<ItemRow> = conn
            .prepare("SELECT id, version, author, deleted, meta, payload FROM items")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, version, author, deleted, meta, payload) in items {
            let wraps = conn
                .prepare("SELECT recipient, wrapped FROM wraps WHERE item_id = ?1 ORDER BY recipient")?
                .query_map([&id], |r| Ok((r.get(0)?, hex::encode(r.get::<_, Vec<u8>>(1)?))))?
                .collect::<rusqlite::Result<_>>()?;
            records.push(Record::Item {
                id,
                stamp: Stamp { version, author },
                deleted,
                meta: hex::encode(meta),
                payload: payload.map(hex::encode),
                wraps,
            });
        }
        Ok(records)
    }

    fn digest_of(record: &Record) -> (String, DigestEntry) {
        match record {
            Record::Member { id, stamp, .. } => {
                (key("member", id), DigestEntry { stamp: stamp.clone(), wraps: BTreeSet::new() })
            }
            Record::Requester { id, stamp, .. } => {
                (key("requester", id), DigestEntry { stamp: stamp.clone(), wraps: BTreeSet::new() })
            }
            Record::Item { id, stamp, wraps, .. } => (
                key("item", id),
                DigestEntry { stamp: stamp.clone(), wraps: wraps.iter().map(|(r, _)| r.clone()).collect() },
            ),
        }
    }

    pub fn digest(&self) -> Result<Digest> {
        Ok(self.records()?.iter().map(Self::digest_of).collect())
    }

    /// The records a peer with this digest lacks or holds an older copy of.
    pub fn newer_than(&self, theirs: &Digest) -> Result<Vec<Record>> {
        Ok(self
            .records()?
            .into_iter()
            .filter(|record| {
                let (key, mine) = Self::digest_of(record);
                match theirs.get(&key) {
                    None => true,
                    Some(entry) if entry.stamp < mine.stamp => true,
                    Some(entry) => entry.stamp == mine.stamp && !mine.wraps.is_subset(&entry.wraps),
                }
            })
            .collect())
    }

    /// Merges records from another device. Returns how many changed
    /// something here. A record that fails authentication aborts the merge.
    pub fn apply(&self, records: &[Record]) -> Result<usize> {
        let mut conn = self.conn();
        let tx = conn.transaction()?;
        let mut changed = 0;
        for record in records {
            let stamp = match record {
                Record::Member { stamp, .. } | Record::Item { stamp, .. } | Record::Requester { stamp, .. } => stamp,
            };
            self.observe(&tx, stamp.version)?;
            let local = |table: &str, id: &str| -> Result<Option<Stamp>> {
                Ok(tx
                    .query_row(&format!("SELECT version, author FROM {table} WHERE id = ?1"), [id], |r| {
                        Ok(Stamp { version: r.get(0)?, author: r.get(1)? })
                    })
                    .optional()?)
            };
            match record {
                Record::Member { id, stamp, wrapped_vk, sealed } => {
                    let sealed = unhex(sealed)?;
                    let plain = crypto::open(&self.vk, &member_aad(id), &sealed)?;
                    let device: DeviceRecord = serde_json::from_slice(&plain)?;
                    if device_id(&crypto::normalize_public(&unhex(&device.device_pub)?)?) != *id {
                        return Err(Error::Crypto);
                    }
                    if local("members", id)?.is_some_and(|mine| mine >= *stamp) {
                        continue;
                    }
                    // This device's own wrapped key is never taken from a peer.
                    let wrapped_vk = if *id == self.device_id {
                        tx.query_row("SELECT wrapped_vk FROM members WHERE id = ?1", [id], |r| r.get(0))?
                    } else {
                        unhex(wrapped_vk)?
                    };
                    tx.execute(
                        "INSERT OR REPLACE INTO members (id, wrapped_vk, sealed, version, author)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id, wrapped_vk, sealed, stamp.version, stamp.author],
                    )?;
                    if device.removed {
                        tx.execute("DELETE FROM wraps WHERE recipient = ?1", [id])?;
                    }
                    changed += 1;
                }
                Record::Requester { id, stamp, sealed } => {
                    let sealed = unhex(sealed)?;
                    crypto::open(&self.vk, &requester_aad(id), &sealed)?;
                    if local("requesters", id)?.is_some_and(|mine| mine >= *stamp) {
                        continue;
                    }
                    tx.execute(
                        "INSERT OR REPLACE INTO requesters (id, sealed, version, author) VALUES (?1, ?2, ?3, ?4)",
                        params![id, sealed, stamp.version, stamp.author],
                    )?;
                    changed += 1;
                }
                Record::Item { id, stamp, deleted, meta, payload, wraps } => {
                    let meta = unhex(meta)?;
                    self.open_meta(id, stamp.version, &meta)?;
                    let payload = payload.as_deref().map(unhex).transpose()?;
                    let wraps: Vec<(&String, Vec<u8>)> =
                        wraps.iter().map(|(r, w)| Ok((r, unhex(w)?))).collect::<Result<_>>()?;
                    match local("items", id)? {
                        Some(mine) if mine == *stamp => {
                            // Same version: the peer may hold wraps made for
                            // a device that joined after this copy was made.
                            for (recipient, wrapped) in &wraps {
                                changed += tx.execute(
                                    "INSERT OR IGNORE INTO wraps (item_id, recipient, wrapped) VALUES (?1, ?2, ?3)",
                                    params![id, recipient, wrapped],
                                )?;
                            }
                        }
                        Some(mine) if mine > *stamp => {
                            // The incoming copy lost; keep it in history.
                            let wraps: Vec<(&String, String)> =
                                wraps.iter().map(|(r, w)| (*r, hex::encode(w))).collect();
                            tx.execute(
                                "INSERT OR IGNORE INTO history (item_id, version, author, deleted, meta, payload, wraps)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                                params![id, stamp.version, stamp.author, deleted, meta, payload, serde_json::to_string(&wraps)?],
                            )?;
                        }
                        mine => {
                            if mine.is_some() {
                                Self::archive(&tx, id)?;
                            }
                            tx.execute("DELETE FROM wraps WHERE item_id = ?1", [id])?;
                            tx.execute(
                                "INSERT OR REPLACE INTO items (id, version, author, deleted, meta, payload)
                                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                params![id, stamp.version, stamp.author, deleted, meta, payload],
                            )?;
                            for (recipient, wrapped) in &wraps {
                                tx.execute(
                                    "INSERT INTO wraps (item_id, recipient, wrapped) VALUES (?1, ?2, ?3)",
                                    params![id, recipient, wrapped],
                                )?;
                            }
                            changed += 1;
                        }
                    }
                }
            }
        }
        tx.commit()?;
        Ok(changed)
    }
}

fn expect<R: Read>(reader: &mut R) -> Result<DeviceMsg> {
    match read_frame::<_, DeviceMsg>(reader)? {
        Some(DeviceMsg::Error { message }) => Err(Error::Vault(message)),
        Some(msg) => Ok(msg),
        None => Err(Error::Vault("the other device closed the connection".into())),
    }
}

/// Runs a sync as the calling side. Returns how many records changed here.
pub fn sync_as_caller<R: Read, W: Write>(vault: &Vault, reader: &mut R, writer: &mut W) -> Result<usize> {
    write_frame(writer, &DeviceMsg::Digest { entries: vault.digest()? })?;
    let DeviceMsg::Reply { entries, records } = expect(reader)? else {
        return Err(Error::Vault("unexpected reply while syncing".into()));
    };
    let changed = vault.apply(&records)?;
    write_frame(writer, &DeviceMsg::Records { records: vault.newer_than(&entries)? })?;
    match expect(reader)? {
        DeviceMsg::Done => Ok(changed),
        _ => Err(Error::Vault("unexpected reply while syncing".into())),
    }
}

/// Answers a sync started by another device with `theirs`. Returns how many
/// records changed here.
pub fn sync_as_callee<R: Read, W: Write>(
    vault: &Vault,
    theirs: &Digest,
    reader: &mut R,
    writer: &mut W,
) -> Result<usize> {
    // Taken before replying, so it describes what the caller is compared with.
    let entries = vault.digest()?;
    write_frame(writer, &DeviceMsg::Reply { entries, records: vault.newer_than(theirs)? })?;
    let DeviceMsg::Records { records } = expect(reader)? else {
        return Err(Error::Vault("unexpected message while syncing".into()));
    };
    let changed = vault.apply(&records)?;
    write_frame(writer, &DeviceMsg::Done)?;
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{HardwareKeys, SoftwareKeys};
    use crate::model::{Kind, Level, NewItem};
    use crate::vault::NewDevice;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    fn item(name: &str, level: Level, value: &str) -> NewItem {
        NewItem {
            name: name.into(),
            level,
            values: [("value".to_string(), Zeroizing::new(value.to_string()))].into_iter().collect(),
            allow: vec![],
            max_grant_secs: 600,
            kind: Kind::Secret,
            sites: vec![],
        }
    }

    struct Pair {
        mac: Vault,
        phone: Vault,
        mac_checks: Arc<AtomicUsize>,
        _dir: tempfile::TempDir,
    }

    /// A Mac vault with `before` already in it, and a phone enrolled into it.
    fn pair(before: &[(&str, Level)]) -> Pair {
        let dir = tempfile::tempdir().unwrap();
        let mac_checks = Arc::new(AtomicUsize::new(0));
        let counter = mac_checks.clone();
        let mac_keys = SoftwareKeys::generate(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            true
        });
        let mac = Vault::create(&dir.path().join("mac.db"), Arc::new(mac_keys), "mac").unwrap();
        for (name, level) in before {
            mac.put(item(name, *level, &format!("{name}-value"))).unwrap();
        }
        let phone_keys = Arc::new(SoftwareKeys::generate(|_| true));
        let (noise_private, noise_public) = mayi_proto::noise::generate_keypair().unwrap();
        let bootstrap = mac
            .enrol_device(
                NewDevice {
                    name: "phone".into(),
                    device_pub: phone_keys.device_public(),
                    biometric_pub: phone_keys.biometric_public(),
                    noise_public: Some(noise_public),
                },
                "add phone",
            )
            .unwrap();
        let phone = Vault::join(
            &dir.path().join("phone.db"),
            phone_keys,
            "phone",
            &bootstrap,
            (&noise_private, &noise_public),
        )
        .unwrap();
        Pair { mac, phone, mac_checks, _dir: dir }
    }

    /// One full exchange, as the protocol does it but without a connection.
    fn sync(a: &Vault, b: &Vault) -> (usize, usize) {
        let (da, db) = (a.digest().unwrap(), b.digest().unwrap());
        let to_a = b.newer_than(&da).unwrap();
        let to_b = a.newer_than(&db).unwrap();
        (a.apply(&to_a).unwrap(), b.apply(&to_b).unwrap())
    }

    fn value(vault: &Vault, name: &str) -> String {
        let meta = vault.meta(name).unwrap();
        vault.reveal(&[&meta], "p").unwrap()[0].get("value").unwrap().to_string()
    }

    #[test]
    fn a_new_device_receives_everything() {
        let p = pair(&[("L1", Level::Log), ("L4", Level::Biometric)]);
        assert_eq!(p.mac_checks.load(Ordering::SeqCst), 1, "sharing level 4 keys needs one check");
        assert!(p.phone.list().unwrap().is_empty(), "empty until the first sync");
        p.mac.add_requester("build-vm", [3u8; 32]).unwrap();

        sync(&p.mac, &p.phone);
        assert_eq!(value(&p.phone, "L1"), "L1-value");
        assert_eq!(value(&p.phone, "L4"), "L4-value", "the phone's own biometric key opens it");
        assert_eq!(p.phone.devices().unwrap().len(), 2);
        assert_eq!(p.phone.device_name().unwrap(), "phone");
        assert!(p.phone.requester_by_key(&[3u8; 32]).unwrap().is_some());
        assert_eq!(sync(&p.mac, &p.phone), (0, 0), "nothing left to exchange");
        assert_eq!(p.mac.digest().unwrap(), p.phone.digest().unwrap());
    }

    #[test]
    fn enrolling_without_level_4_secrets_asks_nothing() {
        let p = pair(&[("L1", Level::Log)]);
        assert_eq!(p.mac_checks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn changes_flow_both_ways_and_the_later_one_wins() {
        let p = pair(&[("TOKEN", Level::Log)]);
        sync(&p.mac, &p.phone);

        p.phone.put(item("FROM_PHONE", Level::Biometric, "p")).unwrap();
        p.mac.put(item("TOKEN", Level::Log, "mac-edit")).unwrap();
        // Edits are ordered by the millisecond: make this one later.
        std::thread::sleep(std::time::Duration::from_millis(3));
        p.phone.put(item("TOKEN", Level::Log, "phone-edit")).unwrap();
        sync(&p.mac, &p.phone);

        assert_eq!(value(&p.mac, "TOKEN"), "phone-edit", "the later edit wins on both");
        assert_eq!(value(&p.phone, "TOKEN"), "phone-edit");
        // A level 4 secret written on the phone is readable on the Mac.
        assert_eq!(value(&p.mac, "FROM_PHONE"), "p");
        let lost: i64 = p
            .mac
            .conn()
            .query_row("SELECT COUNT(*) FROM history WHERE author = ?1", [p.mac.device_id()], |r| r.get(0))
            .unwrap();
        assert!(lost >= 1, "the losing edit is kept in history");

        p.mac.remove("TOKEN").unwrap();
        sync(&p.mac, &p.phone);
        assert!(p.phone.meta("TOKEN").is_err(), "deletions propagate");
        assert_eq!(p.mac.digest().unwrap(), p.phone.digest().unwrap());
    }

    #[test]
    fn same_name_created_on_both_resolves_the_same_way() {
        let p = pair(&[]);
        sync(&p.mac, &p.phone);
        p.mac.put(item("DUP", Level::Log, "from-mac")).unwrap();
        // Versions are milliseconds: within the same one, either could win.
        std::thread::sleep(std::time::Duration::from_millis(3));
        p.phone.put(item("DUP", Level::Log, "from-phone")).unwrap();
        sync(&p.mac, &p.phone);
        assert_eq!(p.mac.list().unwrap().len(), 1);
        assert_eq!(value(&p.mac, "DUP"), value(&p.phone, "DUP"));
        assert_eq!(value(&p.mac, "DUP"), "from-phone");
    }

    #[test]
    fn revocations_and_device_info_sync() {
        let p = pair(&[]);
        let machine = p.mac.add_requester("vm", [4u8; 32]).unwrap();
        sync(&p.mac, &p.phone);
        p.phone.revoke_requester(&machine.id).unwrap();
        p.phone.set_info(7462, vec!["10.0.0.9".into()]).unwrap();
        sync(&p.mac, &p.phone);
        assert!(p.mac.requester_by_key(&[4u8; 32]).unwrap().is_none());
        let phone = p.mac.devices().unwrap().into_iter().find(|d| d.name == "phone").unwrap();
        assert_eq!(phone.addresses, ["10.0.0.9"]);
        let (_, phone_noise) = p.phone.noise_keypair().unwrap();
        assert_eq!(p.mac.device_by_noise_key(&phone_noise).unwrap().unwrap().id, phone.id);
    }

    #[test]
    fn a_removed_device_gets_no_new_level_4_secrets() {
        let p = pair(&[]);
        sync(&p.mac, &p.phone);
        assert!(p.mac.remove_device(p.phone.device_id()).unwrap().is_some());
        let (_, phone_noise) = p.phone.noise_keypair().unwrap();
        assert!(p.mac.device_by_noise_key(&phone_noise).unwrap().is_none());
        let meta = p.mac.put(item("AFTER", Level::Biometric, "x")).unwrap();
        let recipients: i64 = p
            .mac
            .conn()
            .query_row("SELECT COUNT(*) FROM wraps WHERE item_id = ?1", [&meta.id], |r| r.get(0))
            .unwrap();
        assert_eq!(recipients, 1);
    }

    #[test]
    fn records_from_another_vault_are_rejected() {
        let p = pair(&[]);
        let dir = tempfile::tempdir().unwrap();
        let other =
            Vault::create(&dir.path().join("o.db"), Arc::new(SoftwareKeys::generate(|_| true)), "other").unwrap();
        other.put(item("EVIL", Level::Log, "x")).unwrap();
        other.add_requester("intruder", [9u8; 32]).unwrap();
        for record in other.newer_than(&Digest::new()).unwrap() {
            assert!(p.mac.apply(&[record]).is_err());
        }
        assert!(p.mac.list().unwrap().is_empty());
        assert!(p.mac.requesters().unwrap().is_empty());
        assert_eq!(p.mac.devices().unwrap().len(), 2);
    }

    #[test]
    fn the_protocol_messages_do_a_full_sync() {
        let p = pair(&[("A", Level::Log)]);
        p.phone.put(item("B", Level::Log, "b")).unwrap();
        // Caller: phone. Each side's output is the other's input.
        let mut to_mac = Vec::new();
        write_frame(&mut to_mac, &DeviceMsg::Digest { entries: p.phone.digest().unwrap() }).unwrap();
        let Some(DeviceMsg::Digest { entries }) = read_frame(&mut to_mac.as_slice()).unwrap() else { panic!() };
        let mut to_phone = Vec::new();
        // The callee cannot finish until the caller's records arrive, so the
        // caller's half is prepared from the callee's first frame.
        let reply_entries = p.mac.digest().unwrap();
        write_frame(&mut to_phone, &DeviceMsg::Reply { entries: reply_entries, records: p.mac.newer_than(&entries).unwrap() }).unwrap();
        write_frame(&mut to_phone, &DeviceMsg::Done).unwrap();
        let mut from_phone = Vec::new();
        assert!(sync_as_caller(&p.phone, &mut to_phone.as_slice(), &mut from_phone).unwrap() >= 1);
        // Skip the caller's digest (already consumed above) and feed the rest.
        let mut rest = from_phone.as_slice();
        let _: Option<DeviceMsg> = read_frame(&mut rest).unwrap();
        let mut sink = Vec::new();
        assert!(sync_as_callee(&p.mac, &entries, &mut rest, &mut sink).unwrap() >= 1);
        assert_eq!(p.mac.digest().unwrap(), p.phone.digest().unwrap());
        assert_eq!(value(&p.mac, "B"), "b");
    }
}
