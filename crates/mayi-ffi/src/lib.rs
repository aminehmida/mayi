//! The vault device API exposed to the Swift and Kotlin apps through UniFFI.
//!
//! The apps supply the platform parts (hardware keys, user interface) as
//! foreign implementations of [`KeyStore`] and [`UiDelegate`]; everything
//! else runs in the Rust core.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use mayi_core::broker::{Approval, Broker, Notice, Prompt, Requester, Ui};
use mayi_core::crypto::Key;
use mayi_core::grants::GrantScope;
use mayi_core::hardware::HardwareKeys;
use mayi_core::model::{Destination, ItemMeta, Level, NewItem};
use mayi_core::policy::{command_line, Rules};
use mayi_core::server::{JoinCode, Server};
use mayi_core::vault::Vault;
use mayi_proto::RunRequest;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum KeyError {
    /// The biometric check failed or the user cancelled it.
    #[error("biometric check failed or was cancelled")]
    Denied,
    #[error("{detail}")]
    Failed { detail: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeyError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        KeyError::Failed { detail: e.reason }
    }
}

/// The device's two hardware-held P-256 keys. Public keys are uncompressed
/// SEC1 (65 bytes); ECDH results are the raw 32-byte shared secret.
#[uniffi::export(with_foreign)]
pub trait KeyStore: Send + Sync {
    fn device_public(&self) -> Vec<u8>;
    fn biometric_public(&self) -> Vec<u8>;
    fn device_ecdh(&self, peer_public: Vec<u8>) -> Result<Vec<u8>, KeyError>;
    /// One biometric check, showing `prompt`, covers every peer.
    fn biometric_ecdh(
        &self,
        peer_publics: Vec<Vec<u8>>,
        prompt: String,
    ) -> Result<Vec<Vec<u8>>, KeyError>;
}

struct KeyAdapter(Arc<dyn KeyStore>);

fn to_key(bytes: Vec<u8>) -> mayi_core::Result<Key> {
    let bytes = Zeroizing::new(bytes);
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| mayi_core::Error::Hardware("ECDH result is not 32 bytes".into()))?;
    Ok(Zeroizing::new(array))
}

impl From<KeyError> for mayi_core::Error {
    fn from(e: KeyError) -> Self {
        match e {
            KeyError::Denied => mayi_core::Error::BiometricDenied,
            KeyError::Failed { detail } => mayi_core::Error::Hardware(detail),
        }
    }
}

impl HardwareKeys for KeyAdapter {
    fn device_public(&self) -> Vec<u8> {
        self.0.device_public()
    }

    fn biometric_public(&self) -> Vec<u8> {
        self.0.biometric_public()
    }

    fn device_ecdh(&self, peer_public: &[u8]) -> mayi_core::Result<Key> {
        to_key(self.0.device_ecdh(peer_public.to_vec())?)
    }

    fn biometric_ecdh(&self, peer_publics: &[&[u8]], prompt: &str) -> mayi_core::Result<Vec<Key>> {
        let peers = peer_publics.iter().map(|p| p.to_vec()).collect();
        self.0
            .biometric_ecdh(peers, prompt.to_string())?
            .into_iter()
            .map(to_key)
            .collect()
    }
}

/// A request as shown to the user. Everything except `command`, `requester`
/// and `remote` is written by the requesting side and may be untrue.
#[derive(Clone, uniffi::Record)]
pub struct RequestInfo {
    /// The command line, shell-quoted so argument boundaries are visible.
    /// Empty for a sign-in.
    pub command: String,
    /// For a sign-in: the origin of the page the login is to be typed into,
    /// as the requester's browser reported it. It replaces the command.
    pub site: Option<String>,
    /// For a sign-in: the fields to be typed, among `username`, `password`
    /// and `totp` (the two-factor code).
    pub fields: Vec<String>,
    pub cwd: String,
    pub reason: String,
    pub agent: String,
    pub session: String,
    pub host: String,
    /// The machine the request came from, as established by the transport.
    pub requester: String,
    pub remote: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct PromptSecret {
    pub name: String,
    pub level: u8,
    pub needs_approval: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct PromptInfo {
    pub run_id: u64,
    pub request: RequestInfo,
    pub secrets: Vec<PromptSecret>,
}

#[derive(Clone, uniffi::Record)]
pub struct NoticeInfo {
    pub run_id: u64,
    pub request: RequestInfo,
    pub secrets: Vec<String>,
}

#[derive(Clone, Copy, uniffi::Enum)]
pub enum ApprovalChoice {
    Deny,
    Once,
    /// The same command again in this session.
    SessionCommand,
    /// Any command in this session.
    SessionAny,
}

/// The app's user interface. Methods are called on background threads.
#[uniffi::export(with_foreign)]
pub trait UiDelegate: Send + Sync {
    /// Blocks until the user answers, or until `withdraw` is called for the
    /// same run, in which case it should return `Deny`.
    fn approve(&self, prompt: PromptInfo) -> ApprovalChoice;
    /// The requester went away: take the prompt for `run_id` down.
    fn withdraw(&self, run_id: u64);
    /// Secrets were released without asking; offer a Stop for `run_id`.
    fn notify(&self, notice: NoticeInfo);
    /// The command of a released run ended.
    fn finished(&self, run_id: u64, exit_code: Option<i32>);
    /// A machine finished pairing and may now send requests.
    fn paired(&self, name: String, id: String);
    /// Another device joined the vault.
    fn device_added(&self, name: String);
    /// A sync with another device changed records here: refresh what is shown.
    fn synced(&self, changed: u64);
    /// Whether the owner is using this device right now (unlocked, recent
    /// input). Requesters ask the device in use first.
    fn user_active(&self) -> bool;
    /// Another machine just connected: a phone stays awake for a moment so
    /// its request can arrive.
    fn incoming(&self);
}

struct UiAdapter(Arc<dyn UiDelegate>);

fn request_info(request: &RunRequest, requester: &Requester) -> RequestInfo {
    RequestInfo {
        command: command_line(&request.shown_argv()),
        site: request.site.clone(),
        fields: if request.site.is_some() {
            request.bindings.iter().map(|b| b.field.clone()).collect()
        } else {
            vec![]
        },
        cwd: request.cwd.clone(),
        reason: request.reason.clone(),
        agent: request.agent.clone(),
        session: request.session.clone(),
        host: request.host.clone(),
        requester: requester.id.clone(),
        remote: requester.remote,
    }
}

impl Ui for UiAdapter {
    fn approve(&self, prompt: &Prompt) -> Approval {
        let info = PromptInfo {
            run_id: prompt.run_id,
            request: request_info(prompt.request, prompt.requester),
            secrets: prompt
                .secrets
                .iter()
                .map(|s| PromptSecret {
                    name: s.name.clone(),
                    level: s.level as u8,
                    needs_approval: s.needs_approval,
                })
                .collect(),
        };
        match self.0.approve(info) {
            ApprovalChoice::Deny => Approval::Deny,
            ApprovalChoice::Once => Approval::Allow(GrantScope::Once),
            ApprovalChoice::SessionCommand => Approval::Allow(GrantScope::SessionCommand),
            ApprovalChoice::SessionAny => Approval::Allow(GrantScope::SessionAny),
        }
    }

    fn notify(&self, notice: &Notice) {
        self.0.notify(NoticeInfo {
            run_id: notice.run_id,
            request: request_info(notice.request, notice.requester),
            secrets: notice.secrets.clone(),
        });
    }

    fn withdraw(&self, run_id: u64) {
        self.0.withdraw(run_id);
    }

    fn finished(&self, run_id: u64, exit: Option<i32>) {
        self.0.finished(run_id, exit);
    }

    fn paired(&self, name: &str, id: &str) {
        self.0.paired(name.to_string(), id.to_string());
    }

    fn device_added(&self, name: &str) {
        self.0.device_added(name.to_string());
    }

    fn synced(&self, changed: usize) {
        self.0.synced(changed as u64);
    }

    fn user_active(&self) -> bool {
        self.0.user_active()
    }

    fn incoming(&self) {
        self.0.incoming();
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MayiError {
    #[error("{detail}")]
    Failed { detail: String },
}

/// Writing to a connection the other side closed (a `mayi` that went away
/// before its answer, a phone that dropped off) must fail the write, not end
/// the app: a Rust program ignores SIGPIPE, an app hosting this library does
/// not.
fn no_sigpipe() {
    // SAFETY: sets the disposition of one signal; no handler runs.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
}

impl From<mayi_core::Error> for MayiError {
    fn from(e: mayi_core::Error) -> Self {
        MayiError::Failed { detail: e.to_string() }
    }
}

impl From<std::io::Error> for MayiError {
    fn from(e: std::io::Error) -> Self {
        MayiError::Failed { detail: e.to_string() }
    }
}

/// A secret without its values.
#[derive(Clone, uniffi::Record)]
pub struct SecretRecord {
    pub name: String,
    pub level: u8,
    pub fields: Vec<String>,
    pub allow: Vec<String>,
    pub max_grant_secs: u64,
    pub version: u64,
    /// A website login: typed only into one of `sites`, never given to a command.
    pub login: bool,
    pub sites: Vec<String>,
    /// How many devices hold its current version, as far as this one knows.
    /// With 1, it is lost if this device is.
    pub copies: u32,
    /// The folder it is kept in, if any.
    pub folder: Option<String>,
    /// Who may still know the value: replace it at its source, or dismiss.
    pub rotate: Vec<RotateNoteRecord>,
}

/// A machine revoked or a device removed that may still know a secret.
#[derive(Clone, uniffi::Record)]
pub struct RotateNoteRecord {
    pub who: String,
    /// `revoked` (a machine) or `removed` (a device).
    pub why: String,
    pub at_ms: u64,
}

/// One field of a secret, decrypted to show its owner.
#[derive(Clone, uniffi::Record)]
pub struct RevealedField {
    pub name: String,
    pub value: String,
}

/// A secret's values, to show its owner in the app. A login's `totp` field
/// is its two-factor key: show the code [`two_factor_code`] gives instead.
#[derive(Clone, uniffi::Record)]
pub struct RevealedSecret {
    pub fields: Vec<RevealedField>,
}

/// A two-factor code and how many more seconds it is valid.
#[derive(Clone, uniffi::Record)]
pub struct TwoFactorCode {
    pub code: String,
    pub valid_secs: u64,
}

/// The code a two-factor key (or `otpauth://` link) gives now, so the apps
/// can show the code rather than the key, and keep it current without
/// decrypting again. Fails if the key is not one.
#[uniffi::export]
pub fn two_factor_code(key: String) -> Result<TwoFactorCode, MayiError> {
    let totp = mayi_core::totp::Totp::parse(&key).map_err(|detail| MayiError::Failed { detail })?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(TwoFactorCode { code: totp.code(now).to_string(), valid_secs: totp.valid_for(now) })
}

impl From<ItemMeta> for SecretRecord {
    fn from(m: ItemMeta) -> Self {
        Self {
            name: m.name,
            level: m.level as u8,
            fields: m.fields,
            allow: m.allow,
            max_grant_secs: m.max_grant_secs,
            version: m.version,
            login: m.destination == Destination::Website,
            sites: m.sites,
            // Only on this device until the next sync.
            copies: 1,
            folder: m.folder,
            rotate: m
                .rotate
                .into_iter()
                .map(|n| RotateNoteRecord { who: n.who, why: n.why, at_ms: n.at_ms })
                .collect(),
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct AuditSecret {
    pub name: String,
    pub level: u8,
    pub via: String,
}

#[derive(Clone, uniffi::Record)]
pub struct AuditRecord {
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
    pub command: String,
    /// For a sign-in: the page's origin, in place of the command.
    pub site: String,
    pub reason: String,
    pub secrets: Vec<AuditSecret>,
    /// The device that decided, when another device of the vault did.
    pub device: Option<String>,
}

/// A machine paired to send requests over the network.
#[derive(Clone, uniffi::Record)]
pub struct MachineRecord {
    pub id: String,
    pub name: String,
    pub added_ms: u64,
    pub revoked: bool,
    /// For the machine a vault device runs on, which enrolled itself through
    /// that device: the device's name.
    pub runs_device: Option<String>,
}

/// A device holding the vault.
#[derive(Clone, uniffi::Record)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub addresses: Vec<String>,
    pub port: u16,
    pub removed: bool,
    pub this_device: bool,
    /// The offline recovery key rather than a device.
    pub recovery: bool,
}

/// The outcome of syncing with one device.
#[derive(Clone, uniffi::Record)]
pub struct SyncResult {
    pub device: String,
    /// Records updated here, when the device was reached.
    pub changed: Option<u64>,
    /// Why it was not reached, otherwise.
    pub error: Option<String>,
}

/// Redeems an enrolment token from another device: creates this device's
/// copy of the vault at `vault_path` and fills it with a first sync. The
/// other device may ask its owner for a fingerprint before answering. Open
/// the vault with `VaultDevice.open` afterwards.
#[uniffi::export]
pub fn join_vault(
    vault_path: String,
    device_name: String,
    keys: Arc<dyn KeyStore>,
    token: String,
) -> Result<(), MayiError> {
    no_sigpipe();
    let keys: Arc<dyn HardwareKeys> = Arc::new(KeyAdapter(keys));
    mayi_core::server::join_vault(Path::new(&vault_path), keys, &device_name, &token)?;
    Ok(())
}

/// Restores this device's access to the vault file at `vault_path` with the
/// recovery key, after its keys were lost or replaced, or on a new device
/// given a copy of the file. Open the vault with `VaultDevice.open` afterwards.
#[uniffi::export]
pub fn recover_vault(
    vault_path: String,
    device_name: String,
    keys: Arc<dyn KeyStore>,
    recovery_key: String,
) -> Result<(), MayiError> {
    let keys: Arc<dyn HardwareKeys> = Arc::new(KeyAdapter(keys));
    Vault::recover(Path::new(&vault_path), keys, &device_name, &recovery_key)?;
    Ok(())
}

/// A code this device shows while it has no vault, so that a device that
/// holds one can add it: the phone scans the code a new Mac shows, or a Mac
/// pastes the code a new phone or Mac shows (`VaultDevice.add_device_by_code`).
#[derive(uniffi::Object)]
pub struct JoinInvitation {
    code: JoinCode,
    cancelled: AtomicBool,
}

#[uniffi::export]
impl JoinInvitation {
    /// Starts listening for the other device and makes the code, valid for
    /// `ttl_secs`. `addresses` are where the other device should look for
    /// this one; empty means this device's own network addresses.
    #[uniffi::constructor]
    pub fn open(addresses: Vec<String>, ttl_secs: u64) -> Result<Arc<Self>, MayiError> {
        no_sigpipe();
        Ok(Arc::new(Self { code: JoinCode::open(addresses, 0, ttl_secs)?, cancelled: AtomicBool::new(false) }))
    }

    /// The code to show, as a QR code and as text.
    pub fn token(&self) -> String {
        self.code.token()
    }

    /// Blocks until a device with a vault adds this one, the code expires
    /// ("the code expired"), or `cancel` is called ("cancelled"). On success
    /// the vault is at `vault_path`, filled by a first sync: open it with
    /// `VaultDevice.open`.
    pub fn wait(&self, vault_path: String, device_name: String, keys: Arc<dyn KeyStore>) -> Result<(), MayiError> {
        let keys: Arc<dyn HardwareKeys> = Arc::new(KeyAdapter(keys));
        self.code.wait(Path::new(&vault_path), keys, &device_name, &self.cancelled)?;
        Ok(())
    }

    /// Makes a `wait` in progress return.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

#[derive(uniffi::Object)]
pub struct VaultDevice {
    server: Arc<Server>,
    /// The TCP port paired machines connect to, once listening.
    remote_port: Mutex<Option<u16>>,
    /// The addresses given to `serve_remote`; empty means this device's own.
    advertised: Mutex<Vec<String>>,
}

#[uniffi::export]
impl VaultDevice {
    /// Opens the vault at `vault_path`, creating it on first run with this
    /// device as its only member.
    #[uniffi::constructor]
    pub fn open(
        vault_path: String,
        device_name: String,
        keys: Arc<dyn KeyStore>,
        ui: Arc<dyn UiDelegate>,
    ) -> Result<Arc<Self>, MayiError> {
        no_sigpipe();
        let path = Path::new(&vault_path);
        let keys: Arc<dyn HardwareKeys> = Arc::new(KeyAdapter(keys));
        let vault = if path.exists() {
            Vault::open(path, keys)?
        } else {
            Vault::create(path, keys, &device_name)?
        };
        let broker = Broker::new(vault, Arc::new(UiAdapter(ui)), Rules::default());
        Ok(Arc::new(Self {
            server: Server::new(broker),
            remote_port: Mutex::new(None),
            advertised: Mutex::new(Vec::new()),
        }))
    }

    /// Starts serving requesters on a unix socket. Returns once the socket
    /// is bound; requests are handled on background threads.
    pub fn serve(&self, socket_path: String) -> Result<(), MayiError> {
        let listener = Server::bind(Path::new(&socket_path))?;
        let server = self.server.clone();
        thread::spawn(move || server.serve(listener));
        Ok(())
    }

    /// Starts accepting paired machines and other devices on a TCP port (0
    /// picks a free one) and returns the port in use. Publishes `addresses`
    /// (empty means this device's own network addresses) to the rest of the
    /// vault. Calling it again only republishes.
    pub fn serve_remote(&self, port: u16, addresses: Vec<String>) -> Result<u16, MayiError> {
        let mut current = self.remote_port.lock().unwrap_or_else(|e| e.into_inner());
        let port = match *current {
            Some(port) => port,
            None => {
                let listener = std::net::TcpListener::bind(("0.0.0.0", port))?;
                let port = listener.local_addr()?.port();
                let server = self.server.clone();
                thread::spawn(move || server.serve_tcp(listener));
                *current = Some(port);
                port
            }
        };
        drop(current);
        *self.advertised.lock().unwrap_or_else(|e| e.into_inner()) = addresses;
        self.republish()?;
        Ok(port)
    }

    /// Publishes where this device can be reached again, after a network
    /// change: a new Wi-Fi, a VPN coming up. Returns whether the addresses
    /// changed, in which case the other devices should be told by a sync.
    /// Does nothing before `serve_remote`.
    pub fn republish(&self) -> Result<bool, MayiError> {
        let Some(port) = *self.remote_port.lock().unwrap_or_else(|e| e.into_inner()) else { return Ok(false) };
        let given = self.advertised.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let addresses = if given.is_empty() { mayi_core::server::local_addresses() } else { given };
        Ok(self.server.announce(port, addresses)?)
    }

    /// Opens an invitation for a new vault device and returns the token to
    /// enter on it: one use, valid for `ttl_secs`. The new device receives
    /// the whole vault. Call `serve_remote` first.
    pub fn start_enrolment(&self, addresses: Vec<String>, ttl_secs: u64) -> Result<String, MayiError> {
        let port = self
            .remote_port
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ok_or_else(|| MayiError::Failed { detail: "not accepting other devices yet".into() })?;
        let addresses =
            if addresses.is_empty() { mayi_core::server::local_addresses() } else { addresses };
        Ok(self.server.start_enrolment(addresses, port, ttl_secs)?)
    }

    /// Adds the device that shows `code` (its `JoinInvitation`): connects to
    /// it, admits it, which asks for a fingerprint if there are level 4
    /// secrets, and sends it the vault. Blocks until done; returns its name.
    pub fn add_device_by_code(&self, code: String) -> Result<String, MayiError> {
        Ok(self.server.add_device_by_code(&code)?)
    }

    /// Every device that ever held the vault, including removed ones.
    pub fn devices(&self) -> Result<Vec<DeviceInfo>, MayiError> {
        let vault = self.vault();
        Ok(vault
            .devices()?
            .into_iter()
            .map(|d| DeviceInfo {
                this_device: d.id == vault.device_id(),
                id: d.id,
                name: d.name,
                addresses: d.addresses,
                port: d.port,
                removed: d.removed,
                recovery: d.recovery,
            })
            .collect())
    }

    /// Removes a device from the vault. It keeps what it could already
    /// decrypt: returns the names of those secrets, which should be rotated.
    pub fn remove_device(&self, id: String) -> Result<Vec<String>, MayiError> {
        Ok(self.vault().remove_device(&id)?.unwrap_or_default())
    }

    /// Creates the offline recovery key and returns it. It is shown once and
    /// not stored. Needs a biometric check, showing `prompt`, if level 4
    /// secrets exist. Replaces any earlier recovery key.
    pub fn create_recovery_key(&self, prompt: String) -> Result<String, MayiError> {
        Ok(self.vault().create_recovery_key(&prompt)?)
    }

    /// Syncs with every other device that can be reached now. Blocks while
    /// it tries each one.
    pub fn sync_all(&self) -> Result<Vec<SyncResult>, MayiError> {
        Ok(self
            .server
            .sync_all()?
            .into_iter()
            .map(|(device, outcome)| match outcome {
                Ok(changed) => SyncResult { device, changed: Some(changed as u64), error: None },
                Err(error) => SyncResult { device, changed: None, error: Some(error) },
            })
            .collect())
    }

    /// Opens a pairing invitation and returns the token to paste on the
    /// other machine: one use, valid for `ttl_secs`. `addresses` are where
    /// that machine should look for this device; empty means this device's
    /// own network addresses. Call `serve_remote` first.
    pub fn start_pairing(&self, addresses: Vec<String>, ttl_secs: u64) -> Result<String, MayiError> {
        let port = self
            .remote_port
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ok_or_else(|| MayiError::Failed { detail: "not accepting other machines yet".into() })?;
        let addresses =
            if addresses.is_empty() { mayi_core::server::local_addresses() } else { addresses };
        Ok(self.server.start_pairing(addresses, port, ttl_secs)?)
    }

    pub fn cancel_pairing(&self) {
        self.server.cancel_pairing();
    }

    /// Every machine ever paired, including revoked ones.
    pub fn machines(&self) -> Result<Vec<MachineRecord>, MayiError> {
        let vault = self.vault();
        let devices = vault.devices()?;
        let device_name = |id: &str| devices.iter().find(|d| d.id == id).map(|d| d.name.clone());
        Ok(vault
            .requesters()?
            .into_iter()
            .map(|r| MachineRecord {
                runs_device: r.local_to.as_deref().and_then(device_name),
                id: r.id,
                name: r.name,
                added_ms: r.added_ms,
                revoked: r.revoked,
            })
            .collect())
    }

    /// Whether `mayi` on this machine may pair itself with the vault through
    /// the local socket, so agents here can also ask the other devices.
    /// Turning it off revokes the machine it paired.
    pub fn set_local_enrol(&self, allowed: bool) -> Result<(), MayiError> {
        Ok(self.server.set_local_enrol(allowed)?)
    }

    /// Stops accepting requests from a machine. Returns the names of the
    /// secrets this device released to it, to rotate if it is not trusted.
    pub fn revoke_machine(&self, id: String) -> Result<Vec<String>, MayiError> {
        Ok(self.vault().revoke_requester(&id)?.unwrap_or_default())
    }

    /// Kills the command of a released run and revokes its session's grants.
    pub fn stop(&self, run_id: u64) -> bool {
        self.server.stop(run_id)
    }

    pub fn list_secrets(&self) -> Result<Vec<SecretRecord>, MayiError> {
        let vault = self.vault();
        let copies = vault.copies()?;
        Ok(vault
            .list()?
            .into_iter()
            .map(|meta| {
                let count = copies.get(&meta.id).copied().unwrap_or(1);
                SecretRecord { copies: count, ..meta.into() }
            })
            .collect())
    }

    /// A secret's values, to show its owner. Confirm the owner is present
    /// first: this asks nothing for levels 1 to 3, and for level 4 only the
    /// biometric check that unlocks it, showing `prompt`. Logged as viewed.
    pub fn reveal_secret(&self, name: String, prompt: String) -> Result<RevealedSecret, MayiError> {
        let (meta, values) = self.vault().view(&name, &prompt)?;
        let fields = meta
            .fields
            .iter()
            .filter_map(|f| values.get(f).map(|v| RevealedField { name: f.clone(), value: v.to_string() }))
            .collect();
        Ok(RevealedSecret { fields })
    }

    /// Creates a secret or replaces the one with the same name. A login
    /// (`login` true) takes the fields `username`, `password` and `totp`
    /// (the two-factor setup key or `otpauth://` link) and at least one site.
    #[allow(clippy::too_many_arguments)]
    pub fn put_secret(
        &self,
        name: String,
        level: u8,
        values: HashMap<String, String>,
        allow: Vec<String>,
        max_grant_secs: u64,
        login: bool,
        sites: Vec<String>,
        folder: Option<String>,
    ) -> Result<SecretRecord, MayiError> {
        let level = Level::try_from(level).map_err(|detail| MayiError::Failed { detail })?;
        let values = values.into_iter().map(|(k, v)| (k, Zeroizing::new(v))).collect();
        let destination = if login { Destination::Website } else { Destination::Command };
        Ok(self
            .vault()
            .put(NewItem { name, level, values, allow, max_grant_secs, destination, sites, folder })?
            .into())
    }

    /// The owner decided a secret flagged for rotation needs none.
    pub fn dismiss_rotation(&self, name: String) -> Result<SecretRecord, MayiError> {
        Ok(self.vault().dismiss_rotation(&name)?.into())
    }

    /// Changes a secret's allowlist, grant cap, websites and folder, keeping its values.
    pub fn update_rules(
        &self,
        name: String,
        allow: Vec<String>,
        max_grant_secs: u64,
        sites: Vec<String>,
        folder: Option<String>,
    ) -> Result<SecretRecord, MayiError> {
        Ok(self.vault().update_rules(&name, allow, max_grant_secs, sites, folder)?.into())
    }

    pub fn remove_secret(&self, name: String) -> Result<(), MayiError> {
        Ok(self.vault().remove(&name)?)
    }

    /// The last `count` audit entries, oldest first.
    pub fn audit_tail(&self, count: u32) -> Result<Vec<AuditRecord>, MayiError> {
        let devices = self.vault().devices()?;
        let device_name = |id: &str| devices.iter().find(|d| d.id == id).map_or_else(|| id.to_string(), |d| d.name.clone());
        Ok(self
            .vault()
            .audit_tail(count as usize)?
            .into_iter()
            .map(|e| AuditRecord {
                device: (!e.device.is_empty()).then(|| device_name(&e.device)),
                ts_ms: e.ts_ms,
                run_id: e.run_id,
                event: e.event,
                outcome: e.outcome,
                requester: e.requester,
                remote: e.remote,
                agent: e.agent,
                session: e.session,
                host: e.host,
                cwd: e.cwd,
                command: command_line(&e.argv),
                site: e.site,
                reason: e.reason,
                secrets: e
                    .secrets
                    .into_iter()
                    .map(|s| AuditSecret { name: s.name, level: s.level, via: s.via })
                    .collect(),
            })
            .collect())
    }
}

impl VaultDevice {
    fn vault(&self) -> &Vault {
        self.server.broker().vault()
    }
}
