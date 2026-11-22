//! The two hardware-held keys of a vault device.
//!
//! Each app implements [`HardwareKeys`] on top of its platform key store
//! (Secure Enclave, Android Keystore). The private keys never reach this
//! crate: it only ever sees ECDH results.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::crypto::{key_from_slice, Key};
use crate::{Error, Result};

pub trait HardwareKeys: Send + Sync {
    /// Key guarding the vault key. Usable whenever the device is unlocked.
    fn device_public(&self) -> Vec<u8>;

    /// Key guarding level 4 secrets. Every use requires a biometric check.
    fn biometric_public(&self) -> Vec<u8>;

    fn device_ecdh(&self, peer_public: &[u8]) -> Result<Key>;

    /// Runs ECDH with the biometric key against each peer after a single
    /// biometric check that shows `prompt`. Returns
    /// [`Error::BiometricDenied`] if the check fails or is cancelled.
    fn biometric_ecdh(&self, peer_publics: &[&[u8]], prompt: &str) -> Result<Vec<Key>>;

    /// Takes down a biometric check in progress (another device answered,
    /// or the requester gave up): [`HardwareKeys::biometric_ecdh`] then
    /// returns [`Error::BiometricDenied`].
    fn cancel_biometric(&self) {}
}

/// Keys held in process memory, with a callback standing in for the
/// biometric check. For tests and the development daemon only: it gives none
/// of the hardware guarantees.
pub struct SoftwareKeys {
    device: SecretKey,
    biometric: SecretKey,
    confirm: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl SoftwareKeys {
    pub fn generate(confirm: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        Self {
            device: SecretKey::random(&mut OsRng),
            biometric: SecretKey::random(&mut OsRng),
            confirm: Box::new(confirm),
        }
    }

    /// One key in both roles: the offline recovery key, which stands in
    /// for a device when restoring a vault.
    pub fn single(confirm: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        let key = SecretKey::random(&mut OsRng);
        Self { device: key.clone(), biometric: key, confirm: Box::new(confirm) }
    }

    pub fn from_single(secret: &[u8], confirm: impl Fn(&str) -> bool + Send + Sync + 'static) -> Result<Self> {
        let key = SecretKey::from_slice(secret).map_err(|_| Error::Hardware("invalid key".into()))?;
        Ok(Self { device: key.clone(), biometric: key, confirm: Box::new(confirm) })
    }

    /// The device key's secret scalar.
    pub fn secret(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.device.to_bytes().to_vec())
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(64));
        bytes.extend_from_slice(&self.device.to_bytes());
        bytes.extend_from_slice(&self.biometric.to_bytes());
        bytes
    }

    pub fn from_bytes(
        bytes: &[u8],
        confirm: impl Fn(&str) -> bool + Send + Sync + 'static,
    ) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::Hardware("key file has the wrong size".into()));
        }
        let parse = |b: &[u8]| {
            SecretKey::from_slice(b).map_err(|_| Error::Hardware("invalid key file".into()))
        };
        Ok(Self {
            device: parse(&bytes[..32])?,
            biometric: parse(&bytes[32..])?,
            confirm: Box::new(confirm),
        })
    }
}

fn public_bytes(key: &SecretKey) -> Vec<u8> {
    key.public_key().to_encoded_point(false).as_bytes().to_vec()
}

fn ecdh(key: &SecretKey, peer_public: &[u8]) -> Result<Key> {
    let peer = PublicKey::from_sec1_bytes(peer_public).map_err(|_| Error::Crypto)?;
    let shared = p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine());
    key_from_slice(shared.raw_secret_bytes())
}

impl HardwareKeys for SoftwareKeys {
    fn device_public(&self) -> Vec<u8> {
        public_bytes(&self.device)
    }

    fn biometric_public(&self) -> Vec<u8> {
        public_bytes(&self.biometric)
    }

    fn device_ecdh(&self, peer_public: &[u8]) -> Result<Key> {
        ecdh(&self.device, peer_public)
    }

    fn biometric_ecdh(&self, peer_publics: &[&[u8]], prompt: &str) -> Result<Vec<Key>> {
        if !(self.confirm)(prompt) {
            return Err(Error::BiometricDenied);
        }
        peer_publics.iter().map(|p| ecdh(&self.biometric, p)).collect()
    }
}
