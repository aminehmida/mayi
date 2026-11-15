//! Symmetric sealing and ECIES key wrapping.
//!
//! Only standard constructions: XChaCha20-Poly1305 with random nonces, and
//! ephemeral-static P-256 ECDH + HKDF-SHA256 for wrapping to a device key.
//! P-256 is used because it is what the Secure Enclave and Android Keystore
//! offer for hardware-held keys.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

pub type Key = Zeroizing<[u8; 32]>;

const NONCE_LEN: usize = 24;
/// Uncompressed SEC1 P-256 point.
const PUBLIC_LEN: usize = 65;

pub fn random_key() -> Key {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

pub fn random_id() -> String {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    hex::encode(id)
}

/// Returns `nonce || ciphertext`.
pub fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("in-memory encryption cannot fail");
    [nonce.as_slice(), &ciphertext].concat()
}

pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN {
        return Err(Error::Crypto);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Crypto)
}

/// Re-encodes a P-256 public key in uncompressed form, rejecting invalid points.
pub fn normalize_public(public: &[u8]) -> Result<Vec<u8>> {
    let key = PublicKey::from_sec1_bytes(public).map_err(|_| Error::Crypto)?;
    Ok(key.to_encoded_point(false).as_bytes().to_vec())
}

fn ecies_key(shared: &[u8], ephemeral_public: &[u8], recipient_public: &[u8]) -> Key {
    let salt = [ephemeral_public, recipient_public].concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(b"mayi/ecies/v1", &mut *key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// Seals `plaintext` to a P-256 public key. Needs no access to the private
/// key, so any device can write a secret for a biometric-gated key.
///
/// Returns `ephemeral_public || nonce || ciphertext`.
pub fn ecies_seal(recipient_public: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let recipient_public = normalize_public(recipient_public)?;
    let recipient = PublicKey::from_sec1_bytes(&recipient_public).map_err(|_| Error::Crypto)?;
    let ephemeral = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public = ephemeral.public_key().to_encoded_point(false);
    let shared = ephemeral.diffie_hellman(&recipient);
    let key = ecies_key(
        shared.raw_secret_bytes(),
        ephemeral_public.as_bytes(),
        &recipient_public,
    );
    Ok([ephemeral_public.as_bytes(), &seal(&key, aad, plaintext)].concat())
}

/// The ephemeral public key the holder of the private key must run ECDH with.
pub fn ecies_ephemeral(sealed: &[u8]) -> Result<&[u8]> {
    sealed.get(..PUBLIC_LEN).ok_or(Error::Crypto)
}

/// Opens an ECIES blob given the ECDH result computed by the key holder.
pub fn ecies_open(
    shared: &[u8; 32],
    recipient_public: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let ephemeral_public = ecies_ephemeral(sealed)?;
    let recipient_public = normalize_public(recipient_public)?;
    let key = ecies_key(shared, ephemeral_public, &recipient_public);
    open(&key, aad, &sealed[PUBLIC_LEN..])
}

pub(crate) fn key_from_slice(bytes: &[u8]) -> Result<Key> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| Error::Crypto)?;
    Ok(Zeroizing::new(array))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::{HardwareKeys, SoftwareKeys};

    #[test]
    fn seal_round_trip_and_tamper() {
        let key = random_key();
        let sealed = seal(&key, b"aad", b"hello");
        assert_eq!(&**open(&key, b"aad", &sealed).unwrap(), b"hello");
        assert!(open(&key, b"other", &sealed).is_err());
        assert!(open(&random_key(), b"aad", &sealed).is_err());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, b"aad", &bad).is_err());
        assert!(open(&key, b"aad", &sealed[..10]).is_err());
    }

    #[test]
    fn ecies_round_trip() {
        let keys = SoftwareKeys::generate(|_| true);
        let public = keys.device_public();
        let sealed = ecies_seal(&public, b"aad", b"data key").unwrap();
        let shared = keys.device_ecdh(ecies_ephemeral(&sealed).unwrap()).unwrap();
        assert_eq!(
            &**ecies_open(&shared, &public, b"aad", &sealed).unwrap(),
            b"data key"
        );
        assert!(ecies_open(&shared, &public, b"other", &sealed).is_err());

        let other = SoftwareKeys::generate(|_| true);
        let wrong = other.device_ecdh(ecies_ephemeral(&sealed).unwrap()).unwrap();
        assert!(ecies_open(&wrong, &public, b"aad", &sealed).is_err());
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        assert!(ecies_seal(&[4u8; 65], b"", b"x").is_err());
        assert!(ecies_seal(b"short", b"", b"x").is_err());
    }
}
