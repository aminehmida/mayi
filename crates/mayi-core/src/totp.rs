//! Time-based one-time codes (RFC 6238), as authenticator apps compute them.
//!
//! A login's two-factor key stays on vault devices. A requester only ever
//! gets the code of the moment, which is useless a minute later.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    key: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

/// RFC 4648 base32, as setup keys are written: any case, and with the
/// spaces, dashes and padding people and websites add.
fn base32(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.chars() {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            '=' | ' ' | '-' => continue,
            _ => return None,
        };
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn hmac<M: Mac + hmac::digest::KeyInit>(key: &[u8], message: &[u8]) -> Zeroizing<Vec<u8>> {
    // HMAC takes a key of any length, so this cannot fail.
    let mut mac = <M as Mac>::new_from_slice(key).expect("any key length");
    mac.update(message);
    Zeroizing::new(mac.finalize().into_bytes().to_vec())
}

impl Totp {
    /// Reads what a website shows when two-factor is set up: the key on its
    /// own, or the `otpauth://totp/...` link inside the QR code.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let mut totp = Totp { key: Zeroizing::new(Vec::new()), algorithm: Algorithm::Sha1, digits: 6, period: 30 };
        let key = match text.strip_prefix("otpauth://") {
            None => text,
            Some(link) => {
                if !link.starts_with("totp/") {
                    return Err("only time-based two-factor keys are supported".into());
                }
                let query = link.split_once('?').map_or("", |(_, query)| query);
                let mut key = "";
                for (name, value) in query.split('&').filter_map(|pair| pair.split_once('=')) {
                    match name {
                        "secret" => key = value,
                        "algorithm" => {
                            totp.algorithm = match value.to_ascii_uppercase().as_str() {
                                "SHA1" => Algorithm::Sha1,
                                "SHA256" => Algorithm::Sha256,
                                "SHA512" => Algorithm::Sha512,
                                _ => return Err(format!("unsupported two-factor algorithm {value}")),
                            }
                        }
                        "digits" => totp.digits = value.parse().map_err(|_| "bad digits in the two-factor link")?,
                        "period" => totp.period = value.parse().map_err(|_| "bad period in the two-factor link")?,
                        _ => {}
                    }
                }
                key
            }
        };
        totp.key = Zeroizing::new(base32(key).ok_or("the two-factor key is not valid base32")?);
        if totp.key.is_empty() {
            return Err("the two-factor key is empty".into());
        }
        if !(6..=8).contains(&totp.digits) || totp.period == 0 {
            return Err("unsupported two-factor settings".into());
        }
        Ok(totp)
    }

    /// How many seconds the code valid at `unix_secs` stays valid.
    pub fn valid_for(&self, unix_secs: u64) -> u64 {
        self.period - unix_secs % self.period
    }

    /// The code valid at `unix_secs`.
    pub fn code(&self, unix_secs: u64) -> Zeroizing<String> {
        let counter = (unix_secs / self.period).to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 => hmac::<Hmac<Sha1>>(&self.key, &counter),
            Algorithm::Sha256 => hmac::<Hmac<Sha256>>(&self.key, &counter),
            Algorithm::Sha512 => hmac::<Hmac<Sha512>>(&self.key, &counter),
        };
        let at = (mac[mac.len() - 1] & 0x0f) as usize;
        let number = u32::from_be_bytes([mac[at] & 0x7f, mac[at + 1], mac[at + 2], mac[at + 3]]);
        Zeroizing::new(format!("{:0width$}", number % 10u32.pow(self.digits), width = self.digits as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totp(key: &[u8], algorithm: Algorithm) -> Totp {
        Totp { key: Zeroizing::new(key.to_vec()), algorithm, digits: 8, period: 30 }
    }

    #[test]
    fn rfc_6238_vectors() {
        let sha1 = totp(b"12345678901234567890", Algorithm::Sha1);
        let sha256 = totp(b"12345678901234567890123456789012", Algorithm::Sha256);
        let sha512 =
            totp(b"1234567890123456789012345678901234567890123456789012345678901234", Algorithm::Sha512);
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (time, want1, want256, want512) in cases {
            assert_eq!(*sha1.code(time), want1, "sha1 at {time}");
            assert_eq!(*sha256.code(time), want256, "sha256 at {time}");
            assert_eq!(*sha512.code(time), want512, "sha512 at {time}");
        }
    }

    #[test]
    fn reads_keys_as_websites_show_them() {
        // "12345678901234567890" in base32.
        let key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let plain = Totp::parse(key).unwrap();
        assert_eq!(*plain.code(59), "287082", "six digits by default");
        let spaced = Totp::parse(" gezd gnbv gy3t qojq gezd gnbv gy3t qojq ").unwrap();
        assert_eq!(*spaced.code(59), "287082");
        let link = Totp::parse(&format!(
            "otpauth://totp/Example:amine@example.com?secret={key}&issuer=Example&digits=8&period=30&algorithm=SHA1"
        ))
        .unwrap();
        assert_eq!(*link.code(59), "94287082");
        let slow = Totp::parse(&format!("otpauth://totp/x?secret={key}&period=60")).unwrap();
        assert_eq!(slow.code(59), slow.code(0));
        assert_ne!(slow.code(59), slow.code(60));
    }

    #[test]
    fn rejects_what_it_cannot_compute() {
        for bad in [
            "",
            "not base32!",
            "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1",
            "otpauth://totp/x?issuer=nokey",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=12",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&period=0",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad:?}");
        }
    }
}
