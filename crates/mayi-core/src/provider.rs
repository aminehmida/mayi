//! Providers turn a secret's stored values into the values it releases.
//!
//! There is one for each [`Source`], compiled in rather than loaded: the
//! vault device holds every key, so code that runs there ships with Mayi.
//! Stored values are the only source so far. A login's go through their own
//! provider, because its two-factor key is never released: the page gets
//! the current code. See `docs/providers.md` for the ones planned.

use mayi_proto::{FIELD_PASSWORD, FIELD_TOTP, FIELD_USERNAME};

use crate::model::{Destination, ItemMeta, SecretValues, Source};
use crate::totp::Totp;

/// Why a device refuses a secret whose destination or source it does not know.
pub const NEEDS_NEWER: &str = "it was made by a newer version of Mayi: update Mayi on this device to use it";

pub trait Provider: Sync {
    /// Checks, and tidies, values about to be stored.
    fn check(&self, values: &mut SecretValues) -> Result<(), String>;

    /// The values to release for `fields`, made from the stored ones. Has
    /// every field asked for, or fails. `now_secs` is Unix time in seconds.
    fn release(&self, stored: &SecretValues, fields: &[&str], now_secs: u64) -> Result<SecretValues, String>;
}

/// The provider for a secret going to `destination` from `source`, or why
/// this device cannot use it.
pub fn find(destination: &Destination, source: &Source) -> Result<&'static dyn Provider, String> {
    match (destination, source) {
        (Destination::Command, Source::Stored) => Ok(&Stored),
        (Destination::Website, Source::Stored) => Ok(&Login),
        _ => Err(NEEDS_NEWER.into()),
    }
}

/// [`find`] for an existing secret, with its name in the error.
pub fn of(meta: &ItemMeta) -> Result<&'static dyn Provider, String> {
    find(&meta.destination, &meta.source).map_err(|e| format!("{}: {e}", meta.name))
}

fn field<'a>(stored: &'a SecretValues, name: &str) -> Result<&'a zeroize::Zeroizing<String>, String> {
    stored.get(name).ok_or_else(|| format!("no field {name}"))
}

/// Values released as the owner saved them.
pub struct Stored;

impl Provider for Stored {
    fn check(&self, _values: &mut SecretValues) -> Result<(), String> {
        Ok(())
    }

    fn release(&self, stored: &SecretValues, fields: &[&str], _now_secs: u64) -> Result<SecretValues, String> {
        fields.iter().map(|&f| Ok((f.to_string(), field(stored, f)?.clone()))).collect()
    }
}

const LOGIN_FIELDS: [&str; 3] = [FIELD_USERNAME, FIELD_PASSWORD, FIELD_TOTP];

/// A website login: a password, and optionally a username and a two-factor
/// key, under fixed names. The key stays here; the page gets the code.
pub struct Login;

impl Provider for Login {
    /// Empty optional fields are dropped.
    fn check(&self, values: &mut SecretValues) -> Result<(), String> {
        if let Some(other) = values.keys().find(|f| !LOGIN_FIELDS.contains(&f.as_str())) {
            return Err(format!("a login has a username, a password and a two-factor key, not {other:?}"));
        }
        values.retain(|field, value| field == FIELD_PASSWORD || !value.trim().is_empty());
        if values.get(FIELD_PASSWORD).is_none_or(|p| p.is_empty()) {
            return Err("a login needs a password".into());
        }
        if let Some(key) = values.get(FIELD_TOTP) {
            Totp::parse(key)?;
        }
        Ok(())
    }

    fn release(&self, stored: &SecretValues, fields: &[&str], now_secs: u64) -> Result<SecretValues, String> {
        fields
            .iter()
            .map(|&f| {
                let value = field(stored, f)?;
                let value = if f == FIELD_TOTP { Totp::parse(value)?.code(now_secs) } else { value.clone() };
                Ok((f.to_string(), value))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn values(pairs: &[(&str, &str)]) -> SecretValues {
        pairs.iter().map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string()))).collect()
    }

    #[test]
    fn each_known_pair_has_a_provider_and_others_none() {
        assert!(find(&Destination::Command, &Source::Stored).is_ok());
        assert!(find(&Destination::Website, &Source::Stored).is_ok());
        let newer = [
            (Destination::Other("file".into()), Source::Stored),
            (Destination::Command, Source::Other("aws_sso".into())),
            (Destination::Website, Source::Other("aws_sso".into())),
        ];
        for (destination, source) in newer {
            assert_eq!(find(&destination, &source).err().as_deref(), Some(NEEDS_NEWER));
        }
    }

    #[test]
    fn stored_values_are_released_as_saved() {
        let stored = values(&[("user", "u"), ("password", "p"), ("totp", KEY)]);
        let out = Stored.release(&stored, &["password", "totp"], 59).unwrap();
        assert_eq!(out, values(&[("password", "p"), ("totp", KEY)]), "only what was asked, a totp field untouched");
        assert!(Stored.release(&stored, &["missing"], 59).is_err());
    }

    #[test]
    fn a_login_releases_the_code_and_never_the_key() {
        let stored = values(&[("username", "amine"), ("password", "pw"), ("totp", KEY)]);
        let out = Login.release(&stored, &["username", "password", "totp"], 59).unwrap();
        assert_eq!(&**out.get("username").unwrap(), "amine");
        assert_eq!(&**out.get("password").unwrap(), "pw");
        // The RFC 6238 test key's code at 59 seconds, to six digits.
        assert_eq!(&**out.get("totp").unwrap(), "287082");
        assert!(Login.release(&stored, &["value"], 59).is_err());
    }
}
