//! Providers turn a secret's stored values into the values it releases.
//!
//! There is one for each [`Source`], compiled in rather than loaded: the
//! vault device holds every key, so code that runs there ships with Mayi.
//! Stored values go out as saved; a login's go through their own provider,
//! because its two-factor key is never released: the page gets the current
//! code. An AWS sign-in's provider (`aws.rs`) keeps state and talks to AWS,
//! so the broker owns it. See `docs/providers.md` for the ones planned.

use mayi_proto::{FIELD_PASSWORD, FIELD_TOTP, FIELD_USERNAME};

use crate::model::{Destination, ItemMeta, SecretValues, Source};
use crate::totp::Totp;

/// Why a device refuses a secret whose destination or source it does not know.
pub const NEEDS_NEWER: &str = "it was made by a newer version of Mayi: update Mayi on this device to use it";

/// What a provider is asked to release.
pub struct Release<'a> {
    pub meta: &'a ItemMeta,
    pub stored: &'a SecretValues,
    /// The fields asked for, as the request's bindings name them.
    pub fields: &'a [&'a str],
    /// Unix time in seconds.
    pub now_secs: u64,
}

pub struct Released {
    /// Every field asked for.
    pub values: SecretValues,
    /// New stored values to keep, when the provider's state changed (AWS
    /// replaced a refresh token).
    pub store: Option<SecretValues>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Failed(String),
    /// The owner must sign in again (an AWS session ended).
    SignInNeeded(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Failed(why) | Refusal::SignInNeeded(why) => f.write_str(why),
        }
    }
}

pub trait Provider: Sync {
    /// Checks, and tidies, values about to be stored.
    fn check(&self, values: &mut SecretValues) -> Result<(), String>;

    /// The values to release, made from the stored ones.
    fn release(&self, r: &Release) -> Result<Released, Refusal>;
}

/// Whether this version can use a secret going to `destination` from
/// `source`.
pub fn known(destination: &Destination, source: &Source) -> Result<(), String> {
    match (destination, source) {
        (Destination::Command, Source::Stored | Source::AwsSso) | (Destination::Website, Source::Stored) => Ok(()),
        _ => Err(NEEDS_NEWER.into()),
    }
}

/// [`known`] for an existing secret, with its name in the error.
pub fn check_known(meta: &ItemMeta) -> Result<(), String> {
    known(&meta.destination, &meta.source).map_err(|e| format!("{}: {e}", meta.name))
}

/// The provider for stored values going to `destination`. AWS sign-ins are
/// released by the broker's own provider.
pub fn stored(destination: &Destination) -> Result<&'static dyn Provider, String> {
    match destination {
        Destination::Command => Ok(&Stored),
        Destination::Website => Ok(&Login),
        Destination::Other(_) => Err(NEEDS_NEWER.into()),
    }
}

fn field<'a>(stored: &'a SecretValues, name: &str) -> Result<&'a zeroize::Zeroizing<String>, Refusal> {
    stored.get(name).ok_or_else(|| Refusal::Failed(format!("no field {name}")))
}

/// Values released as the owner saved them.
pub struct Stored;

impl Provider for Stored {
    fn check(&self, _values: &mut SecretValues) -> Result<(), String> {
        Ok(())
    }

    fn release(&self, r: &Release) -> Result<Released, Refusal> {
        let values = r.fields.iter().map(|&f| Ok((f.to_string(), field(r.stored, f)?.clone()))).collect::<Result<_, _>>()?;
        Ok(Released { values, store: None })
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

    fn release(&self, r: &Release) -> Result<Released, Refusal> {
        let values = r
            .fields
            .iter()
            .map(|&f| {
                let value = field(r.stored, f)?;
                let value = if f == FIELD_TOTP {
                    Totp::parse(value).map_err(Refusal::Failed)?.code(r.now_secs)
                } else {
                    value.clone()
                };
                Ok((f.to_string(), value))
            })
            .collect::<Result<_, Refusal>>()?;
        Ok(Released { values, store: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Level;
    use zeroize::Zeroizing;

    const KEY: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn values(pairs: &[(&str, &str)]) -> SecretValues {
        pairs.iter().map(|(k, v)| (k.to_string(), Zeroizing::new(v.to_string()))).collect()
    }

    fn meta() -> ItemMeta {
        ItemMeta {
            id: "i".into(),
            name: "x".into(),
            level: Level::Log,
            allow: vec![],
            max_grant_secs: 0,
            fields: vec![],
            destination: Destination::Command,
            source: Source::Stored,
            sites: vec![],
            folder: None,
            rotate: vec![],
            aws: None,
            unknown_fields: Default::default(),
            version: 1,
        }
    }

    fn release(p: &dyn Provider, stored: &SecretValues, fields: &[&str]) -> Result<SecretValues, Refusal> {
        p.release(&Release { meta: &meta(), stored, fields, now_secs: 59 }).map(|r| r.values)
    }

    #[test]
    fn known_pairs_and_others() {
        for (destination, source) in [
            (Destination::Command, Source::Stored),
            (Destination::Website, Source::Stored),
            (Destination::Command, Source::AwsSso),
        ] {
            assert!(known(&destination, &source).is_ok(), "{destination:?} {source:?}");
        }
        let newer = [
            (Destination::Other("file".into()), Source::Stored),
            (Destination::Command, Source::Other("gcloud".into())),
            (Destination::Website, Source::AwsSso),
        ];
        for (destination, source) in newer {
            assert_eq!(known(&destination, &source).err().as_deref(), Some(NEEDS_NEWER));
        }
        assert!(stored(&Destination::Other("file".into())).is_err());
    }

    #[test]
    fn stored_values_are_released_as_saved() {
        let stored = values(&[("user", "u"), ("password", "p"), ("totp", KEY)]);
        let out = release(&Stored, &stored, &["password", "totp"]).unwrap();
        assert_eq!(out, values(&[("password", "p"), ("totp", KEY)]), "only what was asked, a totp field untouched");
        assert!(release(&Stored, &stored, &["missing"]).is_err());
    }

    #[test]
    fn a_login_releases_the_code_and_never_the_key() {
        let stored = values(&[("username", "amine"), ("password", "pw"), ("totp", KEY)]);
        let out = release(&Login, &stored, &["username", "password", "totp"]).unwrap();
        assert_eq!(&**out.get("username").unwrap(), "amine");
        assert_eq!(&**out.get("password").unwrap(), "pw");
        // The RFC 6238 test key's code at 59 seconds, to six digits.
        assert_eq!(&**out.get("totp").unwrap(), "287082");
        assert!(release(&Login, &stored, &["value"]).is_err());
    }
}
