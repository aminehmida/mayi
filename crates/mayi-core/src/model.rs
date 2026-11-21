use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// How much user involvement a secret demands before it is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum Level {
    /// Released silently; the request is recorded.
    Log = 1,
    /// Released at once; the user is notified and can stop the command.
    Notify = 2,
    /// Held until the user approves.
    Approve = 3,
    /// Encrypted to a biometric-gated hardware key.
    Biometric = 4,
}

impl From<Level> for u8 {
    fn from(level: Level) -> u8 {
        level as u8
    }
}

impl TryFrom<u8> for Level {
    type Error = String;

    fn try_from(n: u8) -> Result<Self, String> {
        match n {
            1 => Ok(Level::Log),
            2 => Ok(Level::Notify),
            3 => Ok(Level::Approve),
            4 => Ok(Level::Biometric),
            _ => Err(format!("level must be 1 to 4, got {n}")),
        }
    }
}

/// Where a secret's values may go. Stored as `kind`, with the names it had
/// before destinations had their own word: `secret` and `login`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum Destination {
    /// Into the environment of a command.
    #[default]
    Command,
    /// Into the sign-in form of one of its websites, and nowhere else.
    Website,
    /// One added by a newer version of Mayi: listed and synced, never
    /// released here.
    Other(String),
}

impl From<String> for Destination {
    fn from(name: String) -> Self {
        match name.as_str() {
            "secret" => Self::Command,
            "login" => Self::Website,
            _ => Self::Other(name),
        }
    }
}

impl From<Destination> for String {
    fn from(destination: Destination) -> String {
        match destination {
            Destination::Command => "secret".into(),
            Destination::Website => "login".into(),
            Destination::Other(name) => name,
        }
    }
}

/// What produces a secret's values (see `provider.rs`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum Source {
    /// The values saved by the owner. Left out of stored records, so they
    /// read the same to versions that came before sources.
    #[default]
    Stored,
    /// An AWS IAM Identity Center sign-in: the values are its session, and
    /// what is released is the credentials of one of its profiles, fetched
    /// by the vault device (see `aws.rs`).
    AwsSso,
    /// One added by a newer version of Mayi: listed and synced, never
    /// released here.
    Other(String),
}

impl Source {
    pub fn is_stored(&self) -> bool {
        *self == Source::Stored
    }
}

impl From<String> for Source {
    fn from(name: String) -> Self {
        match name.as_str() {
            "stored" => Self::Stored,
            "aws_sso" => Self::AwsSso,
            _ => Self::Other(name),
        }
    }
}

impl From<Source> for String {
    fn from(source: Source) -> String {
        match source {
            Source::Stored => "stored".into(),
            Source::AwsSso => "aws_sso".into(),
            Source::Other(name) => name,
        }
    }
}

/// One role of an AWS sign-in that requests may use, under a name of the
/// owner's choosing, with its own level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsProfile {
    pub name: String,
    pub account_id: String,
    #[serde(default)]
    pub account_name: String,
    pub role: String,
    pub level: Level,
}

/// What is not secret about an AWS sign-in: where it signs in, and the
/// profiles it offers. Kept with the metadata, so listing never decrypts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsSignIn {
    pub start_url: String,
    pub region: String,
    pub profiles: Vec<AwsProfile>,
}

/// Field name to value.
pub type SecretValues = BTreeMap<String, Zeroizing<String>>;

/// Everything about a secret except its values. Readable with the vault key
/// alone, so listing and policy never need a biometric check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ItemMeta {
    pub id: String,
    pub name: String,
    /// Minimum level; context can raise it but never lower it.
    pub level: Level,
    /// Command patterns (`*` wildcard) this secret is expected to be used with.
    pub allow: Vec<String>,
    /// Longest a single approval may stay valid. 0 means every use asks again.
    pub max_grant_secs: u64,
    pub fields: Vec<String>,
    #[serde(default, rename = "kind")]
    pub destination: Destination,
    #[serde(default, skip_serializing_if = "Source::is_stored")]
    pub source: Source,
    /// The websites a login may be typed into: a host, `*.` and a host for
    /// its subdomains, each with an optional port. Empty for other secrets.
    #[serde(default)]
    pub sites: Vec<String>,
    /// The folder the owner keeps it in, for the apps' lists. Agents use names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Who may still know the value since a machine was revoked or a device
    /// removed. Cleared by saving a new value, or dismissed by the owner.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rotate: Vec<RotateNote>,
    /// For an AWS sign-in: its portal and profiles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsSignIn>,
    /// Fields written by a newer version of Mayi, kept as they are so that
    /// changing this secret here does not strip them.
    #[serde(flatten)]
    pub unknown_fields: BTreeMap<String, serde_json::Value>,
    #[serde(skip)]
    pub version: u64,
}

/// Why a secret should be replaced at its source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateNote {
    /// The machine or device that may still know the value.
    pub who: String,
    /// `revoked` (a machine) or `removed` (a device).
    pub why: String,
    pub at_ms: u64,
}

pub struct NewItem {
    pub name: String,
    pub level: Level,
    pub values: SecretValues,
    pub allow: Vec<String>,
    pub max_grant_secs: u64,
    pub destination: Destination,
    pub sites: Vec<String>,
    pub folder: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(json: serde_json::Value) -> ItemMeta {
        serde_json::from_value(json).unwrap()
    }

    fn base() -> serde_json::Value {
        serde_json::json!({
            "id": "i1", "name": "TOKEN", "level": 3, "allow": [], "max_grant_secs": 600,
            "fields": ["value"], "kind": "secret", "sites": [],
        })
    }

    #[test]
    fn records_read_and_write_as_before() {
        let secret = meta(base());
        assert_eq!(secret.destination, Destination::Command);
        assert_eq!(secret.source, Source::Stored);
        assert_eq!(serde_json::to_value(&secret).unwrap(), base(), "no new keys written");

        let mut login = base();
        login["kind"] = "login".into();
        assert_eq!(meta(login.clone()).destination, Destination::Website);
        assert_eq!(serde_json::to_value(meta(login.clone())).unwrap(), login);

        let mut old = base();
        old.as_object_mut().unwrap().remove("kind");
        assert_eq!(meta(old).destination, Destination::Command, "records from before logins");
    }

    #[test]
    fn what_a_newer_version_wrote_survives_a_round_trip() {
        let mut newer = base();
        newer["kind"] = "file".into();
        newer["source"] = "gcloud".into();
        newer["targets"] = serde_json::json!([{ "name": "ReadOnly", "level": 1 }]);
        let read = meta(newer.clone());
        assert_eq!(read.destination, Destination::Other("file".into()));
        assert_eq!(read.source, Source::Other("gcloud".into()));
        assert!(read.unknown_fields.contains_key("targets"));
        assert_eq!(serde_json::to_value(&read).unwrap(), newer);
    }
}
