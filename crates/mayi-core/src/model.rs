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

/// Where a secret's values may go.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Into the environment of a command.
    #[default]
    Secret,
    /// Into the sign-in form of one of its websites, and nowhere else.
    Login,
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
    #[serde(default)]
    pub kind: Kind,
    /// The websites a login may be typed into: a host, `*.` and a host for
    /// its subdomains, each with an optional port. Empty for other secrets.
    #[serde(default)]
    pub sites: Vec<String>,
    #[serde(skip)]
    pub version: u64,
}

pub struct NewItem {
    pub name: String,
    pub level: Level,
    pub values: SecretValues,
    pub allow: Vec<String>,
    pub max_grant_secs: u64,
    pub kind: Kind,
    pub sites: Vec<String>,
}
