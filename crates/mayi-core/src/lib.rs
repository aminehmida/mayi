//! Vault, policy and broker logic shared by every Mayi vault device.

pub mod broker;
pub mod crypto;
pub mod error;
pub mod grants;
pub mod hardware;
pub mod model;
pub mod policy;
#[cfg(unix)]
pub mod server;
pub mod sync;
pub mod totp;
pub mod vault;

pub use error::{Error, Result};

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
