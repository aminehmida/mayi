#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("decryption failed")]
    Crypto,
    #[error("hardware key: {0}")]
    Hardware(String),
    #[error("biometric check failed or was cancelled")]
    BiometricDenied,
    #[error("no such secret: {0}")]
    NotFound(String),
    #[error("vault: {0}")]
    Vault(String),
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
