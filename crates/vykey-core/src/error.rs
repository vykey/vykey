use crate::crypto::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid master password")]
    WrongPassword,
    #[error("vault \"{0}\" not found")]
    VaultNotFound(String),
    #[error("vault \"{0}\" already exists")]
    VaultExists(String),
    #[error("entry not found")]
    EntryNotFound,
    #[error("folder not found")]
    FolderNotFound,
    #[error("folder \"{0}\" already exists")]
    FolderExists(String),
    #[error("database schema version {0} is newer than supported ({1}); update vykey")]
    SchemaTooNew(i64, i64),
    #[error("stored value is not valid UTF-8")]
    InvalidUtf8,
    #[error("corrupt entry data: {0}")]
    Data(String),
    #[error("invalid TOTP secret")]
    InvalidTotpSecret,
}

pub type Result<T> = std::result::Result<T, Error>;
