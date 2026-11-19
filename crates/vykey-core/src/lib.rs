//! Core of vykey: vault format, cryptography and storage.
//!
//! The on-disk format is described in `docs/vault-format.md`. vykey owns
//! it; databases created by the Go implementation (github.com/stickpro/kyp)
//! are upgraded on open.

#![forbid(unsafe_code)]

pub mod audit;
pub mod card;
pub mod crypto;
pub mod error;
pub mod password;
pub mod paths;
mod schema;
pub mod settings;
pub mod store;
pub mod totp;

pub use error::{Error, Result};
pub use store::{
    Card, Entry, EntryInput, EntryKind, Folder, KeyWrap, PasswordChange, Store, Vault, VaultMeta,
};
