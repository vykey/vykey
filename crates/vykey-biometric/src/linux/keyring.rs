//! The data key of a vault in the kernel key retention service (`keyctl`):
//! a `user` key "vykey:<vault id>" in the user keyring `@u`.
//!
//! Memory only, so a reboot drops it, and the kernel removes it when its
//! timeout ([`crate::KEY_LIFETIME`]) runs out, whether vykey runs or not.
//! Readable by processes of the same user, like any per-user secret store.

use std::time::Duration;

use linux_keyutils::{KeyError, KeyPermissionsBuilder, KeyRing, KeyRingIdentifier, Permission};
use zeroize::Zeroizing;

use crate::{Error, Result};

fn keyring_error(e: KeyError) -> Error {
    Error::Keyring(e.to_string())
}

fn user_keyring() -> Result<KeyRing> {
    KeyRing::from_special_id(KeyRingIdentifier::User, true).map_err(keyring_error)
}

fn description(vault_id: &str) -> String {
    format!("vykey:{vault_id}")
}

/// Not there, or just expired / removed.
fn missing(e: &KeyError) -> bool {
    matches!(
        e,
        KeyError::KeyDoesNotExist | KeyError::KeyExpired | KeyError::KeyRevoked
    )
}

pub fn store_secret(vault_id: &str, secret: &[u8], lifetime: Duration) -> Result<()> {
    let ring = user_keyring()?;
    // Replaces (updates) an existing key with the same description.
    let key = ring
        .add_key(&description(vault_id), secret)
        .map_err(keyring_error)?;
    // Our user only, and no linking into other keyrings.
    let perms = KeyPermissionsBuilder::builder()
        .posessor(Permission::ALL)
        .user(
            Permission::VIEW
                | Permission::READ
                | Permission::WRITE
                | Permission::SEARCH
                | Permission::SETATTR,
        )
        .build();
    key.set_perms(perms).map_err(keyring_error)?;
    let seconds = usize::try_from(lifetime.as_secs()).unwrap_or(usize::MAX);
    key.set_timeout(seconds).map_err(keyring_error)
}

pub fn load_secret(vault_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match user_keyring()?.search(&description(vault_id)) {
        Ok(key) => match key.read_to_vec() {
            Ok(secret) => Ok(Some(Zeroizing::new(secret))),
            Err(e) if missing(&e) => Ok(None),
            Err(e) => Err(keyring_error(e)),
        },
        Err(e) if missing(&e) => Ok(None),
        Err(e) => Err(keyring_error(e)),
    }
}

pub fn has_secret(vault_id: &str) -> bool {
    user_keyring().is_ok_and(|ring| ring.search(&description(vault_id)).is_ok())
}

pub fn delete_secret(vault_id: &str) -> Result<()> {
    match user_keyring()?.search(&description(vault_id)) {
        Ok(key) => match key.invalidate() {
            Ok(()) => Ok(()),
            Err(e) if missing(&e) => Ok(()),
            Err(e) => Err(keyring_error(e)),
        },
        Err(e) if missing(&e) => Ok(()),
        Err(e) => Err(keyring_error(e)),
    }
}
