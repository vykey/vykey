//! `vy passwd`: changes the master password of a vault. Only the wrapped
//! vault key is rewritten (see `vykey_core::Store::change_password`), so
//! entries and fingerprint unlock stay as they are.

use vykey_core::{Store, Vault};
use zeroize::Zeroizing;

use crate::import::pick_vault;
use crate::tui::MIN_PASSWORD_LEN;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn run(store: &Store, vault: Option<&str>) -> Result<()> {
    let meta = pick_vault(store, vault)?;
    let current = Zeroizing::new(rpassword::prompt_password(format!(
        "Current master password for vault \"{}\": ",
        meta.name
    ))?);
    // Check it before asking for the new one.
    let mut vault = Vault::unlock(meta, &current)?;
    let new = Zeroizing::new(rpassword::prompt_password("New master password: ")?);
    if new.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "the master password must be at least {MIN_PASSWORD_LEN} characters long"
        )
        .into());
    }
    if *new == *current {
        return Err("the new password is the same as the current one".into());
    }
    let repeat = Zeroizing::new(rpassword::prompt_password("Repeat new master password: ")?);
    if *repeat != *new {
        return Err("passwords do not match".into());
    }
    let wrap = vault.password_change().prepare(&current, &new)?;
    store.change_password(&mut vault, wrap)?;
    println!(
        "Master password of \"{}\" changed. Backups and old copies of the database \
         still open with the old password.",
        vault.meta().name
    );
    Ok(())
}
