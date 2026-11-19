//! `vy fingerprint`: turns fingerprint unlock on or off for a vault. The
//! TUI then waits for a finger on its unlock screen, like `sudo` with
//! pam_fprintd. See `vykey_biometric` for how the key is kept.

use vykey_biometric::Availability;
use vykey_core::{Store, Vault};

use crate::import::pick_vault;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Action {
    /// Store the vault key in the system keyring (asks for the master password)
    Enable,
    /// Remove the vault key from the system keyring
    Disable,
    /// Show the reader and which vaults have fingerprint unlock
    Status,
}

fn reader_text(a: Availability) -> &'static str {
    match a {
        Availability::Ready => "ready",
        Availability::NoReader => "no fingerprint reader found",
        Availability::NoFingers => {
            "no fingerprints enrolled (add one in the system settings or with fprintd-enroll)"
        }
        Availability::Unsupported => "not supported (fprintd is not running or not installed)",
    }
}

pub fn run(store: &Store, action: Action, vault: Option<&str>) -> Result<()> {
    match action {
        Action::Status => {
            println!("Reader: {}", reader_text(vykey_biometric::availability()));
            let vaults = match vault {
                Some(name) => vec![store.vault_meta(name)?],
                None => store.list_vaults()?,
            };
            for v in vaults {
                let on = vykey_biometric::is_enabled(&v.id)?;
                println!("{}: {}", v.name, if on { "enabled" } else { "disabled" });
            }
        }
        Action::Enable => {
            let reader = vykey_biometric::availability();
            if reader != Availability::Ready {
                return Err(format!("fingerprint reader: {}", reader_text(reader)).into());
            }
            let meta = pick_vault(store, vault)?;
            let password = zeroize::Zeroizing::new(rpassword::prompt_password(format!(
                "Master password for vault \"{}\": ",
                meta.name
            ))?);
            let vault = Vault::unlock(meta, &password)?;
            drop(password);
            vykey_biometric::enable(vault.meta(), vault.key())?;
            println!(
                "Fingerprint unlock enabled for \"{}\".\n\
                 The vault key is now in the system keyring: anyone who can use your \
                 unlocked session can read it. Turn it off with `vy fingerprint disable`.",
                vault.meta().name
            );
        }
        Action::Disable => {
            let meta = pick_vault(store, vault)?;
            vykey_biometric::disable(&meta.id)?;
            println!("Fingerprint unlock disabled for \"{}\".", meta.name);
        }
    }
    Ok(())
}
