//! `vy fingerprint`: turns fingerprint unlock on or off for a vault. The
//! TUI then waits for a finger on its unlock screen, like `sudo` with
//! pam_fprintd. The flag lives in settings.json (shared with the desktop
//! app); the key itself in the kernel keyring, for at most a day after the
//! last master password and never across a reboot (see `vykey_biometric`).

use vykey_biometric::Availability;
use vykey_core::settings::Settings;
use vykey_core::{Store, Vault};

use crate::import::pick_vault;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Action {
    /// Turn it on (asks for the master password)
    Enable,
    /// Turn it off and drop the stored key
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
    let path = vykey_core::paths::settings_path().ok_or("cannot find the settings directory")?;
    let mut settings = Settings::load(&path);
    match action {
        Action::Status => {
            println!("Reader: {}", reader_text(vykey_biometric::availability()));
            let vaults = match vault {
                Some(name) => vec![store.vault_meta(name)?],
                None => store.list_vaults()?,
            };
            for v in vaults {
                let state = match (settings.fingerprint(&v.id), vykey_biometric::has_key(&v.id)) {
                    (false, _) => "off",
                    (true, true) => "on",
                    (true, false) => "on, enter the master password once to use it",
                };
                println!("{}: {state}", v.name);
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
            vykey_biometric::store_key(&vault.meta().id, vault.key())?;
            settings.set_fingerprint(&vault.meta().id, true);
            settings.save(&path)?;
            println!(
                "Fingerprint unlock enabled for \"{}\".\n\
                 The master password is still needed after every restart and at least \
                 once a day. Turn it off with `vy fingerprint disable`.",
                vault.meta().name
            );
        }
        Action::Disable => {
            let meta = pick_vault(store, vault)?;
            vykey_biometric::remove_key(&meta.id)?;
            settings.set_fingerprint(&meta.id, false);
            settings.save(&path)?;
            println!("Fingerprint unlock disabled for \"{}\".", meta.name);
        }
    }
    Ok(())
}
