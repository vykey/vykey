//! Fingerprint unlock.
//!
//! A fingerprint cannot produce a key, so the vault key is kept by the OS
//! and handed out after the reader confirms the finger:
//!
//! 1. With the vault open, [`enable`] stores its master key in the user's
//!    keyring (Secret Service: GNOME Keyring, KWallet, KeePassXC).
//! 2. On the unlock screen [`verify`] asks fprintd to check a finger — the
//!    same reader and prompts `sudo` uses through `pam_fprintd`.
//! 3. On a match, [`open`] reads the key back and opens the vault without
//!    Argon2 or the master password.
//!
//! Security note: on Linux the fingerprint only gates vykey's own UI. The
//! keyring hands the key to any process of the same user while it is
//! unlocked; there is no hardware binding as with Touch ID or Windows Hello.
//! A stale key (vault re-created, database replaced) is detected by the
//! verifier and removed.
//!
//! Every call blocks (D-Bus round trips, a keyring prompt, waiting for a
//! finger): run them off the UI thread.

#![forbid(unsafe_code)]

use std::time::Duration;

use vykey_core::crypto::{KEY_LEN, Key};
use vykey_core::{Vault, VaultMeta};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(not(target_os = "linux"))]
mod unsupported;
#[cfg(not(target_os = "linux"))]
use unsupported as platform;

/// How long [`verify`] waits for a finger, as `pam_fprintd`. The reader is
/// claimed meanwhile, so `sudo` in another terminal cannot use it.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// Failed scans before [`verify`] gives up, as `pam_fprintd`.
pub const MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fingerprint unlock is not supported on this system")]
    Unsupported,
    #[error("no fingerprint reader found")]
    NoReader,
    #[error("no fingerprints enrolled (add one in the system settings or with fprintd-enroll)")]
    NoFingers,
    #[error("the fingerprint reader is in use by another program")]
    Busy,
    #[error("the fingerprint reader was disconnected")]
    Disconnected,
    #[error("not allowed to use the fingerprint reader: {0}")]
    Denied(String),
    #[error("fingerprint reader error: {0}")]
    Reader(String),
    #[error("no system keyring (Secret Service): {0}")]
    NoKeyring(String),
    #[error("the keyring request was dismissed")]
    Dismissed,
    #[error("D-Bus error: {0}")]
    Dbus(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Whether a fingerprint can be used right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Ready,
    /// fprintd runs, but there is no reader.
    NoReader,
    /// There is a reader, but the user has no enrolled fingers.
    NoFingers,
    /// No fprintd (or not Linux).
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finger {
    LeftThumb,
    LeftIndex,
    LeftMiddle,
    LeftRing,
    LeftLittle,
    RightThumb,
    RightIndex,
    RightMiddle,
    RightRing,
    RightLittle,
}

impl Finger {
    /// From fprintd's finger name ("right-index-finger"); `None` for "any".
    pub fn from_fprintd(name: &str) -> Option<Self> {
        Some(match name {
            "left-thumb" => Self::LeftThumb,
            "left-index-finger" => Self::LeftIndex,
            "left-middle-finger" => Self::LeftMiddle,
            "left-ring-finger" => Self::LeftRing,
            "left-little-finger" => Self::LeftLittle,
            "right-thumb" => Self::RightThumb,
            "right-index-finger" => Self::RightIndex,
            "right-middle-finger" => Self::RightMiddle,
            "right-ring-finger" => Self::RightRing,
            "right-little-finger" => Self::RightLittle,
            _ => return None,
        })
    }

    /// English name, as in pam_fprintd's prompt: "right index finger".
    pub fn name(self) -> &'static str {
        match self {
            Self::LeftThumb => "left thumb",
            Self::LeftIndex => "left index finger",
            Self::LeftMiddle => "left middle finger",
            Self::LeftRing => "left ring finger",
            Self::LeftLittle => "left little finger",
            Self::RightThumb => "right thumb",
            Self::RightIndex => "right index finger",
            Self::RightMiddle => "right middle finger",
            Self::RightRing => "right ring finger",
            Self::RightLittle => "right little finger",
        }
    }
}

/// Why the reader wants another scan (the attempt is not counted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    Scan,
    SwipeTooShort,
    NotCentered,
    RemoveAndRetry,
}

/// Progress of [`verify`], for the prompt on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The reader waits. `finger` is `None` when any enrolled finger works;
    /// `swipe` readers want a swipe instead of a touch.
    Prompt {
        finger: Option<Finger>,
        swipe: bool,
    },
    Retry(Retry),
    /// Wrong finger; the reader waits again.
    NoMatch {
        attempts_left: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Match,
    /// [`MAX_ATTEMPTS`] failed scans.
    NoMatch,
    TimedOut,
    Cancelled,
}

/// Stops a running [`verify`] from another thread. Cloning shares it.
#[derive(Clone)]
pub struct Cancel(platform::Cancel);

impl Cancel {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(platform::Cancel::new())
    }

    pub fn cancel(&self) {
        self.0.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }
}

/// Checks for fprintd, a reader and enrolled fingers. Quick (D-Bus calls
/// only), never touches the reader.
pub fn availability() -> Availability {
    platform::availability()
}

/// Claims the reader and waits for a finger: up to [`MAX_ATTEMPTS`] scans
/// within `timeout`, or until `cancel`. `on_event` drives the prompt.
pub fn verify(cancel: &Cancel, timeout: Duration, on_event: impl FnMut(Event)) -> Result<Verdict> {
    platform::verify(&cancel.0, timeout, on_event)
}

/// Whether the keyring holds a key for this vault. Never shows a prompt.
pub fn is_enabled(vault_id: &str) -> Result<bool> {
    platform::has_secret(vault_id)
}

/// Stores the key of an open vault (replacing an older one). May show the
/// keyring's unlock prompt.
pub fn enable(meta: &VaultMeta, key: &Key) -> Result<()> {
    platform::store_secret(
        &meta.id,
        &format!("vykey vault “{}”", meta.name),
        key.as_slice(),
    )
}

/// Removes the stored key; nothing to do if there is none.
pub fn disable(vault_id: &str) -> Result<()> {
    platform::delete_secret(vault_id)
}

/// Opens the vault with the stored key. Call only after [`verify`] returned
/// [`Verdict::Match`]. `Ok(None)`: no key, or a stale one (removed, so the
/// next unlock asks for the master password).
pub fn open(meta: VaultMeta) -> Result<Option<Vault>> {
    let Some(secret) = platform::load_secret(&meta.id)? else {
        return Ok(None);
    };
    let key: Option<Key> = <[u8; KEY_LEN]>::try_from(secret.as_slice())
        .ok()
        .map(Zeroizing::new);
    drop(secret);
    let id = meta.id.clone();
    match key.map(|k| Vault::unlock_with_key(meta, k)) {
        Some(Ok(vault)) => Ok(Some(vault)),
        _ => {
            platform::delete_secret(&id)?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finger_names() {
        assert_eq!(
            Finger::from_fprintd("right-index-finger"),
            Some(Finger::RightIndex)
        );
        assert_eq!(Finger::from_fprintd("left-thumb"), Some(Finger::LeftThumb));
        assert_eq!(Finger::from_fprintd("any"), None);
        assert_eq!(Finger::RightIndex.name(), "right index finger");
    }
}
