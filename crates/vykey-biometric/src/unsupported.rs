//! Platforms without fingerprint unlock yet (macOS Touch ID and Windows
//! Hello are planned): reports "unsupported" everywhere.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::{Availability, Error, Event, Result, Verdict};

#[derive(Clone)]
pub struct Cancel;

impl Cancel {
    pub fn new() -> Self {
        Self
    }

    pub fn cancel(&self) {}

    pub fn is_cancelled(&self) -> bool {
        false
    }
}

pub fn availability() -> Availability {
    Availability::Unsupported
}

pub fn verify(_: &Cancel, _: Duration, _: impl FnMut(Event)) -> Result<Verdict> {
    Err(Error::Unsupported)
}

pub fn has_secret(_: &str) -> bool {
    false
}

pub fn store_secret(_: &str, _: &[u8], _: Duration) -> Result<()> {
    Err(Error::Unsupported)
}

pub fn load_secret(_: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Ok(None)
}

pub fn delete_secret(_: &str) -> Result<()> {
    Ok(())
}
