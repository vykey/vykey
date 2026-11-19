//! Clipboard with auto-clear: a copied secret is removed after
//! [`CLEAR_AFTER`] and on exit, unless something else was copied since.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// Same delay as the desktop app.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Clipboard {
    /// Created on first use: on X11/Wayland the owner must stay alive for
    /// the content to remain pasteable.
    inner: Option<arboard::Clipboard>,
    copied: Option<(Instant, Zeroizing<String>)>,
}

impl Clipboard {
    pub fn copy(&mut self, text: &str) -> Result<(), String> {
        if self.inner.is_none() {
            self.inner = Some(arboard::Clipboard::new().map_err(|e| e.to_string())?);
        }
        let cb = self.inner.as_mut().expect("created above");
        cb.set_text(text.to_owned()).map_err(|e| e.to_string())?;
        self.copied = Some((Instant::now(), Zeroizing::new(text.to_owned())));
        Ok(())
    }

    /// Clears the clipboard once the copied secret has expired.
    pub fn tick(&mut self) {
        if self
            .copied
            .as_ref()
            .is_some_and(|(at, _)| at.elapsed() >= CLEAR_AFTER)
        {
            self.clear_if_ours();
        }
    }

    /// Clears the clipboard if it still holds what we copied.
    pub fn clear_if_ours(&mut self) {
        if let Some((_, value)) = self.copied.take()
            && let Some(cb) = self.inner.as_mut()
            && cb.get_text().ok().as_deref() == Some(value.as_str())
        {
            let _ = cb.clear();
        }
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        self.clear_if_ours();
    }
}
