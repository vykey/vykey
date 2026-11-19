//! App preferences, stored as plain JSON next to (not inside) the vault
//! database: they are needed before any vault is unlocked and hold nothing
//! secret. Default location: [`crate::paths::settings_path`].

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Colour scheme of the interface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThemeMode {
    /// Follow the operating system.
    #[default]
    System,
    Light,
    Dark,
}

/// Every field has a default, so a missing, partial or newer file still loads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeMode,
    /// Interface language code ("en", "ru", …); `None` follows the system
    /// locale. Codes the app does not know fall back to English.
    pub language: Option<String>,
}

impl Settings {
    /// Reads `path`. A missing or unreadable file yields the defaults: bad
    /// preferences must never keep the app from starting.
    pub fn load(path: &Path) -> Self {
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Writes `path` atomically (temp file + rename), creating its directory.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, json)?;
        fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/settings.json");
        assert_eq!(Settings::load(&path), Settings::default());

        let s = Settings {
            theme: ThemeMode::Dark,
            language: Some("ru".into()),
        };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains(r#""theme": "dark""#)
        );
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains(r#""language": "ru""#)
        );
    }

    #[test]
    fn tolerant_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");

        fs::write(&path, "not json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());

        fs::write(&path, r#"{"theme":"light","future":1}"#).unwrap();
        assert_eq!(Settings::load(&path).theme, ThemeMode::Light);

        fs::write(&path, "{}").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
    }
}
