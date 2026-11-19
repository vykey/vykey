//! App preferences, stored as plain JSON next to (not inside) the vault
//! database: they are needed before any vault is unlocked and hold nothing
//! secret. Default location: [`crate::paths::settings_path`].

use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeMode,
    /// Interface language code ("en", "ru", …); `None` follows the system
    /// locale. Codes the app does not know fall back to English.
    pub language: Option<String>,
    /// Auto-lock after this many seconds without activity; 0 = never.
    /// `VYKEY_LOCK_TIMEOUT` overrides it (see [`Settings::lock_timeout`]).
    pub lock_timeout: u64,
    /// Ids of vaults with fingerprint unlock on. Their keys live in the OS
    /// for a limited time (see `vykey_biometric`); this only says to keep
    /// them after each password unlock.
    pub fingerprint_vaults: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: ThemeMode::default(),
            language: None,
            lock_timeout: DEFAULT_LOCK_TIMEOUT.as_secs(),
            fingerprint_vaults: Vec::new(),
        }
    }
}

impl Settings {
    pub fn fingerprint(&self, vault_id: &str) -> bool {
        self.fingerprint_vaults.iter().any(|id| id == vault_id)
    }

    pub fn set_fingerprint(&mut self, vault_id: &str, on: bool) {
        self.fingerprint_vaults.retain(|id| id != vault_id);
        if on {
            self.fingerprint_vaults.push(vault_id.to_owned());
        }
    }

    /// Effective auto-lock delay: `VYKEY_LOCK_TIMEOUT` if set and valid,
    /// else the saved one. `None` = never lock.
    pub fn lock_timeout(&self) -> Option<Duration> {
        lock_timeout_from_env().unwrap_or_else(|| {
            (self.lock_timeout > 0).then(|| Duration::from_secs(self.lock_timeout))
        })
    }

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

/// Environment variable overriding the saved auto-lock delay (Go duration
/// syntax, "0" = never).
pub const LOCK_TIMEOUT_ENV: &str = "VYKEY_LOCK_TIMEOUT";

/// Auto-lock delay of a fresh install.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Auto-lock delay from `VYKEY_LOCK_TIMEOUT`: `None` = not set or not
/// parsable (the saved setting applies), `Some(None)` = never lock ("0").
pub fn lock_timeout_from_env() -> Option<Option<Duration>> {
    let d = parse_duration(&env::var(LOCK_TIMEOUT_ENV).ok()?)?;
    Some((!d.is_zero()).then_some(d))
}

/// Parses Go-style durations as in `VYKEY_LOCK_TIMEOUT`: "30s", "5m", "1h30m", "0".
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s == "0" {
        return Some(Duration::ZERO);
    }
    let mut total = Duration::ZERO;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    let mut any = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let value: f64 = num.parse().ok()?;
        num.clear();
        let unit = match c {
            'h' => 3600.0,
            'm' if chars.peek() == Some(&'s') => {
                chars.next();
                0.001
            }
            'm' => 60.0,
            's' => 1.0,
            _ => return None,
        };
        total += Duration::from_secs_f64(value * unit);
        any = true;
    }
    (any && num.is_empty()).then_some(total)
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
            lock_timeout: 900,
            fingerprint_vaults: vec!["v1".into()],
        };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        assert!(s.fingerprint("v1") && !s.fingerprint("v2"));
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
        assert_eq!(Settings::load(&path).lock_timeout, 300);
    }

    #[test]
    fn saved_lock_timeout() {
        // Only meaningful without VYKEY_LOCK_TIMEOUT in the environment.
        if env::var_os(LOCK_TIMEOUT_ENV).is_some() {
            return;
        }
        let mut s = Settings::default();
        assert_eq!(s.lock_timeout(), Some(DEFAULT_LOCK_TIMEOUT));
        s.lock_timeout = 60;
        assert_eq!(s.lock_timeout(), Some(Duration::from_secs(60)));
        s.lock_timeout = 0;
        assert_eq!(s.lock_timeout(), None);
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("1h30m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("0"), Some(Duration::ZERO));
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("5"), None);
    }
}
