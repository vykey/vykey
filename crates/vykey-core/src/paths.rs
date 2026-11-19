//! Default database location.
//!
//! vykey was called kyp before, and the Go implementation still uses that
//! name: `pkg/storage/path.go` reads `$KYP_DB_PATH`, else
//! `<data dir>/kyp/kyp.db`. Both legacy locations are still honoured so
//! existing vaults keep opening after the rename.

use std::env;
use std::path::PathBuf;

/// Environment variable overriding the database path.
pub const DB_PATH_ENV: &str = "VYKEY_DB_PATH";

/// Pre-rename name of [`DB_PATH_ENV`], also read by the Go implementation.
pub const LEGACY_DB_PATH_ENV: &str = "KYP_DB_PATH";

/// Resolves the database path, first match wins:
/// 1. `$VYKEY_DB_PATH`;
/// 2. `$KYP_DB_PATH` (legacy);
/// 3. `<data dir>/vykey/vykey.db`, if it exists;
/// 4. `<data dir>/kyp/kyp.db`, if it exists (legacy / Go app);
/// 5. `<data dir>/vykey/vykey.db` (created on open).
pub fn default_db_path() -> Option<PathBuf> {
    for var in [DB_PATH_ENV, LEGACY_DB_PATH_ENV] {
        if let Some(p) = env::var_os(var).filter(|p| !p.is_empty()) {
            return Some(PathBuf::from(p));
        }
    }
    let data = user_data_dir()?;
    let path = data.join("vykey").join("vykey.db");
    let legacy = data.join("kyp").join("kyp.db");
    if !path.exists() && legacy.exists() {
        return Some(legacy);
    }
    Some(path)
}

/// `<config dir>/vykey/settings.json` (see [`crate::settings`]).
pub fn settings_path() -> Option<PathBuf> {
    Some(user_config_dir()?.join("vykey").join("settings.json"))
}

/// Linux: `$XDG_CONFIG_HOME` or `~/.config`; macOS and Windows: same as the
/// data dir.
fn user_config_dir() -> Option<PathBuf> {
    if cfg!(target_os = "macos") || cfg!(windows) {
        return user_data_dir();
    }
    if let Some(xdg) = env::var_os("XDG_CONFIG_HOME").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(xdg));
    }
    Some(env::home_dir()?.join(".config"))
}

/// Linux: `$XDG_DATA_HOME` or `~/.local/share`;
/// macOS: `~/Library/Application Support`; Windows: `%APPDATA%`.
fn user_data_dir() -> Option<PathBuf> {
    if let Some(xdg) = env::var_os("XDG_DATA_HOME").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(xdg));
    }
    let home = env::home_dir()?;
    if cfg!(target_os = "macos") {
        return Some(home.join("Library").join("Application Support"));
    }
    if cfg!(windows)
        && let Some(appdata) = env::var_os("APPDATA")
    {
        return Some(PathBuf::from(appdata));
    }
    Some(home.join(".local").join("share"))
}
