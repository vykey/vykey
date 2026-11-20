//! Default database location: `$VYKEY_DB_PATH`, else
//! `<data dir>/vykey/vykey.db`. Databases of the Go app (`kyp/kyp.db`) are
//! not picked up automatically: copy the file to the new path (see
//! docs/usage.md, "Migrating from kyp").

use std::env;
use std::path::PathBuf;

/// Environment variable overriding the database path.
pub const DB_PATH_ENV: &str = "VYKEY_DB_PATH";

/// `$VYKEY_DB_PATH`, otherwise `<data dir>/vykey/vykey.db`.
pub fn default_db_path() -> Option<PathBuf> {
    if let Some(p) = env::var_os(DB_PATH_ENV).filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    Some(user_data_dir()?.join("vykey").join("vykey.db"))
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
