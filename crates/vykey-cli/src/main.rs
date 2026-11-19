//! `vy` — terminal client of vykey: a full-screen TUI over the same vault
//! database as the desktop app, plus `vy import` for Bitwarden exports and
//! `vy fingerprint` for fingerprint unlock, `vy passwd` to change a master
//! password.

mod clipboard;
mod fingerprint;
mod import;
mod passwd;
mod tui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vykey_core::Store;

#[derive(Parser)]
#[command(
    name = "vy",
    version,
    about = "vykey password manager — terminal client"
)]
struct Cli {
    /// Vault database [default: $VYKEY_DB_PATH or the vykey data directory]
    #[arg(long, global = true, value_name = "PATH")]
    db: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the interactive terminal UI (default)
    Start,
    /// Import logins and secure notes from a Bitwarden CSV export
    Import {
        /// Bitwarden CSV export
        file: PathBuf,
        /// Vault to import into (required if there are several)
        #[arg(long, value_name = "NAME")]
        vault: Option<String>,
        /// Import only entries from this Bitwarden folder
        #[arg(long, value_name = "NAME")]
        folder: Option<String>,
    },
    /// Change the master password of a vault
    Passwd {
        /// Vault (required if there are several)
        #[arg(long, value_name = "NAME")]
        vault: Option<String>,
    },
    /// Unlock a vault with a fingerprint instead of the master password (Linux, fprintd)
    Fingerprint {
        #[arg(value_enum)]
        action: fingerprint::Action,
        /// Vault (required if there are several; `status` shows all by default)
        #[arg(long, value_name = "NAME")]
        vault: Option<String>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vy: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let path = cli
        .db
        .or_else(vykey_core::paths::default_db_path)
        .ok_or("cannot determine the database path; pass --db")?;
    let store = Store::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    match cli.command.unwrap_or(Command::Start) {
        Command::Start => tui::run(store)?,
        Command::Import {
            file,
            vault,
            folder,
        } => import::run(&store, &file, vault.as_deref(), folder.as_deref())?,
        Command::Passwd { vault } => passwd::run(&store, vault.as_deref())?,
        Command::Fingerprint { action, vault } => {
            fingerprint::run(&store, action, vault.as_deref())?
        }
    }
    Ok(())
}
