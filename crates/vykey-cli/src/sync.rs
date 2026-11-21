//! `vy sync`: connects the database to a vykey sync server and syncs it.
//! The same account and sync state as the desktop app (they live in the
//! database). Folders and entries need the vault key: `vy sync now --vault`
//! asks for the master password; without it only vault records sync.

use clap::Subcommand;
use vykey_core::sync::http::HttpClient;
use vykey_core::sync::proto::Token;
use vykey_core::sync::{self, Report};
use vykey_core::{Store, Vault};
use zeroize::Zeroizing;

use crate::import::pick_vault;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Subcommand)]
pub enum Action {
    /// Create an account on a server and connect this database to it
    Init {
        /// Own server, e.g. https://sync.example.com [default: vykey Cloud,
        /// https://sync.vykey.dev]
        #[arg(long, value_name = "URL")]
        server: Option<String>,
        /// Ask for an invite key (servers with closed registration)
        #[arg(long)]
        invite: bool,
    },
    /// Connect this database to an existing account (asks for its token)
    Join {
        /// Own server, e.g. https://sync.example.com [default: vykey Cloud,
        /// https://sync.vykey.dev]
        #[arg(long, value_name = "URL")]
        server: Option<String>,
    },
    /// Sync now
    Now {
        /// Also sync the folders and entries of this vault (asks for its
        /// master password)
        #[arg(long, value_name = "NAME")]
        vault: Option<String>,
    },
    /// Show the account and the last sync
    Status,
    /// Print the account token (needed to connect another device)
    Token,
    /// Disconnect this database (data stays here and on the server)
    Leave,
}

pub fn run(store: &Store, action: Action) -> Result<()> {
    match action {
        Action::Init { server, invite } => init(store, server_or_cloud(&server), invite),
        Action::Join { server } => join(store, server_or_cloud(&server)),
        Action::Now { vault } => now(store, vault.as_deref()),
        Action::Status => status(store),
        Action::Token => {
            let account = connected(store)?;
            println!("{}", account.token);
            Ok(())
        }
        Action::Leave => {
            connected(store)?;
            store.clear_sync_account()?;
            println!(
                "Disconnected. The data stays here and on the server; reconnect with \
                 `vy sync join` and the account token."
            );
            Ok(())
        }
    }
}

fn server_or_cloud(server: &Option<String>) -> &str {
    server.as_deref().unwrap_or(sync::CLOUD_SERVER)
}

fn connected(store: &Store) -> Result<sync::SyncAccount> {
    store.sync_account()?.ok_or_else(|| {
        "not connected to a sync account; see `vy sync init` or `vy sync join`".into()
    })
}

fn refuse_if_connected(store: &Store) -> Result<()> {
    if let Some(a) = store.sync_account()? {
        return Err(format!(
            "already connected to {}; `vy sync leave` first",
            a.server_url
        )
        .into());
    }
    Ok(())
}

fn init(store: &Store, server: &str, ask_invite: bool) -> Result<()> {
    refuse_if_connected(store)?;
    let client = HttpClient::new(server)?;
    let invite = if ask_invite {
        Some(Zeroizing::new(rpassword::prompt_password("Invite key: ")?))
    } else {
        None
    };
    eprintln!("Creating the account (this can take a few seconds)…");
    let token = client.create_account(invite.as_deref().map(String::as_str))?;
    store.set_sync_account(client.server_url(), &token)?;
    println!(
        "Account created. Its token, needed to connect your other devices:\n\n    {token}\n\n\
         It is the only key to this account: it cannot be recovered, and whoever has it \
         can download your encrypted vaults. Keep it like a password."
    );
    first_sync(store, &client.with_token(&token))
}

fn join(store: &Store, server: &str) -> Result<()> {
    refuse_if_connected(store)?;
    let raw = Zeroizing::new(rpassword::prompt_password("Account token: ")?);
    let token: Token = raw
        .parse()
        .map_err(|_| "this is not a vykey account token")?;
    let client = HttpClient::new(server)?.with_token(&token);
    // Checks the token before anything is stored.
    client.account_info()?;
    store.set_sync_account(client.server_url(), &token)?;
    println!("Connected to {}.", client.server_url());
    first_sync(store, &client)
}

/// Vault records only: contents follow with `vy sync now --vault`.
fn first_sync(store: &Store, client: &HttpClient) -> Result<()> {
    let r = sync::sync(store, None, client)?;
    print_report(&r);
    println!("Run `vy sync now --vault NAME` to sync the entries of a vault.");
    Ok(())
}

fn now(store: &Store, vault: Option<&str>) -> Result<()> {
    let account = connected(store)?;
    let vault = match vault {
        Some(name) => {
            let meta = pick_vault(store, Some(name))?;
            let password = Zeroizing::new(rpassword::prompt_password(format!(
                "Master password for vault \"{}\": ",
                meta.name
            ))?);
            Some(Vault::unlock(meta, &password)?)
        }
        None => None,
    };
    let client = HttpClient::new(&account.server_url)?.with_token(&account.token);
    let r = sync::sync(store, vault.as_ref(), &client)?;
    print_report(&r);
    let waiting = store.sync_inbox_len()?;
    if vault.is_none() && waiting > 0 {
        println!("{waiting} record(s) wait for their vault: pass --vault NAME to sync them.");
    }
    Ok(())
}

fn print_report(r: &Report) {
    println!(
        "Synced: {} received, {} sent, {} conflict(s).",
        r.pulled, r.pushed, r.conflicts
    );
    if r.conflicts > 0 {
        println!(
            "Entries changed on two devices keep the other version as \"… {}\".",
            sync::CONFLICT_SUFFIX
        );
    }
    if r.skipped > 0 {
        println!("{} record(s) could not be read or sent.", r.skipped);
    }
    for name in &r.password_changed {
        println!("The master password of \"{name}\" was changed on another device.");
    }
}

fn status(store: &Store) -> Result<()> {
    let Some(account) = store.sync_account()? else {
        println!("Not connected to a sync account.");
        return Ok(());
    };
    println!("Server:      {}", account.server_url);
    match account.last_synced_at {
        Some(at) => println!("Last sync:   {}", date(at)),
        None => println!("Last sync:   never"),
    }
    let waiting = store.sync_inbox_len()?;
    if waiting > 0 {
        println!("Waiting:     {waiting} record(s) of locked vaults");
    }
    let client = HttpClient::new(&account.server_url)?.with_token(&account.token);
    match client.account_info() {
        Ok(info) => println!(
            "On server:   {} record(s), {} of {} KiB",
            info.records,
            info.bytes.div_ceil(1024),
            info.quota_bytes / 1024
        ),
        Err(e) => println!("On server:   unavailable ({e})"),
    }
    Ok(())
}

fn date(unix: i64) -> String {
    chrono::DateTime::from_timestamp(unix, 0)
        .map(|d| {
            d.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}
