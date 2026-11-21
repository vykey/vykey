//! `vykey-server`: command line.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use vykey_server::api::{self, Api, Config};
use vykey_server::http::{self, Options};
use vykey_server::pow::PowConfig;
use vykey_server::store::{Quota, RedbStore, Storage};
use vykey_sync_proto::pow;

const HELP: &str = "\
vykey-server — zero-knowledge sync server for vykey

USAGE:
    vykey-server [serve] [OPTIONS]   run the server (default)
    vykey-server account new         create an account, print its token
    vykey-server stats               totals over all accounts
    vykey-server gc                  remove old tombstones now
    vykey-server backup <FILE>       write a consistent copy of the database

`account new`, `stats`, `gc` and `backup` open the database themselves, so
the server must be stopped; a running server does gc and backups on its own
(--backup-dir).

OPTIONS:
    --db <FILE>             database file [env VYKEY_SERVER_DB]
                            [default: vykey-server.redb]
    --listen <ADDR>         address to listen on [env VYKEY_SERVER_LISTEN]
                            [default: 127.0.0.1:8470]
    --max-connections <N>   open connections at most; more wait [default: 512]
    --trust-proxy           take the client address from X-Forwarded-For
    --open-registration     anyone may create an account; without it,
                            POST /v1/account needs the invite key
                            [env VYKEY_SERVER_INVITE_KEY]
    --pow <BITS>            open registration needs proof of work of BITS
                            leading zero bits (24 ≈ 1 s on a desktop);
                            rises under load, invited clients skip it
    --pow-per-hour <N>      registrations per hour before the proof of work
                            gets harder [default: 100]
    --quota-mb <N>          per-account storage quota [default: 10]
    --quota-records <N>     per-account record quota [default: 20000]
    --poll-after <SECS>     how often clients poll [default: 300]
    --tombstone-days <N>    keep tombstones this long [default: 90]
    --backup-dir <DIR>      daily backups into DIR
    --backup-keep <N>       backups to keep in --backup-dir [default: 7]
    --quiet                 no request log
    -h, --help              this help
    -V, --version           version

Plain HTTP only: put a TLS reverse proxy in front.";

struct Args {
    command: Vec<String>,
    db: PathBuf,
    listen: String,
    max_connections: usize,
    trust_proxy: bool,
    open_registration: bool,
    pow_bits: Option<u8>,
    pow_per_hour: u32,
    quota_mb: u64,
    quota_records: u64,
    poll_after: u32,
    tombstone_days: u64,
    backup_dir: Option<PathBuf>,
    backup_keep: usize,
    quiet: bool,
}

enum Parsed {
    Run(Args),
    Exit(String),
}

fn parse_args(mut it: impl Iterator<Item = String>) -> Result<Parsed, String> {
    let mut a = Args {
        command: Vec::new(),
        db: std::env::var_os("VYKEY_SERVER_DB")
            .map_or_else(|| PathBuf::from("vykey-server.redb"), PathBuf::from),
        listen: std::env::var("VYKEY_SERVER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8470".into()),
        max_connections: 512,
        trust_proxy: false,
        open_registration: false,
        pow_bits: None,
        pow_per_hour: 100,
        quota_mb: 10,
        quota_records: 20_000,
        poll_after: 300,
        tombstone_days: 90,
        backup_dir: None,
        backup_keep: 7,
        quiet: false,
    };
    while let Some(arg) = it.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_owned(), Some(v.to_owned())),
            _ => (arg.clone(), None),
        };
        let mut value = || {
            inline
                .clone()
                .or_else(|| it.next())
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        fn num<T: std::str::FromStr>(flag: &str, v: String) -> Result<T, String> {
            v.parse().map_err(|_| format!("{flag}: not a number: {v}"))
        }
        match flag.as_str() {
            "--db" => a.db = value()?.into(),
            "--listen" => a.listen = value()?,
            "--max-connections" => a.max_connections = num(&flag, value()?)?,
            "--trust-proxy" => a.trust_proxy = true,
            "--open-registration" => a.open_registration = true,
            "--pow" => a.pow_bits = Some(num(&flag, value()?)?),
            "--pow-per-hour" => a.pow_per_hour = num(&flag, value()?)?,
            "--quota-mb" => a.quota_mb = num(&flag, value()?)?,
            "--quota-records" => a.quota_records = num(&flag, value()?)?,
            "--poll-after" => a.poll_after = num(&flag, value()?)?,
            "--tombstone-days" => a.tombstone_days = num(&flag, value()?)?,
            "--backup-dir" => a.backup_dir = Some(value()?.into()),
            "--backup-keep" => a.backup_keep = num(&flag, value()?)?,
            "--quiet" => a.quiet = true,
            "-h" | "--help" => return Ok(Parsed::Exit(HELP.into())),
            "-V" | "--version" => {
                return Ok(Parsed::Exit(format!(
                    "vykey-server {}",
                    env!("CARGO_PKG_VERSION")
                )));
            }
            f if f.starts_with('-') => return Err(format!("unknown option {f}; see --help")),
            _ => a.command.push(arg),
        }
    }
    if a.max_connections == 0 {
        return Err("--max-connections must be at least 1".into());
    }
    if a.pow_bits
        .is_some_and(|b| !(1..=pow::MAX_DIFFICULTY).contains(&b))
    {
        return Err(format!("--pow takes 1 to {} bits", pow::MAX_DIFFICULTY));
    }
    Ok(Parsed::Run(a))
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Parsed::Run(a)) => a,
        Ok(Parsed::Exit(text)) => {
            println!("{text}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("vykey-server: {e}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vykey-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    let command: Vec<&str> = args.command.iter().map(String::as_str).collect();
    let open = || RedbStore::open(&args.db).map_err(|e| format!("{}: {e}", args.db.display()));
    match command.as_slice() {
        [] | ["serve"] => serve(&args, open()?),
        ["account", "new"] => {
            let token = api::create_account(&open()?, api::unix_now()).map_err(|e| e.message)?;
            println!("{token}");
            Ok(())
        }
        ["stats"] => {
            let s = open()?.stats().map_err(|e| e.to_string())?;
            println!(
                "accounts: {}\nrecords:  {}\nbytes:    {}",
                s.accounts, s.records, s.bytes
            );
            Ok(())
        }
        ["gc"] => {
            let n = gc(&open()?, args.tombstone_days)?;
            println!("removed {n} tombstones");
            Ok(())
        }
        ["backup", out] => {
            open()?
                .backup(Path::new(out))
                .map_err(|e| format!("backup: {e}"))?;
            println!("written {out}");
            Ok(())
        }
        _ => Err(format!(
            "unknown command `{}`; see --help",
            args.command.join(" ")
        )),
    }
}

fn serve(args: &Args, store: RedbStore) -> Result<(), String> {
    let invite_key = std::env::var("VYKEY_SERVER_INVITE_KEY")
        .ok()
        .filter(|k| !k.trim().is_empty());
    if !args.open_registration && invite_key.is_none() {
        eprintln!(
            "vykey-server: registration is closed: create accounts with \
             `vykey-server account new` while the server is stopped, set \
             VYKEY_SERVER_INVITE_KEY, or pass --open-registration"
        );
    }
    if args.pow_bits.is_some() && !args.open_registration {
        eprintln!(
            "vykey-server: --pow applies to open registration only; \
             invited clients skip it"
        );
    }
    let cfg = Config {
        open_registration: args.open_registration,
        invite_key,
        quota: Quota {
            bytes: args.quota_mb.saturating_mul(1024 * 1024),
            records: args.quota_records,
        },
        poll_after: args.poll_after,
        pow: args.pow_bits.map(|base_bits| PowConfig {
            base_bits,
            target_per_hour: args.pow_per_hour,
        }),
        ..Config::default()
    };

    let store = Arc::new(store);
    {
        // Weak, so the database closes cleanly when the server stops.
        let store = Arc::downgrade(&store);
        let days = args.tombstone_days;
        let backups = args
            .backup_dir
            .clone()
            .map(|d| (d, args.backup_keep.max(1)));
        std::thread::spawn(move || maintenance(&store, days, backups));
    }
    let api = Arc::new(Api::new(store, cfg));
    let opts = Options {
        trust_proxy: args.trust_proxy,
        log: !args.quiet,
        max_connections: args.max_connections,
        ..Options::default()
    };

    let rt = http::runtime().map_err(|e| format!("cannot start the runtime: {e}"))?;
    rt.block_on(async {
        let listener = TcpListener::bind(&args.listen)
            .await
            .map_err(|e| format!("cannot listen on {}: {e}", args.listen))?;
        eprintln!(
            "vykey-server {} listening on http://{}",
            env!("CARGO_PKG_VERSION"),
            listener.local_addr().map_err(|e| e.to_string())?
        );
        http::serve(listener, api, opts, http::shutdown_signal()).await;
        Ok::<_, String>(())
    })?;
    Ok(())
}

/// Once a minute after start, then daily: gc and, if asked, a backup.
fn maintenance(
    store: &std::sync::Weak<RedbStore>,
    tombstone_days: u64,
    backups: Option<(PathBuf, usize)>,
) {
    std::thread::sleep(Duration::from_secs(60));
    loop {
        let Some(store) = store.upgrade() else {
            return; // the server stopped
        };
        match gc(&store, tombstone_days) {
            Ok(0) => {}
            Ok(n) => eprintln!("vykey-server: gc removed {n} tombstones"),
            Err(e) => eprintln!("vykey-server: gc: {e}"),
        }
        if let Some((dir, keep)) = &backups
            && let Err(e) = backup_into(&store, dir, *keep)
        {
            eprintln!("vykey-server: backup: {e}");
        }
        drop(store);
        std::thread::sleep(Duration::from_secs(86_400));
    }
}

fn gc(store: &RedbStore, tombstone_days: u64) -> Result<u64, String> {
    let cutoff = api::unix_now().saturating_sub(tombstone_days.saturating_mul(86_400));
    store.gc(cutoff).map_err(|e| e.to_string())
}

/// Writes `DIR/sync-<unix time>.redb` and deletes all but the newest
/// `keep` of them.
fn backup_into(store: &RedbStore, dir: &Path, keep: usize) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(format!("sync-{}.redb", api::unix_now()));
    store.backup(&path).map_err(|e| e.to_string())?;
    let mut old: Vec<PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| is_backup_name(p))
        .collect();
    // Same-width unix times sort as strings until the year 2286.
    old.sort();
    let excess = old.len().saturating_sub(keep);
    for p in &old[..excess] {
        if let Err(e) = std::fs::remove_file(p) {
            eprintln!("vykey-server: cannot remove {}: {e}", p.display());
        }
    }
    Ok(())
}

fn is_backup_name(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.strip_prefix("sync-"))
        .and_then(|n| n.strip_suffix(".redb"))
        .is_some_and(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Parsed, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn options_both_forms() {
        let Ok(Parsed::Run(a)) = parse(&[
            "serve",
            "--listen",
            "0.0.0.0:1",
            "--quota-mb=5",
            "--open-registration",
            "--backup-dir=/b",
        ]) else {
            panic!()
        };
        assert_eq!(a.command, ["serve"]);
        assert_eq!(a.listen, "0.0.0.0:1");
        assert_eq!(a.quota_mb, 5);
        assert!(a.open_registration);
        assert_eq!(a.backup_dir.as_deref(), Some(Path::new("/b")));
    }

    #[test]
    fn registration_is_closed_unless_asked() {
        let Ok(Parsed::Run(a)) = parse(&[]) else {
            panic!()
        };
        assert!(!a.open_registration);
    }

    #[test]
    fn bad_options() {
        assert!(parse(&["--max-connections"]).is_err());
        assert!(parse(&["--max-connections", "x"]).is_err());
        assert!(parse(&["--max-connections", "0"]).is_err());
        assert!(parse(&["--wat"]).is_err());
        assert!(parse(&["--pow", "0"]).is_err());
        assert!(parse(&["--pow", "33"]).is_err());
        assert!(matches!(parse(&["--pow=22"]), Ok(Parsed::Run(a)) if a.pow_bits == Some(22)));
        assert!(matches!(parse(&["--help"]), Ok(Parsed::Exit(_))));
    }

    #[test]
    fn backup_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbStore::open(&dir.path().join("db.redb")).unwrap();
        let backups = dir.path().join("backups");
        std::fs::create_dir(&backups).unwrap();
        for t in ["1000000001", "1000000002", "1000000003"] {
            std::fs::write(backups.join(format!("sync-{t}.redb")), b"").unwrap();
        }
        std::fs::write(backups.join("notes.txt"), b"").unwrap();
        backup_into(&store, &backups, 2).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&backups)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names.len(), 3, "{names:?}");
        assert_eq!(names[0], "notes.txt");
        assert_eq!(names[1], "sync-1000000003.redb");
        assert!(RedbStore::open(&backups.join(&names[2])).is_ok());
    }

    #[test]
    fn backup_names() {
        assert!(is_backup_name(Path::new("/x/sync-1800000000.redb")));
        assert!(!is_backup_name(Path::new("/x/sync-.redb")));
        assert!(!is_backup_name(Path::new("/x/sync-12a.redb")));
        assert!(!is_backup_name(Path::new("/x/db.redb")));
    }
}
