<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/vykey-lockup-lilac.png">
    <img src="assets/logo/vykey-lockup-violet.png" alt="vykey" width="320">
  </picture>
</p>

# vykey

**vykey** (*Vault Your Keys*) is a local password manager written in Rust: a
native desktop app ([Slint](https://slint.dev), no web view, no JS) and a
terminal client, `vy`, working on the same encrypted vault file.

Formerly kyp; successor of the Go app
([stickpro/kyp](https://github.com/stickpro/kyp)): opens its databases and
upgrades them in place — see [docs/vault-format.md](docs/vault-format.md) and
[Migrating from kyp](#migrating-from-kyp).

## Features

- Several vaults in one database, each with its own master password:
  create, switch, rename, change the master password, delete
- Logins, payment cards (Luhn check, payment system, expiry warnings) and
  secure notes; favourites and coloured folders
- Everything except timestamps is encrypted, titles included
- Unlock / create vault, entry list with search and sorting, entry details
  with copy, reveal and live 2FA (TOTP) codes
- Create, edit and delete entries; password generator with strength meter
- Offline security audit: weak, reused and stale passwords, 2FA coverage
- Settings: light, dark or system theme; interface language (English,
  Russian; follows the system by default); auto-lock delay
- Auto-lock on inactivity (5 min by default), clipboard auto-clear after 30 s
- Fingerprint unlock on Linux (fprintd), opt-in per vault — see below
- Terminal client `vy`: full-screen TUI and Bitwarden CSV import

## Layout

```
crates/vykey-core      vault format, crypto, storage, TOTP, audit (no UI)
crates/vykey-biometric fingerprint unlock: fprintd + kernel keyring (Linux)
crates/vykey-desktop   Slint desktop app, binary `vykey` (ui/, src/, translations/)
crates/vykey-cli       terminal client, binary `vy` (ratatui)
crates/vykey-sync-proto wire types of the sync protocol (client and server)
crates/vykey-server    sync server, binary `vykey-server`
docs/                  vault format and sync protocol specs
packaging/             macOS bundle, server systemd unit
assets/logo/           logo, wordmark, lockup and app icon (PNG)
testdata/              fixture databases created by the Go app
```

## Build

```sh
cargo run -p vykey-desktop             # debug
cargo build -p vykey-desktop --release # → target/release/vykey
cargo build -p vykey-cli --release     # → target/release/vy
cargo build -p vykey-server --release  # → target/release/vykey-server
cargo test --workspace
```

Linux needs `fontconfig` and `libxkbcommon` development headers.

## Terminal client

```sh
vy                                  # open the TUI (same as `vy start`)
vy --db ~/vault.db                  # another database
vy import bitwarden.csv             # import a Bitwarden CSV export
vy import bitwarden.csv --vault Work --folder Work
vy fingerprint enable --vault Work  # fingerprint unlock (see below)
vy fingerprint status
vy passwd --vault Work              # change the master password
```

`vy import` asks for the master password (it is never a command-line
argument), imports logins and secure notes, and turns Bitwarden folders into
vykey folders.

| Screen  | Keys |
|---------|------|
| vaults  | `↑`/`↓` pick a vault, `enter` unlock, `n` new vault, `q` quit; `esc` on the password prompt returns here; `ctrl+f` retries the fingerprint |
| list    | `↑`/`↓` (`j`/`k`) move, `enter` open, `/` filter, `n` new entry, `v` switch vault, `q` quit |
| details | `u` copy username, `c` copy password (card: number), `t` copy TOTP, `v` copy CVV, `p`/`space` show/hide, `f` favourite, `e` edit, `d` delete, `esc` back |
| form    | `tab`/`shift+tab` next/previous field, `←`/`→` entry type (new entries), `ctrl+g` generate password, `ctrl+p` show/hide, `ctrl+s` save, `esc` back |
| any     | `ctrl+l` lock, `ctrl+c` quit |

The terminal client is English only.

## Fingerprint unlock (Linux)

With a reader supported by [fprintd](https://fprint.freedesktop.org/) and an
enrolled finger (`fprintd-enroll`), a vault can be opened like `sudo` with
`pam_fprintd`: the unlock screen shows "Place your right index finger on the
fingerprint reader" while the password field keeps working. Three attempts,
30 s timeout; then "Use fingerprint" (desktop) or `ctrl+f` (TUI) retries.

Turn it on per vault in the desktop app (Settings → Security) or with
`vy fingerprint enable`. Each time the master password opens such a vault,
its data key goes into the kernel keyring (`keyctl`, user keyring, key
`vykey:<vault id>`) for 24 hours. After a matching finger vykey reads the key
back and opens the vault without Argon2; that does not extend the 24 hours.
So the master password is needed:

- after every restart (the kernel keyring lives in memory only);
- at least once a day (the kernel drops the key, even if vykey is not
  running).

These limits are fixed. Nothing to install besides fprintd: no GNOME
Keyring or KWallet. The master password itself is never stored, and
changing it keeps fingerprint unlock working.

What this protects against, and what not:

- The fingerprint only gates vykey's own UI. Any program of your user can
  read the key while it lives, so malware in your session can open the vault
  without a finger for up to a day. Unlike Touch ID or Windows Hello there is
  no hardware binding. The key never touches the disk.
- The key alone is not enough: it decrypts the database file, which must be
  stolen as well.
- Deleting a vault removes its key. A key that no longer opens the vault
  (database replaced, vault re-created) is detected and removed; the next
  unlock asks for the password.
- The reader is claimed while vykey waits, so `sudo` in another terminal
  falls back to its password prompt until the check ends.

## Sync server

`vykey-server` keeps encrypted copies of vaults so several devices can
sync; it never sees their contents. Accounts are anonymous: creating one
returns a token (`vy1-…`), the only credential. Protocol, data layout and
what the server can see: [docs/sync-protocol.md](docs/sync-protocol.md).
The clients do not sync yet; this is the server side.

```sh
vykey-server                          # serve on 127.0.0.1:8470, ./vykey-server.redb
vykey-server --db /var/lib/vykey-server/sync.redb --backup-dir /var/lib/vykey-server/backups
vykey-server account new              # (server stopped) create an account, print the token
VYKEY_SERVER_INVITE_KEY=… vykey-server  # clients with the key may create accounts
vykey-server --open-registration      # anyone may create an account
vykey-server --open-registration --pow 24  # …after ~1 s of proof of work
vykey-server stats | gc | backup FILE # (server stopped)
vykey-server --help
```

Registration is closed by default: accounts come from `account new`, or
from clients that send the invite key, unless the server runs with
`--open-registration`. It speaks plain HTTP: run it behind a TLS reverse proxy with
`--trust-proxy` (systemd unit in [packaging/server/](packaging/server/)). One
redb file holds everything; tombstones older than 90 days are collected
daily, and `--backup-dir` writes a daily consistent copy (7 kept).
Built on redb (storage) and hyper (HTTP/1.1, on tokio); the protocol
logic itself is synchronous and transport-independent (`api.rs`).

## Configuration

| Variable             | Default                          |
|----------------------|----------------------------------|
| `VYKEY_DB_PATH`      | `$XDG_DATA_HOME/vykey/vykey.db` (or `~/.local/share/vykey/vykey.db`; macOS: `~/Library/Application Support/vykey/vykey.db`; Windows: `%APPDATA%\vykey\vykey.db`) |
| `VYKEY_LOCK_TIMEOUT` | unset: the delay from Settings (5 min by default). Overrides it when set; Go duration syntax (`30s`, `1h30m`), `0` disables |
| `SLINT_BACKEND`      | software renderer (~30 MB RSS); `winit-femtovg` renders with OpenGL (smoother on very large windows, but loads GPU drivers: ~270 MB) |

Preferences chosen in the app (theme, language, auto-lock) are stored in
`$XDG_CONFIG_HOME/vykey/settings.json` (`~/.config/vykey/settings.json`; on
macOS and Windows in the same directory as the database). The terminal
client reads the same file:

```json
{ "theme": "system", "language": null, "lock_timeout": 300 }
```

`lock_timeout` is in seconds, `0` = never. Values other than the presets
(1, 5, 15, 30 min, 1 h) can be set by hand and show up in the list.

## Migrating from kyp

The Go app stored its vault in `kyp/kyp.db`; vykey uses `vykey/vykey.db`.
Copy the file to the new location (close the Go app first):

```sh
# Linux
mkdir -p ~/.local/share/vykey
cp ~/.local/share/kyp/kyp.db ~/.local/share/vykey/vykey.db

# macOS
mkdir -p ~/Library/Application\ Support/vykey
cp ~/Library/Application\ Support/kyp/kyp.db ~/Library/Application\ Support/vykey/vykey.db
```

```powershell
# Windows
New-Item -ItemType Directory -Force "$env:APPDATA\vykey"
Copy-Item "$env:APPDATA\kyp\kyp.db" "$env:APPDATA\vykey\vykey.db"
```

If you used `KYP_DB_PATH` or `db_path` in the Go app's config, copy that file
instead. vykey upgrades the copy on first unlock, and the Go app must not be
used on an upgraded database (it would show encrypted titles as empty), so
keep the original as a backup until you no longer need kyp. Pointing
`VYKEY_DB_PATH` at the Go app's file also works, but upgrades it in place.

## Translations

English is the source language: UI strings are written as `@tr("...")` in
`crates/vykey-desktop/ui/*.slint`, and texts composed in Rust go through the `Tr`
global in `ui/i18n.slint`. Translations are gettext catalogues bundled into
the binary at build time. To add a language:

1. Create `crates/vykey-desktop/translations/<code>/LC_MESSAGES/vykey-desktop.po`
   (copy the Russian one and replace every `msgstr`; set `Plural-Forms`).
2. Add `("<code>", "<name in that language>")` to `LANGUAGES` in
   `crates/vykey-desktop/src/lib.rs`.

`cargo test -p vykey-desktop` fails if a catalogue misses a UI string or keeps
one the UI no longer uses.

## License

MIT. Bundled fonts: SIL OFL 1.1 (`crates/vykey-desktop/ui/fonts/`). Icons: Font
Awesome Free, CC BY 4.0 (`crates/vykey-desktop/ui/icons/`).
