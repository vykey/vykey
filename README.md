<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/vykey-lockup-lilac.png">
    <img src="assets/logo/vykey-lockup-violet.png" alt="vykey" width="320">
  </picture>
</p>

<p align="center">
  <b>Vault Your Keys.</b> No cloud. No account. No trust required.
</p>

<p align="center">
  <a href="https://github.com/vykey/vykey/actions/workflows/ci.yml"><img src="https://github.com/vykey/vykey/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-6A58F0" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/made%20with-Rust-8F81FF" alt="Made with Rust">
</p>

---

**vykey** is a password manager that lives on your computer, not in someone's
cloud. Passwords, cards, 2FA codes and notes are kept in one encrypted file
on your own disk: no account, no subscription, no server, no telemetry.
Open it in a fast native desktop app or right in your terminal.

## Why vykey

- **Yours, offline.** Your vault never leaves your machine. Back it up,
  move it or sync it however you like: it is a single file.
- **Native and light.** Written in Rust with a native UI ([Slint](https://slint.dev)),
  not a browser in disguise. No Electron, no JavaScript, about 30 MB of RAM.
- **Desktop and terminal.** The same vault opens in the desktop app and in
  `vy`, a full-screen terminal client for people who live in a shell.
- **Unlock with a finger.** On Linux, touch the fingerprint reader instead
  of typing the master password, just like `sudo`.
- **Strong, boring crypto.** Argon2id and AES-256-GCM. Every field of every
  entry is encrypted, titles included.

|                                  | vykey | pass | gopass | Bitwarden |
|----------------------------------|:-----:|:----:|:------:|:---------:|
| Works without a cloud or account | ✅ | ✅ | ✅ | ❌ |
| Encryption without GPG setup     | ✅ | ❌ | ❌ | ✅ |
| Built-in 2FA (TOTP) codes        | ✅ | add-on | ✅ | paid plan |
| Entry names encrypted            | ✅ | ❌ | ❌ | ✅ |
| Whole vault in a single file     | ✅ | ❌ | ❌ | ❌ |
| Native desktop app               | ✅ | ❌ | ❌ | Electron |
| Full-screen terminal UI          | ✅ | ❌ | ❌ | ❌ |

<sub>pass and gopass keep one GPG-encrypted file per entry, so entry names
show up as file names. Corrections welcome.</sub>

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
- Sync between devices through a zero-knowledge server (`vykey-server`):
  anonymous accounts, only encrypted data leaves the device

## Install

Builds for Linux, macOS and Windows are on the
[releases page](https://github.com/vykey/vykey/releases).

**macOS.** Open the `.dmg` and drag **vykey** onto **Applications**. The app
is not notarized by Apple yet, so the first launch is blocked with "Apple
could not verify vykey is free of malware". Either:

- open **System Settings → Privacy & Security**, scroll down and click
  **Open Anyway** next to the vykey message, or
- remove the quarantine flag in Terminal:

  ```sh
  xattr -dr com.apple.quarantine /Applications/vykey.app
  ```

The terminal client `vy` is in the same disk image; copy it somewhere on
your `PATH` (e.g. `sudo cp /Volumes/vykey*/vy /usr/local/bin/`) and clear
its quarantine flag the same way.

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

On Linux you need the `fontconfig` and `libxkbcommon` development headers.

Moving over from Bitwarden? `vy import bitwarden.csv`. Coming from kyp, the
Go predecessor of vykey? Your database opens as is: see
[Migrating from kyp](docs/usage.md#migrating-from-kyp).

More in the [user guide](docs/usage.md): terminal shortcuts, fingerprint
unlock, configuration.

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

In the desktop app: Settings → Sync → "Set up…": pick vykey Cloud
(`sync.vykey.dev`, the default) or your own server, then create an account (the token is shown once, to be saved) or paste the
token of an existing one. On a new device, the first screen offers
"Restore from sync" next to creating a vault: paste the token, the vaults
arrive and open with their master passwords. All vaults of the database sync; folders and
entries of a vault sync while it is unlocked. Entries changed on two
devices at once keep the other version as "… (conflict)". From the
terminal:

```sh
vy sync init                    # new account on vykey Cloud
vy sync init --server https://sync.example.com [--invite]  # …on your own server
vy sync join [--server URL]     # existing account: asks for the token
vy sync now --vault Work    # asks for the master password, syncs its entries
vy sync status | token | leave
```

The server:

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

Next on the list:

- **Packages and releases** for Linux (AppImage / Flatpak), then macOS and
  Windows
- **Export** to an open format, so you can always take your data elsewhere
- **Touch ID and Windows Hello** unlock
- **Trash and password history**, to undo a deletion or a password change
- **Custom fields and attachments**
- **More imports**: KeePass, 1Password, browsers
- **Browser autofill** and **sync** between your own devices, without a
  vendor cloud

Ideas and bug reports are welcome in [issues](https://github.com/vykey/vykey/issues).

## For developers

A Cargo workspace of four crates:

```
crates/vykey-core       vault format, crypto, storage, TOTP, audit (no UI)
crates/vykey-desktop    desktop app (Slint), binary `vykey`
crates/vykey-cli        terminal client (ratatui), binary `vy`
crates/vykey-biometric  fingerprint unlock (fprintd + kernel keyring)
```

```sh
cargo run -p vykey-desktop
cargo test --workspace
```

Build details, CI checks and how to add a translation are in
[docs/development.md](docs/development.md); the file format is in
[docs/vault-format.md](docs/vault-format.md).

## License

[MIT](LICENSE). Bundled fonts (Manrope, JetBrains Mono): SIL OFL 1.1. Icons:
Font Awesome Free (CC BY 4.0) and Lucide (ISC).
