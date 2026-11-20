# Using vykey

- [Terminal client](#terminal-client)
- [Fingerprint unlock (Linux)](#fingerprint-unlock-linux)
- [Configuration](#configuration)
- [Migrating from kyp](#migrating-from-kyp)

## Terminal client

```sh
vy                                  # open the TUI (same as `vy start`)
vy --db ~/vault.db                  # another database
vy import bitwarden.csv             # import a Bitwarden CSV export
vy import bitwarden.csv --vault Work --folder Work
vy passwd --vault Work              # change the master password
vy fingerprint enable --vault Work  # fingerprint unlock (see below)
vy fingerprint status
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

## Configuration

| Variable             | Default                          |
|----------------------|----------------------------------|
| `VYKEY_DB_PATH`      | `$XDG_DATA_HOME/vykey/vykey.db` (or `~/.local/share/vykey/vykey.db`; macOS: `~/Library/Application Support/vykey/vykey.db`; Windows: `%APPDATA%\vykey\vykey.db`) |
| `VYKEY_LOCK_TIMEOUT` | unset: the delay from Settings (5 min by default). Overrides it when set; Go duration syntax (`30s`, `1h30m`), `0` disables |
| `SLINT_BACKEND`      | software renderer (~30 MB RSS); `winit-femtovg` renders with OpenGL (smoother on very large windows, but loads GPU drivers: ~270 MB) |

Preferences chosen in the app (theme, language, auto-lock, fingerprint
unlock) are stored in `$XDG_CONFIG_HOME/vykey/settings.json`
(`~/.config/vykey/settings.json`; on macOS and Windows in the same directory
as the database). The terminal client reads the same file:

```json
{ "theme": "system", "language": null, "lock_timeout": 300, "fingerprint_vaults": [] }
```

`lock_timeout` is in seconds, `0` = never. Values other than the presets
(1, 5, 15, 30 min, 1 h) can be set by hand and show up in the list.

Before upgrading the schema of an existing database, vykey copies it to
`<database>.bak-v<old version>`.

## Migrating from kyp

vykey was called kyp and succeeds the Go app
([stickpro/kyp](https://github.com/stickpro/kyp)). It opens the Go app's
databases and upgrades them in place (see [vault-format.md](vault-format.md)).

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
