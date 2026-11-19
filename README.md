# vykey

**vykey** (*Vault Your Keys*) is a native desktop password manager, written in
Rust with [Slint](https://slint.dev). No web view, no JS.

Formerly kyp; successor of the Go app
([stickpro/kyp](https://github.com/stickpro/kyp)): opens its databases and upgrades them in place — see
[docs/vault-format.md](docs/vault-format.md).

## Features

- Several vaults in one database, each with its own master password:
  create, switch, rename, delete
- Logins, payment cards (Luhn check, payment system, expiry warnings) and
  secure notes; favourites and coloured folders
- Everything except timestamps is encrypted, titles included
- Unlock / create vault, entry list with search and sorting, entry details
  with copy, reveal and live 2FA (TOTP) codes
- Create, edit and delete entries; password generator with strength meter
- Offline security audit: weak, reused and stale passwords, 2FA coverage
- Settings: light, dark or system theme; interface language (English,
  Russian; follows the system by default)
- Auto-lock on inactivity, clipboard auto-clear after 30 s

## Layout

```
crates/vykey-core      vault format, crypto, storage, TOTP, audit (no UI)
crates/vykey-desktop   Slint desktop app, binary `vykey` (ui/, src/, translations/)
docs/                  vault format spec
testdata/              fixture databases created by the Go app
```

## Build

```sh
cargo run -p vykey-desktop             # debug
cargo build -p vykey-desktop --release # → target/release/vykey
cargo test --workspace
```

Linux needs `fontconfig` and `libxkbcommon` development headers.

## Configuration

| Variable             | Default                          |
|----------------------|----------------------------------|
| `VYKEY_DB_PATH`      | `$XDG_DATA_HOME/vykey/vykey.db` (or `~/.local/share/vykey/vykey.db`); the legacy `KYP_DB_PATH` and an existing `kyp/kyp.db` are still picked up |
| `VYKEY_LOCK_TIMEOUT` | `5m`; Go duration syntax, `0` disables |
| `SLINT_BACKEND`      | software renderer (~30 MB RSS); `winit-femtovg` renders with OpenGL (smoother on very large windows, but loads GPU drivers: ~270 MB) |

Preferences chosen in the app (theme) are stored in
`$XDG_CONFIG_HOME/vykey/settings.json` (`~/.config/vykey/settings.json`; on
macOS and Windows in the same directory as the database).

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
