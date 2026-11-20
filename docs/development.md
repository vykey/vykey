# Developing vykey

## Layout

```
crates/vykey-core      vault format, crypto, storage, TOTP, audit (no UI)
crates/vykey-biometric fingerprint unlock: fprintd + kernel keyring (Linux)
crates/vykey-desktop   Slint desktop app, binary `vykey` (ui/, src/, translations/)
crates/vykey-cli       terminal client, binary `vy` (ratatui)
docs/                  vault format spec, usage, this file
assets/logo/           logo, wordmark, lockup and app icon
testdata/              fixture databases created by the Go app
```

## Build and test

```sh
cargo run -p vykey-desktop             # debug
cargo build -p vykey-desktop --release # → target/release/vykey
cargo build -p vykey-cli --release     # → target/release/vy
cargo test --workspace
```

Linux needs `fontconfig` and `libxkbcommon` development headers. CI runs
`cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`
and `cargo test --workspace`; `unsafe` code is denied in the workspace.

The on-disk format is specified in [vault-format.md](vault-format.md); keep
it in sync with `crates/vykey-core` (`crypto.rs`, `store.rs`, `schema.rs`,
`migrations/`). `tests/go_compat.rs` checks compatibility with databases
written by the Go app.

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
