# vykey vault format

vykey owns this format. It started as the format of the Go implementation
([stickpro/kyp](https://github.com/stickpro/kyp)); databases created by the Go
app (schema v1) are upgraded in place when vykey opens them. The Go app is
not developed further and must not be used on a database vykey has upgraded
(it would show encrypted titles as empty).

Source of truth: `crates/vykey-core` (`crypto.rs`, `store.rs`, `schema.rs`,
`migrations/*.sql`).

## Location

1. `$VYKEY_DB_PATH`, if set.
2. Otherwise `<data dir>/vykey/vykey.db` (created if missing). The data dir is
   - Linux: `$XDG_DATA_HOME`, else `~/.local/share`
   - macOS: `~/Library/Application Support`
   - Windows: `%APPDATA%`

The parent directory is created with mode `0700`.

The Go app keeps its database at `<data dir>/kyp/kyp.db` (or `$KYP_DB_PATH`
/ `db_path` in its YAML config). vykey does not look there; to migrate, copy
that file to the path above.

## Key derivation

| Parameter   | Value              |
|-------------|--------------------|
| Algorithm   | Argon2id, v0x13    |
| Time cost   | 1                  |
| Memory      | 65536 KiB (64 MiB) |
| Parallelism | 4                  |
| Key length  | 32 bytes           |
| Salt        | 16 random bytes, stored in `vault_meta.salt` |

Password is passed as raw UTF-8 bytes, no normalization.

## Keys (v5)

Two keys:

- **password key** (KEK) = Argon2id(password, `vault_meta.salt`);
- **data key**: encrypts the verifier, entries and folders.

`vault_meta.wrapped_key = encrypt(data key, password key)` (32-byte
plaintext, layout below). Vaults created since v5 get a random data key.

If `wrapped_key` is `NULL` (every vault created before v5, until its password
is changed), the password key itself is the data key, as in v1–v4 and the Go
app. Changing the password then wraps that same key, so a migrated vault is
never re-encrypted.

Changing the master password writes a new salt and `wrapped_key` and
nothing else: entries and a fingerprint unlock key stay valid. The data key
does not rotate, so a copy of the database from before the change still
opens with the old password.

## Encryption

AES-256-GCM, random 12-byte nonce per value, no associated data.

```
blob = nonce (12 bytes) || ciphertext || tag (16 bytes)
```

Plaintext is the UTF-8 string. A `NULL` column means "field not set";
an empty string is encrypted like any other value.

## Password verifier

`vault_meta.verifier = encrypt("verification", data key)`. A password is
correct iff `wrapped_key` decrypts with the password key (if set) and the
verifier decrypts with the resulting data key to the ASCII string
`verification`.

## Schema

Migrations live in `crates/vykey-core/migrations/` and are recorded in the
`goose_db_version` table (kept from the Go app, which used
[goose](https://github.com/pressly/goose)). Current version: **5**. vykey
refuses a database with a newer version than it knows.

Before migrating an existing database, vykey copies it to
`<path>.bak-v<old version>` (`VACUUM INTO`, mode `0600`); an existing backup
of that version is kept.

| Version | Migration | Change |
|---------|-----------|--------|
| 1 | `0001_initial.sql` | tables below |
| 2 | `0002_entries_vault_id.sql` | `entries.vault_id` + index `idx_entries_vault_id (vault_id, deleted_at)`; with a single vault all entries are assigned to it |
| 3 | `0003_entry_data.sql` | `entries.data`: encrypted JSON (see below); plaintext `title` / `totp_issuer` move into it on unlock |
| 4 | `0004_folders.sql` | `folders` table + index `idx_folders_vault_id`; entries refer to a folder inside `entries.data` |
| 5 | `0005_wrapped_key.sql` | `vault_meta.wrapped_key` (see "Keys"); existing rows stay `NULL` |

### `vault_meta`

| Column       | Type    | Notes                     |
|--------------|---------|---------------------------|
| `id`         | TEXT PK | UUID v4                   |
| `name`       | TEXT    | plaintext, used to select a vault on unlock |
| `salt`       | BLOB    | 16 bytes                  |
| `verifier`   | BLOB    | see above                 |
| `wrapped_key`| BLOB    | v5: data key under the password key; `NULL` = password key is the data key |
| `created_at` | INTEGER | unix seconds              |
| `updated_at` | INTEGER | unix seconds              |

### `entries`

| Column           | Type    | Encrypted | Notes                          |
|------------------|---------|-----------|--------------------------------|
| `id`             | TEXT PK | no        | UUID v4                        |
| `title`          | TEXT    | no        | v1/v2 plaintext; `''` since v3 (moved into `data`) |
| `username`       | BLOB    | yes       | nullable                       |
| `password`       | BLOB    | yes       | nullable                       |
| `url`            | BLOB    | yes       | nullable                       |
| `notes`          | BLOB    | yes       | nullable                       |
| `totp_secret`    | BLOB    | yes       | nullable, base32 secret        |
| `totp_issuer`    | TEXT    | no        | v1/v2 plaintext; `NULL` since v3 (moved into `data`) |
| `totp_algorithm` | TEXT    | no        | default `SHA1`                 |
| `totp_digits`    | INTEGER | no        | default `6`                    |
| `totp_period`    | INTEGER | no        | default `30`                   |
| `created_at`     | INTEGER | no        | unix seconds                   |
| `updated_at`     | INTEGER | no        | unix seconds                   |
| `deleted_at`     | INTEGER | no        | `NULL` = alive; listings skip non-NULL rows |
| `vault_id`       | TEXT    | no        | v2: `vault_meta.id`, `ON DELETE CASCADE`; `NULL` = unassigned |
| `data`           | BLOB    | yes       | v3: JSON, see "Entry data" |

### Entry data (`entries.data`, v3)

AES-GCM blob (same layout as the other fields) of a UTF-8 JSON object.
Unknown keys are ignored; missing keys take the defaults.

| Key           | Type   | Default   | Notes |
|---------------|--------|-----------|-------|
| `title`       | string | `""`      | |
| `totp_issuer` | string | absent    | |
| `kind`        | string | `"login"` | `login`, `card` or `note` |
| `favorite`    | bool   | `false`   | toggling it does not change `updated_at` |
| `card`        | object | absent    | `kind = card` only: `holder`, `number` (digits), `expiry` (`MM/YY`), `cvv`, `pin`; empty strings omitted |
| `folder`      | string | absent    | v4: `folders.id` of the same vault; an id of a deleted folder reads as "no folder". Moving an entry does not change `updated_at` |

A note is an entry with `kind = note`; its text is the `notes` column.
Logins use `username`, `password`, `url`, `totp_secret`.

Upgrade: rows with `data IS NULL` (written before v3) are read from the
plaintext `title` / `totp_issuer` columns. On unlock vykey encrypts them into
`data` and clears those columns (`Store::upgrade_entries`), after claiming
unassigned entries (see "Multiple vaults").

### `folders` (v4)

| Column       | Type    | Encrypted | Notes |
|--------------|---------|-----------|-------|
| `id`         | TEXT PK | no        | UUID v4 |
| `vault_id`   | TEXT    | no        | `vault_meta.id`, `ON DELETE CASCADE` |
| `data`       | BLOB    | yes       | JSON `{"name": "...", "color": "#RRGGBB"}`; `color` may be absent |
| `position`   | INTEGER | no        | display order; new folders go last |
| `created_at` | INTEGER | no        | unix seconds |
| `updated_at` | INTEGER | no        | unix seconds |

Folder names are unique per vault, case-insensitively (checked after
decryption). Membership is stored only in the entries' encrypted `data`, so
the database does not show which entries share a folder. Deleting a folder
re-encrypts its entries without `folder` and keeps them.

### `sync_state`

`device_id TEXT PK`, `server_url TEXT`, `last_synced_at INTEGER`. Reserved
for sync, unused by the GUI.

## Behaviour notes

- Deleting an entry removes the row (`DELETE`), in both implementations;
  `deleted_at` is only honoured when listing.
- Updating an entry: Go keeps `updated_at` unchanged, Rust sets it to now.
  Both are valid for the other side.
- Unset optional fields are stored as `NULL`; the Rust app also maps empty
  strings to `NULL`.
- TOTP codes use HMAC-SHA1 in both apps; `totp_algorithm` is stored but not
  used yet.

## Multiple vaults

Since v2 every entry carries `vault_id`, and all reads and writes are scoped
to the open vault (`WHERE vault_id = ?`), including update and delete by id.

Entries with `vault_id IS NULL` come from v1 databases with several vaults.
On unlock, vykey **claims** them:

- an entry whose every encrypted field decrypts with the vault key is
  assigned to that vault (AES-GCM authentication makes this unambiguous);
- an entry without encrypted fields is assigned only if the database has a
  single vault; otherwise it stays unassigned and invisible.

Deleting a vault removes its `vault_meta` row, its entries and its folders
(cascade, plus an explicit delete). SQLite runs with `foreign_keys = ON`.

An older vykey-rs refuses a database with a newer schema (`SchemaTooNew`).

## Fingerprint unlock (outside the database)

Opt-in per vault (`crates/vykey-biometric`). The 32-byte master key (the
Argon2id output above, not the password) is stored raw in the user's Secret
Service keyring, default collection:

| Field      | Value |
|------------|-------|
| Label      | `vykey vault “<name>”` (not updated on rename) |
| Attributes | `application` = `vykey`, `vault-id` = `vault_meta.id` |
| Secret     | 32 bytes, content type `application/octet-stream` |

A key is accepted only if it decrypts `vault_meta.verifier`; otherwise the
item is deleted. Deleting a vault deletes its item. Nothing in the database
records whether fingerprint unlock is on.

## Known issues

- Entry timestamps, the number of entries and folders per vault and vault
  names are visible without a master password.

## Compatibility tests

`crates/vykey-core/tests/go_compat.rs` holds known-answer vectors produced by
the Go code (key, verifier, ciphertext) and reads two databases created by
the Go app:

- `testdata/go-fixture.db` — schema v1, vault `fixture` / `correct horse`
  (also exercises the v1 → v2 migration);
- `testdata/go-fixture-v2.db` — schema v2, vaults `Работа` / `correct horse`
  and `Личное` / `battery staple`.

The reverse direction is checked by hand:
`cargo test -p vykey-core -- --ignored write_rust_fixture` writes
`target/rust-fixture.db` (vaults `rust` / `correct horse` and `second` /
`battery staple`) for the Go app to open.
