-- Schema v6: sync bookkeeping (docs/sync-protocol.md, docs/vault-format.md).
--
-- Every vault, folder and entry row records the server revision it is
-- based on (sync_rev, 0 = never on a server), a per-record edit counter
-- (version, carried in the sync blob), the time of its last local change
-- of any kind (modified_at, unix seconds: unlike updated_at it also moves
-- for favourites and folder moves) and whether it has a change the server
-- has not seen (dirty). Existing rows start dirty, so connecting an account
-- uploads everything.

ALTER TABLE vault_meta ADD COLUMN sync_rev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vault_meta ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE vault_meta ADD COLUMN dirty INTEGER NOT NULL DEFAULT 1;

ALTER TABLE folders ADD COLUMN sync_rev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE folders ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE folders ADD COLUMN modified_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE folders ADD COLUMN dirty INTEGER NOT NULL DEFAULT 1;
UPDATE folders SET modified_at = updated_at;

ALTER TABLE entries ADD COLUMN sync_rev INTEGER NOT NULL DEFAULT 0;
ALTER TABLE entries ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE entries ADD COLUMN modified_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE entries ADD COLUMN dirty INTEGER NOT NULL DEFAULT 1;
UPDATE entries SET modified_at = updated_at;

-- Local deletions the server still has to learn about. Only rows that were
-- on a server (sync_rev > 0) leave one.
CREATE TABLE sync_tombstones (
    id       TEXT    PRIMARY KEY,
    kind     TEXT    NOT NULL,   -- vault, folder, entry
    vault_id TEXT    NOT NULL,
    sync_rev INTEGER NOT NULL
);

-- Server records of vaults that were locked when they arrived (folders and
-- entries need the vault key); applied on unlock.
CREATE TABLE sync_inbox (
    id       TEXT    PRIMARY KEY,
    kind     TEXT    NOT NULL,
    vault_id TEXT    NOT NULL,
    rev      INTEGER NOT NULL,
    deleted  INTEGER NOT NULL,
    blob     BLOB    NOT NULL
);

CREATE INDEX idx_sync_inbox_vault_id ON sync_inbox (vault_id);

-- The sync account of this database (at most one row). The token is the
-- account's only credential; it is as sensitive as the salts and verifiers
-- already in this file.
CREATE TABLE sync_account (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    server_url     TEXT    NOT NULL,
    token          TEXT    NOT NULL,
    device_id      TEXT    NOT NULL,
    last_rev       INTEGER NOT NULL DEFAULT 0,
    last_synced_at INTEGER
);
