-- Schema v4: folders. Name and colour are encrypted JSON in `data`; an
-- entry refers to its folder by id inside its own encrypted `data`, so the
-- database does not reveal which entries share a folder.

CREATE TABLE folders (
    id          TEXT    PRIMARY KEY,
    vault_id    TEXT    NOT NULL REFERENCES vault_meta (id) ON DELETE CASCADE,
    data        BLOB    NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_folders_vault_id ON folders (vault_id);
