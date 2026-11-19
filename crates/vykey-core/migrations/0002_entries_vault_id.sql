-- Schema v2: entries belong to a vault. Entries left NULL are claimed on
-- unlock (Store::claim_entries).

ALTER TABLE entries ADD COLUMN vault_id TEXT REFERENCES vault_meta (id) ON DELETE CASCADE;

CREATE INDEX idx_entries_vault_id ON entries (vault_id, deleted_at);

UPDATE entries
    SET vault_id = (SELECT id FROM vault_meta LIMIT 1)
    WHERE vault_id IS NULL AND (SELECT COUNT(*) FROM vault_meta) = 1;
