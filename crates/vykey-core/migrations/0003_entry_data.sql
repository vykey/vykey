-- Schema v3: per-entry encrypted JSON (`data`) holding the title, 2FA
-- issuer, entry kind (login / card / note), favourite flag and card fields.
-- Plaintext `title` / `totp_issuer` of existing rows are moved into `data`
-- on unlock (Store::upgrade_entries), when the key is available; afterwards
-- `title` is '' and `totp_issuer` is NULL.

ALTER TABLE entries ADD COLUMN data BLOB;
