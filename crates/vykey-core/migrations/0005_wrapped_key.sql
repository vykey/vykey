-- Schema v5: key wrapping. Entries are encrypted with a data key; the
-- master password only protects that key, so changing the password re-wraps
-- 32 bytes instead of re-encrypting the vault.
--
-- wrapped_key = AES-GCM(data key) under Argon2id(password, salt).
-- NULL (vaults created before v5, until their password is changed): the
-- Argon2id output itself is the data key, as in v1-v4.

ALTER TABLE vault_meta ADD COLUMN wrapped_key BLOB;
