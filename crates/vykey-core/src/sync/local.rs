//! Sync bookkeeping in the local database (schema v6).

use rusqlite::{OptionalExtension, params};
use vykey_sync_proto::{Kind, Record, Token};

use super::record::{EntryRecord, FolderRecord, Stamp, VaultRecord};
use crate::error::{Error, Result};
use crate::store::{
    ENTRY_COLUMNS, EntryData, RawEntry, Store, Vault, VaultMeta, meta_from_row, now,
};
use crate::{Entry, EntryInput, Folder};

/// The sync account of a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAccount {
    pub server_url: String,
    pub token: Token,
    /// Random id of this database, used to order simultaneous edits.
    pub device_id: String,
    /// Server revision this database is up to date with.
    pub last_rev: u64,
    /// Unix seconds of the last successful sync.
    pub last_synced_at: Option<i64>,
}

/// Sync columns of one vault, folder or entry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct State {
    pub sync_rev: u64,
    pub version: u64,
    pub modified_at: i64,
    pub dirty: bool,
}

pub(crate) fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Vault => "vault",
        Kind::Folder => "folder",
        Kind::Entry => "entry",
    }
}

fn kind_from_name(s: &str) -> Result<Kind> {
    match s {
        "vault" => Ok(Kind::Vault),
        "folder" => Ok(Kind::Folder),
        "entry" => Ok(Kind::Entry),
        _ => Err(Error::Data(format!("unknown record kind {s:?}"))),
    }
}

fn table(kind: Kind) -> &'static str {
    match kind {
        Kind::Vault => "vault_meta",
        Kind::Folder => "folders",
        Kind::Entry => "entries",
    }
}

fn rev(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn sql_rev(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// A pending local deletion.
pub(crate) struct Tombstone {
    pub id: String,
    pub kind: Kind,
    pub vault_id: String,
    pub sync_rev: u64,
}

impl Store {
    // ---------- account ----------

    pub fn sync_account(&self) -> Result<Option<SyncAccount>> {
        let row = self
            .conn
            .query_row(
                "SELECT server_url, token, device_id, last_rev, last_synced_at \
                 FROM sync_account WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|(server_url, token, device_id, last_rev, last_synced_at)| {
            Ok(SyncAccount {
                server_url,
                token: token
                    .parse()
                    .map_err(|_| Error::Data("stored sync token is malformed".into()))?,
                device_id,
                last_rev: rev(last_rev),
                last_synced_at,
            })
        })
        .transpose()
    }

    /// Connects this database to an account: everything will be uploaded
    /// (or merged with what the account already has) on the next sync.
    pub fn set_sync_account(&self, server_url: &str, token: &Token) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        reset_sync_state(&tx)?;
        tx.execute(
            "INSERT INTO sync_account (id, server_url, token, device_id, last_rev) \
             VALUES (1, ?1, ?2, ?3, 0)",
            params![
                server_url,
                token.to_string(),
                uuid::Uuid::new_v4().to_string()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Disconnects from the account. Local data stays; the copy on the
    /// server is not touched.
    pub fn clear_sync_account(&self) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        reset_sync_state(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn set_last_rev(&self, last_rev: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_account SET last_rev = ?1 WHERE id = 1",
            [sql_rev(last_rev)],
        )?;
        Ok(())
    }

    pub(crate) fn set_synced_now(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_account SET last_synced_at = ?1 WHERE id = 1",
            [now()],
        )?;
        Ok(())
    }

    // ---------- row state ----------

    pub(crate) fn state(&self, kind: Kind, id: &str) -> Result<Option<(State, String)>> {
        let (modified, vault) = match kind {
            Kind::Vault => ("updated_at", "id"),
            _ => ("modified_at", "vault_id"),
        };
        Ok(self
            .conn
            .query_row(
                &format!(
                    "SELECT sync_rev, version, {modified}, dirty, {vault} FROM {} WHERE id = ?1",
                    table(kind)
                ),
                [id],
                |r| {
                    Ok((
                        State {
                            sync_rev: rev(r.get(0)?),
                            version: rev(r.get(1)?),
                            modified_at: r.get(2)?,
                            dirty: r.get::<_, i64>(3)? != 0,
                        },
                        r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    ))
                },
            )
            .optional()?)
    }

    /// Sets the sync columns of a row; `version` and `dirty` only when given.
    pub(crate) fn mark(
        &self,
        kind: Kind,
        id: &str,
        sync_rev: u64,
        version: Option<u64>,
        dirty: Option<bool>,
    ) -> Result<()> {
        self.conn.execute(
            &format!(
                "UPDATE {} SET sync_rev = ?2, version = COALESCE(?3, version), \
                 dirty = COALESCE(?4, dirty) WHERE id = ?1",
                table(kind)
            ),
            params![
                id,
                sql_rev(sync_rev),
                version.map(sql_rev),
                dirty.map(i64::from)
            ],
        )?;
        Ok(())
    }

    /// After a successful push: the server has `version` under `rev`. The
    /// row stays dirty if it changed while the push was in flight.
    pub(crate) fn ack(&self, kind: Kind, id: &str, rev: u64, version: u64) -> Result<()> {
        self.conn.execute(
            &format!(
                "UPDATE {} SET sync_rev = ?2, \
                 dirty = CASE WHEN version = ?3 THEN 0 ELSE dirty END WHERE id = ?1",
                table(kind)
            ),
            params![id, sql_rev(rev), sql_rev(version)],
        )?;
        Ok(())
    }

    /// Deletes a row because the server deleted it (no tombstone).
    pub(crate) fn drop_local(&self, kind: Kind, id: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        if kind == Kind::Vault {
            tx.execute("DELETE FROM entries WHERE vault_id = ?1", [id])?;
            tx.execute("DELETE FROM folders WHERE vault_id = ?1", [id])?;
            tx.execute("DELETE FROM sync_inbox WHERE vault_id = ?1", [id])?;
            tx.execute(
                "DELETE FROM sync_tombstones WHERE vault_id = ?1 AND kind != 'vault'",
                [id],
            )?;
        }
        tx.execute(&format!("DELETE FROM {} WHERE id = ?1", table(kind)), [id])?;
        tx.commit()?;
        Ok(())
    }

    /// Ids of rows of `kind` that were on the server (for a full resync).
    pub(crate) fn synced_ids(&self, kind: Kind, vault_id: Option<&str>) -> Result<Vec<String>> {
        let mut sql = format!("SELECT id FROM {} WHERE sync_rev > 0", table(kind));
        if vault_id.is_some() {
            sql.push_str(" AND vault_id = ?1");
        }
        let mut stmt = self.conn.prepare(&sql)?;
        let rows: rusqlite::Result<Vec<String>> = match vault_id {
            Some(v) => stmt.query_map([v], |r| r.get(0))?.collect(),
            None => stmt.query_map([], |r| r.get(0))?.collect(),
        };
        Ok(rows?)
    }

    // ---------- vaults ----------

    pub(crate) fn vault_by_id(&self, id: &str) -> Result<Option<VaultMeta>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, salt, verifier, created_at, updated_at, wrapped_key \
                 FROM vault_meta WHERE id = ?1",
                [id],
                meta_from_row,
            )
            .optional()?)
    }

    pub(crate) fn dirty_vaults(&self) -> Result<Vec<(VaultMeta, State)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, salt, verifier, created_at, updated_at, wrapped_key, \
             sync_rev, version FROM vault_meta WHERE dirty = 1",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                meta_from_row(r)?,
                State {
                    sync_rev: rev(r.get(7)?),
                    version: rev(r.get(8)?),
                    modified_at: r.get(5)?,
                    dirty: true,
                },
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Stores a vault record from the server. A name taken by another
    /// local vault gets a suffix (and the row stays dirty, so the rename
    /// reaches the server). Returns the name used.
    pub(crate) fn put_vault(&self, id: &str, v: &VaultRecord, rev: u64) -> Result<String> {
        let mut name = v.name.clone();
        let mut n = 2;
        while let Ok(other) = self.vault_meta(&name) {
            if other.id == id {
                break;
            }
            name = format!("{} ({n})", v.name);
            n += 1;
        }
        let renamed = name != v.name;
        self.conn.execute(
            "INSERT INTO vault_meta (id, name, salt, verifier, wrapped_key, created_at, \
             updated_at, sync_rev, version, dirty) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, salt = excluded.salt, \
             verifier = excluded.verifier, wrapped_key = excluded.wrapped_key, \
             created_at = excluded.created_at, updated_at = excluded.updated_at, \
             sync_rev = excluded.sync_rev, version = excluded.version, dirty = excluded.dirty",
            params![
                id,
                name,
                v.salt,
                v.verifier,
                v.wrapped_key,
                v.created_at,
                v.updated_at,
                sql_rev(rev),
                sql_rev(v.version + u64::from(renamed)),
                i64::from(renamed),
            ],
        )?;
        Ok(name)
    }

    // ---------- folders and entries ----------

    pub(crate) fn dirty_folders(&self, vault: &Vault) -> Result<Vec<(Folder, State)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sync_rev, version, modified_at FROM folders \
             WHERE vault_id = ?1 AND dirty = 1",
        )?;
        let states: Vec<(String, State)> = stmt
            .query_map([&vault.meta.id], |r| {
                Ok((
                    r.get(0)?,
                    State {
                        sync_rev: rev(r.get(1)?),
                        version: rev(r.get(2)?),
                        modified_at: r.get(3)?,
                        dirty: true,
                    },
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        if states.is_empty() {
            return Ok(Vec::new());
        }
        let folders = self.list_folders(vault)?;
        Ok(states
            .into_iter()
            .filter_map(|(id, st)| folders.iter().find(|f| f.id == id).map(|f| (f.clone(), st)))
            .collect())
    }

    pub(crate) fn dirty_entries(&self, vault: &Vault) -> Result<Vec<(Entry, State)>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ENTRY_COLUMNS}, sync_rev, version, modified_at FROM entries \
             WHERE vault_id = ?1 AND dirty = 1 AND deleted_at IS NULL"
        ))?;
        let rows = stmt
            .query_map([&vault.meta.id], |r| {
                Ok((
                    RawEntry::from_row(r)?,
                    State {
                        sync_rev: rev(r.get(14)?),
                        version: rev(r.get(15)?),
                        modified_at: r.get(16)?,
                        dirty: true,
                    },
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(raw, st)| Ok((raw.decrypt(vault)?, st)))
            .collect()
    }

    pub(crate) fn put_folder(
        &self,
        vault: &Vault,
        id: &str,
        f: &FolderRecord,
        rev: u64,
        dirty: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO folders (id, vault_id, data, position, created_at, updated_at, \
             modified_at, sync_rev, version, dirty) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT(id) DO UPDATE SET data = excluded.data, position = excluded.position, \
             created_at = excluded.created_at, updated_at = excluded.updated_at, \
             modified_at = excluded.modified_at, sync_rev = excluded.sync_rev, \
             version = excluded.version, dirty = excluded.dirty \
             WHERE folders.vault_id = excluded.vault_id",
            params![
                id,
                vault.meta.id,
                Store::seal_folder(vault, &f.name, &f.color)?,
                f.position,
                f.created_at,
                f.updated_at,
                f.stamp.modified_at,
                sql_rev(rev),
                sql_rev(f.stamp.version),
                i64::from(dirty),
            ],
        )?;
        Ok(())
    }

    pub(crate) fn put_entry(
        &self,
        vault: &Vault,
        id: &str,
        e: &EntryRecord,
        rev: u64,
        dirty: bool,
    ) -> Result<()> {
        let data = EntryData {
            title: e.title.clone(),
            totp_issuer: e.totp_issuer.clone(),
            kind: e.kind,
            favorite: e.favorite,
            card: e.card.clone(),
            folder: e.folder.clone(),
        };
        self.conn.execute(
            "INSERT INTO entries (id, title, username, password, url, notes, totp_secret, \
             totp_issuer, totp_algorithm, totp_digits, totp_period, created_at, updated_at, \
             deleted_at, vault_id, data, modified_at, sync_rev, version, dirty) \
             VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?8, ?9, ?10, ?11, NULL, ?12, ?13, \
                     ?14, ?15, ?16, ?17) \
             ON CONFLICT(id) DO UPDATE SET title = '', username = excluded.username, \
             password = excluded.password, url = excluded.url, notes = excluded.notes, \
             totp_secret = excluded.totp_secret, totp_issuer = NULL, \
             totp_algorithm = excluded.totp_algorithm, totp_digits = excluded.totp_digits, \
             totp_period = excluded.totp_period, created_at = excluded.created_at, \
             updated_at = excluded.updated_at, deleted_at = NULL, data = excluded.data, \
             modified_at = excluded.modified_at, sync_rev = excluded.sync_rev, \
             version = excluded.version, dirty = excluded.dirty \
             WHERE entries.vault_id = excluded.vault_id",
            params![
                id,
                vault.seal(e.username.as_deref())?,
                vault.seal(e.password.as_deref())?,
                vault.seal(e.url.as_deref())?,
                vault.seal(e.notes.as_deref())?,
                vault.seal(e.totp_secret.as_deref())?,
                e.totp_algorithm,
                e.totp_digits,
                e.totp_period,
                e.created_at,
                e.updated_at,
                vault.meta.id,
                vault.seal_data(&data)?,
                e.stamp.modified_at,
                sql_rev(rev),
                sql_rev(e.stamp.version),
                i64::from(dirty),
            ],
        )?;
        Ok(())
    }

    /// Saves the losing side of a conflict as a new entry, so no secret is
    /// lost silently. Returns its id.
    pub(crate) fn conflict_copy(
        &self,
        vault: &Vault,
        e: &EntryRecord,
        suffix: &str,
    ) -> Result<String> {
        let folder = e.folder.clone().filter(|f| {
            self.list_folders(vault)
                .is_ok_and(|fs| fs.iter().any(|x| &x.id == f))
        });
        let input = EntryInput {
            kind: e.kind,
            favorite: e.favorite,
            title: format!("{} {suffix}", e.title).trim().to_owned(),
            username: e.username.clone(),
            password: e.password.clone(),
            url: e.url.clone(),
            notes: e.notes.clone(),
            card: e.card.clone(),
            folder,
            totp_secret: e.totp_secret.clone(),
            totp_issuer: e.totp_issuer.clone(),
        };
        self.create_entry(vault, &input)
    }

    // ---------- tombstones ----------

    pub(crate) fn tombstones(&self) -> Result<Vec<Tombstone>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, kind, vault_id, sync_rev FROM sync_tombstones")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, kind, vault_id, sync_rev)| {
                Ok(Tombstone {
                    id,
                    kind: kind_from_name(&kind)?,
                    vault_id,
                    sync_rev: rev(sync_rev),
                })
            })
            .collect()
    }

    pub(crate) fn tombstone(&self, id: &str) -> Result<Option<u64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT sync_rev FROM sync_tombstones WHERE id = ?1",
                [id],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(rev))
    }

    pub(crate) fn set_tombstone_rev(&self, id: &str, sync_rev: u64) -> Result<()> {
        self.conn.execute(
            "UPDATE sync_tombstones SET sync_rev = ?2 WHERE id = ?1",
            params![id, sql_rev(sync_rev)],
        )?;
        Ok(())
    }

    pub(crate) fn drop_tombstone(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sync_tombstones WHERE id = ?1", [id])?;
        Ok(())
    }

    // ---------- inbox ----------

    /// Keeps a record of a locked vault until it is unlocked (only the
    /// newest revision of each record).
    pub(crate) fn inbox_put(&self, r: &Record) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_inbox (id, kind, vault_id, rev, deleted, blob) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
             ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, vault_id = excluded.vault_id, \
             rev = excluded.rev, deleted = excluded.deleted, blob = excluded.blob \
             WHERE excluded.rev > sync_inbox.rev",
            params![
                r.id.to_string(),
                kind_name(r.kind),
                r.vault_id.to_string(),
                sql_rev(r.rev),
                i64::from(r.deleted),
                r.blob,
            ],
        )?;
        Ok(())
    }

    /// The waiting records of a vault, oldest first. Cleared with
    /// [`Store::inbox_clear`] once applied, so a failure loses nothing.
    pub(crate) fn inbox_list(&self, vault_id: &str) -> Result<Vec<Record>> {
        let rows = {
            let mut stmt = self.conn.prepare(
                "SELECT id, kind, vault_id, rev, deleted, blob FROM sync_inbox \
                 WHERE vault_id = ?1 ORDER BY rev",
            )?;
            stmt.query_map([vault_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, Vec<u8>>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        rows.into_iter()
            .filter_map(|(id, kind, vault, rev_, deleted, blob)| {
                Some(Ok(Record {
                    id: id.parse().ok()?,
                    kind: match kind_from_name(&kind) {
                        Ok(k) => k,
                        Err(e) => return Some(Err(e)),
                    },
                    vault_id: vault.parse().ok()?,
                    rev: rev(rev_),
                    deleted: deleted != 0,
                    blob,
                }))
            })
            .collect()
    }

    pub(crate) fn inbox_drop(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sync_inbox WHERE id = ?1", [id])?;
        Ok(())
    }

    pub(crate) fn inbox_clear(&self, vault_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM sync_inbox WHERE vault_id = ?1", [vault_id])?;
        Ok(())
    }

    /// Records waiting for a vault to be unlocked.
    pub fn sync_inbox_len(&self) -> Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM sync_inbox", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}

/// Forgets every server revision: rows become dirty again, tombstones and
/// the inbox are dropped, the account is removed.
fn reset_sync_state(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "DELETE FROM sync_account; DELETE FROM sync_tombstones; DELETE FROM sync_inbox; \
         UPDATE vault_meta SET sync_rev = 0, dirty = 1; \
         UPDATE folders SET sync_rev = 0, dirty = 1; \
         UPDATE entries SET sync_rev = 0, dirty = 1;",
    )?;
    Ok(())
}

/// The sync record of a decrypted entry.
pub(crate) fn entry_record(e: &Entry, st: &State, device: &str) -> EntryRecord {
    EntryRecord {
        title: e.title.clone(),
        kind: e.kind,
        favorite: e.favorite,
        folder: e.folder.clone(),
        card: e.card.clone(),
        username: e.username.clone(),
        password: e.password.clone(),
        url: e.url.clone(),
        notes: e.notes.clone(),
        totp_secret: e.totp_secret.clone(),
        totp_issuer: e.totp_issuer.clone(),
        totp_algorithm: e.totp_algorithm.clone(),
        totp_digits: e.totp_digits,
        totp_period: e.totp_period,
        created_at: e.created_at,
        updated_at: e.updated_at,
        stamp: Stamp {
            version: st.version,
            modified_at: st.modified_at,
        },
        modified_by: device.to_owned(),
    }
}

pub(crate) fn folder_record(f: &Folder, st: &State, device: &str) -> FolderRecord {
    FolderRecord {
        name: f.name.clone(),
        color: f.color.clone(),
        position: f.position,
        created_at: f.created_at,
        updated_at: f.updated_at,
        stamp: Stamp {
            version: st.version,
            modified_at: st.modified_at,
        },
        modified_by: device.to_owned(),
    }
}

pub(crate) fn vault_record(m: &VaultMeta, st: &State) -> VaultRecord {
    VaultRecord {
        name: m.name.clone(),
        salt: m.salt.clone(),
        verifier: m.verifier.clone(),
        wrapped_key: m.wrapped_key.clone(),
        created_at: m.created_at,
        updated_at: m.updated_at,
        version: st.version,
    }
}
