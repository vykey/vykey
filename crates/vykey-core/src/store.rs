//! SQLite storage: vault metadata and encrypted entries.
//!
//! Key derivation is split from database access ([`Vault::unlock`] and
//! [`Vault::create`] are pure CPU work), so a UI can run Argon2 on a worker
//! thread while keeping the [`Store`] on its own thread.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, Key};
use crate::error::{Error, Result};
use crate::schema;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct VaultMeta {
    pub id: String,
    pub name: String,
    pub salt: Vec<u8>,
    pub verifier: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// An unlocked vault: metadata plus the derived master key.
pub struct Vault {
    meta: VaultMeta,
    key: Key,
}

impl Vault {
    /// Derives the key and checks it against the verifier. CPU-heavy (Argon2id).
    pub fn unlock(meta: VaultMeta, password: &str) -> Result<Self> {
        let key = crypto::derive_key(password.as_bytes(), &meta.salt)?;
        if !crypto::check_verifier(&meta.verifier, &key) {
            return Err(Error::WrongPassword);
        }
        Ok(Self { meta, key })
    }

    /// Prepares a new vault (not yet stored). CPU-heavy (Argon2id).
    pub fn create(name: &str, password: &str) -> Result<Self> {
        let salt = crypto::generate_salt();
        let key = crypto::derive_key(password.as_bytes(), &salt)?;
        let verifier = crypto::new_verifier(&key)?;
        let ts = now();
        Ok(Self {
            meta: VaultMeta {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.to_owned(),
                salt: salt.to_vec(),
                verifier,
                created_at: ts,
                updated_at: ts,
            },
            key,
        })
    }

    pub fn meta(&self) -> &VaultMeta {
        &self.meta
    }

    fn seal(&self, value: Option<&str>) -> Result<Option<Vec<u8>>> {
        value
            .map(|v| crypto::encrypt(v.as_bytes(), &self.key).map_err(Error::from))
            .transpose()
    }

    fn seal_data(&self, data: &EntryData) -> Result<Vec<u8>> {
        let json =
            Zeroizing::new(serde_json::to_vec(data).map_err(|e| Error::Data(e.to_string()))?);
        Ok(crypto::encrypt(&json, &self.key)?)
    }

    fn open_data(&self, blob: &[u8]) -> Result<EntryData> {
        let json = crypto::decrypt(blob, &self.key)?;
        serde_json::from_slice(&json).map_err(|e| Error::Data(e.to_string()))
    }

    fn open(&self, value: Option<Vec<u8>>) -> Result<Option<String>> {
        value
            .map(|blob| {
                let plain = crypto::decrypt(&blob, &self.key)?;
                String::from_utf8(plain.to_vec()).map_err(|_| Error::InvalidUtf8)
            })
            .transpose()
    }
}

/// Kind of entry. Stored inside the encrypted `data` JSON.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    #[default]
    Login,
    Card,
    Note,
}

/// Payment card fields (kind = card). See [`crate::card`] for helpers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct Card {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub holder: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub number: String,
    /// "MM/YY"
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expiry: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cvv: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pin: String,
}

impl Card {
    fn is_empty(&self) -> bool {
        self.holder.is_empty()
            && self.number.is_empty()
            && self.expiry.is_empty()
            && self.cvv.is_empty()
            && self.pin.is_empty()
    }
}

/// Encrypted per-entry JSON in `entries.data` (schema v3). Holds everything
/// that used to be plaintext (title, 2FA issuer) and the v3 additions.
#[derive(Default, Serialize, Deserialize, Zeroize)]
struct EntryData {
    #[serde(default)]
    title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    totp_issuer: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    kind: EntryKind,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    favorite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    card: Option<Card>,
    /// Id of a folder of the same vault (schema v4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
}

/// Decrypted entry. Secret fields are wiped from memory on drop.
#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: String,
    #[zeroize(skip)]
    pub kind: EntryKind,
    pub favorite: bool,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub card: Option<Card>,
    /// Folder id; `None` = not in a folder. May name a folder that no
    /// longer exists (treat it as `None`).
    pub folder: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_issuer: Option<String>,
    pub totp_algorithm: String,
    pub totp_digits: u32,
    pub totp_period: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Fields a user can set when creating or editing an entry.
#[derive(Debug, Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct EntryInput {
    #[zeroize(skip)]
    pub kind: EntryKind,
    pub favorite: bool,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub card: Option<Card>,
    /// Folder id; `None` = not in a folder.
    pub folder: Option<String>,
    pub totp_secret: Option<String>,
    pub totp_issuer: Option<String>,
}

impl EntryInput {
    fn data(&self) -> EntryData {
        EntryData {
            title: self.title.trim().to_owned(),
            totp_issuer: non_empty(&self.totp_issuer).map(str::to_owned),
            kind: self.kind,
            favorite: self.favorite,
            card: self
                .card
                .clone()
                .filter(|c| self.kind == EntryKind::Card && !c.is_empty()),
            folder: non_empty(&self.folder).map(str::to_owned),
        }
    }
}

impl Entry {
    /// The encrypted part of an existing entry, for partial updates.
    fn data(&self) -> EntryData {
        EntryData {
            title: self.title.clone(),
            totp_issuer: self.totp_issuer.clone(),
            kind: self.kind,
            favorite: self.favorite,
            card: self.card.clone(),
            folder: self.folder.clone(),
        }
    }
}

/// A folder of a vault. Entries refer to it by [`Folder::id`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub id: String,
    pub name: String,
    /// Colour of the folder dot, `#RRGGBB`; the UI picks from a palette.
    pub color: String,
    pub position: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Encrypted JSON in `folders.data` (schema v4).
#[derive(Default, Serialize, Deserialize)]
struct FolderData {
    #[serde(default)]
    name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    color: String,
}

pub struct Store {
    conn: Connection,
}

struct RawEntry {
    id: String,
    title: String,
    username: Option<Vec<u8>>,
    password: Option<Vec<u8>>,
    url: Option<Vec<u8>>,
    notes: Option<Vec<u8>>,
    totp_secret: Option<Vec<u8>>,
    totp_issuer: Option<String>,
    totp_algorithm: String,
    totp_digits: i64,
    totp_period: i64,
    created_at: i64,
    updated_at: i64,
    data: Option<Vec<u8>>,
}

const ENTRY_COLUMNS: &str = "id, title, username, password, url, notes, totp_secret, \
     totp_issuer, totp_algorithm, totp_digits, totp_period, created_at, updated_at, data";

impl RawEntry {
    fn from_row(r: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: r.get(0)?,
            title: r.get(1)?,
            username: r.get(2)?,
            password: r.get(3)?,
            url: r.get(4)?,
            notes: r.get(5)?,
            totp_secret: r.get(6)?,
            totp_issuer: r.get(7)?,
            totp_algorithm: r.get(8)?,
            totp_digits: r.get(9)?,
            totp_period: r.get(10)?,
            created_at: r.get(11)?,
            updated_at: r.get(12)?,
            data: r.get(13)?,
        })
    }

    /// Every encrypted field decrypts with the vault key; an entry without
    /// encrypted fields counts only if `only_vault`.
    fn owned_by(&self, vault: &Vault, only_vault: bool) -> bool {
        let fields = [
            &self.username,
            &self.password,
            &self.url,
            &self.notes,
            &self.totp_secret,
            &self.data,
        ];
        let mut encrypted = 0;
        for blob in fields.into_iter().flatten() {
            encrypted += 1;
            if crypto::decrypt(blob, &vault.key).is_err() {
                return false;
            }
        }
        encrypted > 0 || only_vault
    }

    fn decrypt(self, vault: &Vault) -> Result<Entry> {
        // v3 rows keep title & co in `data`; older rows still have them in
        // plaintext columns until `upgrade_entries` runs.
        let mut data = match &self.data {
            Some(blob) => vault.open_data(blob)?,
            None => EntryData {
                title: self.title.clone(),
                totp_issuer: self.totp_issuer.clone(),
                ..EntryData::default()
            },
        };
        Ok(Entry {
            username: vault.open(self.username)?,
            password: vault.open(self.password)?,
            url: vault.open(self.url)?,
            notes: vault.open(self.notes)?,
            totp_secret: vault.open(self.totp_secret)?,
            id: self.id,
            kind: data.kind,
            favorite: data.favorite,
            title: std::mem::take(&mut data.title),
            totp_issuer: data.totp_issuer.take(),
            card: data.card.take(),
            folder: data.folder.take(),
            totp_algorithm: self.totp_algorithm,
            totp_digits: u32::try_from(self.totp_digits).unwrap_or(6),
            totp_period: u32::try_from(self.totp_period).unwrap_or(30),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn meta_from_row(r: &Row<'_>) -> rusqlite::Result<VaultMeta> {
    Ok(VaultMeta {
        id: r.get(0)?,
        name: r.get(1)?,
        salt: r.get(2)?,
        verifier: r.get(3)?,
        created_at: r.get(4)?,
        updated_at: r.get(5)?,
    })
}

/// Trims and maps empty strings to `None` (Go stores `NULL` for unset fields).
fn non_empty(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

impl Store {
    /// Opens (creating if needed) the database at `path` and migrates it.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let mut conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        schema::migrate(&mut conn)?;
        Ok(Self { conn })
    }

    pub fn list_vaults(&self) -> Result<Vec<VaultMeta>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, salt, verifier, created_at, updated_at \
             FROM vault_meta ORDER BY created_at, name",
        )?;
        let rows = stmt.query_map([], meta_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn vault_meta(&self, name: &str) -> Result<VaultMeta> {
        self.conn
            .query_row(
                "SELECT id, name, salt, verifier, created_at, updated_at \
                 FROM vault_meta WHERE name = ?1 LIMIT 1",
                [name],
                meta_from_row,
            )
            .optional()?
            .ok_or_else(|| Error::VaultNotFound(name.to_owned()))
    }

    /// Stores a vault prepared with [`Vault::create`].
    pub fn insert_vault(&self, vault: &Vault) -> Result<()> {
        let m = &vault.meta;
        if self.vault_meta(&m.name).is_ok() {
            return Err(Error::VaultExists(m.name.clone()));
        }
        self.conn.execute(
            "INSERT INTO vault_meta (id, name, salt, verifier, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![m.id, m.name, m.salt, m.verifier, m.created_at, m.updated_at],
        )?;
        Ok(())
    }

    /// Renames a vault. Names are unique per database.
    pub fn rename_vault(&self, vault: &mut Vault, name: &str) -> Result<()> {
        let name = name.trim();
        if let Ok(other) = self.vault_meta(name)
            && other.id != vault.meta.id
        {
            return Err(Error::VaultExists(name.to_owned()));
        }
        let ts = now();
        self.conn.execute(
            "UPDATE vault_meta SET name = ?2, updated_at = ?3 WHERE id = ?1",
            params![vault.meta.id, name, ts],
        )?;
        vault.meta.name = name.to_owned();
        vault.meta.updated_at = ts;
        Ok(())
    }

    /// Deletes a vault and, through `ON DELETE CASCADE`, all its entries.
    /// Requires the unlocked vault as proof of the master password.
    pub fn delete_vault(&self, vault: Vault) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        // Explicit delete as well, in case foreign keys are off.
        tx.execute("DELETE FROM entries WHERE vault_id = ?1", [&vault.meta.id])?;
        tx.execute("DELETE FROM folders WHERE vault_id = ?1", [&vault.meta.id])?;
        tx.execute("DELETE FROM vault_meta WHERE id = ?1", [&vault.meta.id])?;
        tx.commit()?;
        Ok(())
    }

    /// Number of entries bound to a vault (no key needed).
    pub fn entry_count(&self, vault_id: &str) -> Result<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE vault_id = ?1 AND deleted_at IS NULL",
            [vault_id],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Binds entries without a vault (written before schema v2, or by an
    /// older vykey) to `vault` if they are encrypted with its key. AES-GCM
    /// authentication makes this unambiguous. Entries without encrypted
    /// fields are claimed only when the database has a single vault.
    /// Same rules as `claimEntries` in the Go implementation. Returns the
    /// number of claimed entries.
    pub fn claim_entries(&self, vault: &Vault) -> Result<usize> {
        let raws = {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT {ENTRY_COLUMNS} FROM entries WHERE vault_id IS NULL"
            ))?;
            stmt.query_map([], RawEntry::from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        if raws.is_empty() {
            return Ok(0);
        }
        let only_vault = self.list_vaults()?.len() == 1;
        let mut claimed = 0;
        for raw in raws {
            if raw.owned_by(vault, only_vault) {
                claimed += self.conn.execute(
                    "UPDATE entries SET vault_id = ?1 WHERE id = ?2 AND vault_id IS NULL",
                    params![vault.meta.id, raw.id],
                )?;
            }
        }
        Ok(claimed)
    }

    /// Moves plaintext `title` / `totp_issuer` of this vault's pre-v3 rows
    /// into the encrypted `data` (needs the key, hence done on unlock).
    /// Returns the number of upgraded entries.
    pub fn upgrade_entries(&self, vault: &Vault) -> Result<usize> {
        let raws = {
            let mut stmt = self.conn.prepare(&format!(
                "SELECT {ENTRY_COLUMNS} FROM entries WHERE vault_id = ?1 AND data IS NULL"
            ))?;
            stmt.query_map([&vault.meta.id], RawEntry::from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let tx = self.conn.unchecked_transaction()?;
        for raw in &raws {
            let data = EntryData {
                title: raw.title.clone(),
                totp_issuer: raw.totp_issuer.clone(),
                ..EntryData::default()
            };
            tx.execute(
                "UPDATE entries SET data = ?2, title = '', totp_issuer = NULL WHERE id = ?1",
                params![raw.id, vault.seal_data(&data)?],
            )?;
        }
        tx.commit()?;
        Ok(raws.len())
    }

    /// Everything to run right after unlocking: claim unassigned entries,
    /// then encrypt legacy plaintext titles.
    pub fn prepare_vault(&self, vault: &Vault) -> Result<()> {
        self.claim_entries(vault)?;
        self.upgrade_entries(vault)?;
        Ok(())
    }

    /// Sets the favourite flag without touching `updated_at` (it is not a
    /// change of the secret, so it must not reset "stale password" checks).
    pub fn set_favorite(&self, vault: &Vault, id: &str, favorite: bool) -> Result<()> {
        self.rewrite_data(vault, id, |d| d.favorite = favorite)
    }

    /// Moves an entry into `folder` (`None` = out of any folder). Like
    /// [`Store::set_favorite`], it keeps `updated_at`.
    pub fn set_folder(&self, vault: &Vault, id: &str, folder: Option<&str>) -> Result<()> {
        if let Some(f) = folder {
            self.folder_exists(vault, f)?;
        }
        self.rewrite_data(vault, id, |d| d.folder = folder.map(str::to_owned))
    }

    /// Re-encrypts `data` of one entry after `change`, keeping `updated_at`.
    fn rewrite_data(
        &self,
        vault: &Vault,
        id: &str,
        change: impl FnOnce(&mut EntryData),
    ) -> Result<()> {
        let entry = self.get_entry(vault, id)?;
        let mut data = entry.data();
        change(&mut data);
        self.conn.execute(
            "UPDATE entries SET data = ?3, title = '', totp_issuer = NULL \
             WHERE id = ?1 AND vault_id = ?2",
            params![id, vault.meta.id, vault.seal_data(&data)?],
        )?;
        Ok(())
    }

    // ---------- folders ----------

    fn folder_exists(&self, vault: &Vault, id: &str) -> Result<()> {
        self.conn
            .query_row(
                "SELECT 1 FROM folders WHERE id = ?1 AND vault_id = ?2",
                [id, &vault.meta.id],
                |_| Ok(()),
            )
            .optional()?
            .ok_or(Error::FolderNotFound)
    }

    /// Folders of `vault` in display order (position, then creation).
    pub fn list_folders(&self, vault: &Vault) -> Result<Vec<Folder>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, data, position, created_at, updated_at FROM folders \
             WHERE vault_id = ?1 ORDER BY position, created_at, id",
        )?;
        let rows = stmt
            .query_map([&vault.meta.id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, blob, position, created_at, updated_at)| {
                let json = crypto::decrypt(&blob, &vault.key)?;
                let data: FolderData =
                    serde_json::from_slice(&json).map_err(|e| Error::Data(e.to_string()))?;
                Ok(Folder {
                    id,
                    name: data.name,
                    color: data.color,
                    position,
                    created_at,
                    updated_at,
                })
            })
            .collect()
    }

    /// Names are unique per vault, case-insensitively. Names are encrypted,
    /// so this is checked after decryption.
    fn check_folder_name(&self, vault: &Vault, name: &str, except: Option<&str>) -> Result<()> {
        let lower = name.to_lowercase();
        let taken = self
            .list_folders(vault)?
            .iter()
            .any(|f| Some(f.id.as_str()) != except && f.name.to_lowercase() == lower);
        if taken {
            return Err(Error::FolderExists(name.to_owned()));
        }
        Ok(())
    }

    fn seal_folder(vault: &Vault, name: &str, color: &str) -> Result<Vec<u8>> {
        let data = FolderData {
            name: name.to_owned(),
            color: color.trim().to_owned(),
        };
        let json = serde_json::to_vec(&data).map_err(|e| Error::Data(e.to_string()))?;
        Ok(crypto::encrypt(&json, &vault.key)?)
    }

    /// Creates a folder at the end of the list and returns its id.
    pub fn create_folder(&self, vault: &Vault, name: &str, color: &str) -> Result<String> {
        let name = name.trim();
        self.check_folder_name(vault, name, None)?;
        let id = uuid::Uuid::new_v4().to_string();
        let ts = now();
        self.conn.execute(
            "INSERT INTO folders (id, vault_id, data, position, created_at, updated_at) \
             VALUES (?1, ?2, ?3, \
                     (SELECT COALESCE(MAX(position), -1) + 1 FROM folders WHERE vault_id = ?2), \
                     ?4, ?4)",
            params![
                id,
                vault.meta.id,
                Self::seal_folder(vault, name, color)?,
                ts
            ],
        )?;
        Ok(id)
    }

    /// Renames and/or recolours a folder.
    pub fn update_folder(&self, vault: &Vault, id: &str, name: &str, color: &str) -> Result<()> {
        let name = name.trim();
        self.check_folder_name(vault, name, Some(id))?;
        let changed = self.conn.execute(
            "UPDATE folders SET data = ?3, updated_at = ?4 WHERE id = ?1 AND vault_id = ?2",
            params![
                id,
                vault.meta.id,
                Self::seal_folder(vault, name, color)?,
                now()
            ],
        )?;
        if changed == 0 {
            return Err(Error::FolderNotFound);
        }
        Ok(())
    }

    /// Deletes a folder. Its entries stay in the vault, outside any folder.
    /// Returns the number of entries taken out of it.
    pub fn delete_folder(&self, vault: &Vault, id: &str) -> Result<usize> {
        self.folder_exists(vault, id)?;
        let members: Vec<Entry> = self
            .list_entries(vault)?
            .into_iter()
            .filter(|e| e.folder.as_deref() == Some(id))
            .collect();
        let tx = self.conn.unchecked_transaction()?;
        for e in &members {
            let mut data = e.data();
            data.folder = None;
            tx.execute(
                "UPDATE entries SET data = ?3, title = '', totp_issuer = NULL \
                 WHERE id = ?1 AND vault_id = ?2",
                params![e.id, vault.meta.id, vault.seal_data(&data)?],
            )?;
        }
        tx.execute(
            "DELETE FROM folders WHERE id = ?1 AND vault_id = ?2",
            [id, &vault.meta.id],
        )?;
        tx.commit()?;
        Ok(members.len())
    }

    /// All live entries of `vault`, ordered by title.
    pub fn list_entries(&self, vault: &Vault) -> Result<Vec<Entry>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM entries WHERE vault_id = ?1 AND deleted_at IS NULL"
        ))?;
        let raws = stmt
            .query_map([&vault.meta.id], RawEntry::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Titles are encrypted, so sort after decryption.
        let mut entries = raws
            .into_iter()
            .map(|raw| raw.decrypt(vault))
            .collect::<Result<Vec<_>>>()?;
        entries.sort_by_cached_key(|e| e.title.to_lowercase());
        Ok(entries)
    }

    pub fn get_entry(&self, vault: &Vault, id: &str) -> Result<Entry> {
        let raw = self
            .conn
            .query_row(
                &format!(
                    "SELECT {ENTRY_COLUMNS} FROM entries WHERE id = ?1 AND vault_id = ?2 LIMIT 1"
                ),
                [id, &vault.meta.id],
                RawEntry::from_row,
            )
            .optional()?
            .ok_or(Error::EntryNotFound)?;
        raw.decrypt(vault)
    }

    /// Creates an entry and returns its id.
    pub fn create_entry(&self, vault: &Vault, input: &EntryInput) -> Result<String> {
        self.check_input_folder(vault, input)?;
        let id = uuid::Uuid::new_v4().to_string();
        let ts = now();
        self.conn.execute(
            "INSERT INTO entries (id, title, username, password, url, notes, totp_secret, \
             totp_issuer, totp_algorithm, totp_digits, totp_period, created_at, updated_at, \
             deleted_at, vault_id, data) \
             VALUES (?1, '', ?2, ?3, ?4, ?5, ?6, NULL, 'SHA1', 6, 30, ?7, ?7, NULL, ?8, ?9)",
            params![
                id,
                vault.seal(non_empty(&input.username))?,
                vault.seal(input.password.as_deref().filter(|p| !p.is_empty()))?,
                vault.seal(non_empty(&input.url))?,
                vault.seal(input.notes.as_deref().filter(|n| !n.trim().is_empty()))?,
                vault.seal(non_empty(&input.totp_secret))?,
                ts,
                vault.meta.id,
                vault.seal_data(&input.data())?,
            ],
        )?;
        Ok(id)
    }

    /// Updates user-editable fields; TOTP algorithm/digits/period are kept.
    pub fn update_entry(&self, vault: &Vault, id: &str, input: &EntryInput) -> Result<()> {
        self.check_input_folder(vault, input)?;
        let changed = self.conn.execute(
            "UPDATE entries SET title = '', username = ?2, password = ?3, url = ?4, notes = ?5, \
             totp_secret = ?6, totp_issuer = NULL, updated_at = ?7, data = ?9 \
             WHERE id = ?1 AND vault_id = ?8",
            params![
                id,
                vault.seal(non_empty(&input.username))?,
                vault.seal(input.password.as_deref().filter(|p| !p.is_empty()))?,
                vault.seal(non_empty(&input.url))?,
                vault.seal(input.notes.as_deref().filter(|n| !n.trim().is_empty()))?,
                vault.seal(non_empty(&input.totp_secret))?,
                now(),
                vault.meta.id,
                vault.seal_data(&input.data())?,
            ],
        )?;
        if changed == 0 {
            return Err(Error::EntryNotFound);
        }
        Ok(())
    }

    fn check_input_folder(&self, vault: &Vault, input: &EntryInput) -> Result<()> {
        match non_empty(&input.folder) {
            Some(f) => self.folder_exists(vault, f),
            None => Ok(()),
        }
    }

    /// Deletes an entry of `vault` permanently (same as the Go implementation).
    pub fn delete_entry(&self, vault: &Vault, id: &str) -> Result<()> {
        let changed = self.conn.execute(
            "DELETE FROM entries WHERE id = ?1 AND vault_id = ?2",
            [id, &vault.meta.id],
        )?;
        if changed == 0 {
            return Err(Error::EntryNotFound);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("sub/vykey.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn vault_lifecycle() {
        let (_d, store) = store();
        assert!(store.list_vaults().unwrap().is_empty());
        let v = Vault::create("main", "pw").unwrap();
        store.insert_vault(&v).unwrap();
        assert!(matches!(
            store.insert_vault(&Vault::create("main", "x").unwrap()),
            Err(Error::VaultExists(_))
        ));
        let meta = store.vault_meta("main").unwrap();
        assert!(matches!(
            Vault::unlock(meta.clone(), "nope"),
            Err(Error::WrongPassword)
        ));
        Vault::unlock(meta, "pw").unwrap();
    }

    #[test]
    fn entry_crud() {
        let (_d, store) = store();
        let v = Vault::create("main", "pw").unwrap();
        store.insert_vault(&v).unwrap();

        let mut input = EntryInput::default();
        input.title = " GitHub ".into();
        input.username = Some("alex".into());
        input.password = Some("s3cret".into());
        input.url = Some("".into());
        let id = store.create_entry(&v, &input).unwrap();
        let e = store.get_entry(&v, &id).unwrap();
        assert_eq!(e.title, "GitHub");
        assert_eq!(e.password.as_deref(), Some("s3cret"));
        assert_eq!(e.url, None);
        assert_eq!((e.totp_digits, e.totp_period), (6, 30));

        let mut input = EntryInput::default();
        input.title = "GitHub".into();
        input.notes = Some("recovery codes".into());
        store.update_entry(&v, &id, &input).unwrap();
        let list = store.list_entries(&v).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].notes.as_deref(), Some("recovery codes"));
        assert_eq!(list[0].password, None);

        store.delete_entry(&v, &id).unwrap();
        assert!(store.list_entries(&v).unwrap().is_empty());
        assert!(matches!(
            store.delete_entry(&v, &id),
            Err(Error::EntryNotFound)
        ));
    }

    fn input(title: &str, password: Option<&str>) -> EntryInput {
        let mut i = EntryInput::default();
        i.title = title.into();
        i.password = password.map(Into::into);
        i
    }

    fn titles(store: &Store, v: &Vault) -> Vec<String> {
        store
            .list_entries(v)
            .unwrap()
            .iter()
            .map(|e| e.title.clone())
            .collect()
    }

    #[test]
    fn vaults_are_isolated() {
        let (_d, store) = store();
        let a = Vault::create("a", "1").unwrap();
        let b = Vault::create("b", "2").unwrap();
        store.insert_vault(&a).unwrap();
        store.insert_vault(&b).unwrap();
        store.create_entry(&a, &input("in a", Some("p"))).unwrap();
        let id_b = store.create_entry(&b, &input("in b", Some("q"))).unwrap();

        assert_eq!(titles(&store, &a), ["in a"]);
        assert_eq!(titles(&store, &b), ["in b"]);
        assert_eq!(store.entry_count(&a.meta.id).unwrap(), 1);
        assert!(matches!(
            store.get_entry(&a, &id_b),
            Err(Error::EntryNotFound)
        ));
        assert!(matches!(
            store.update_entry(&a, &id_b, &input("x", None)),
            Err(Error::EntryNotFound)
        ));
        assert!(matches!(
            store.delete_entry(&a, &id_b),
            Err(Error::EntryNotFound)
        ));
        assert_eq!(titles(&store, &b), ["in b"]);
    }

    /// Inserts an entry the way schema v1 / older vykey did: no vault_id.
    fn insert_legacy(store: &Store, title: &str, vault: &Vault, password: Option<&str>) {
        store
            .conn
            .execute(
                "INSERT INTO entries (id, title, password, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, 0, 0)",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    title,
                    vault.seal(password).unwrap()
                ],
            )
            .unwrap();
    }

    #[test]
    fn unassigned_entries_are_claimed_by_their_vault() {
        let (_d, store) = store();
        let a = Vault::create("a", "1").unwrap();
        let b = Vault::create("b", "2").unwrap();
        store.insert_vault(&a).unwrap();
        store.insert_vault(&b).unwrap();
        insert_legacy(&store, "legacy a", &a, Some("x"));
        insert_legacy(&store, "legacy b", &b, Some("y"));
        insert_legacy(&store, "title only", &a, None);

        assert_eq!(store.claim_entries(&a).unwrap(), 1);
        assert_eq!(store.claim_entries(&b).unwrap(), 1);
        assert_eq!(titles(&store, &a), ["legacy a"]);
        assert_eq!(titles(&store, &b), ["legacy b"]);
        // The title-only entry cannot be attributed with two vaults.
        assert_eq!(store.claim_entries(&a).unwrap(), 0);
    }

    #[test]
    fn single_vault_claims_everything() {
        let (_d, store) = store();
        let v = Vault::create("only", "1").unwrap();
        store.insert_vault(&v).unwrap();
        insert_legacy(&store, "with password", &v, Some("x"));
        insert_legacy(&store, "title only", &v, None);
        assert_eq!(store.claim_entries(&v).unwrap(), 2);
        assert_eq!(titles(&store, &v).len(), 2);
    }

    #[test]
    fn rename_and_delete_vault() {
        let (_d, store) = store();
        let mut a = Vault::create("a", "1").unwrap();
        let b = Vault::create("b", "2").unwrap();
        store.insert_vault(&a).unwrap();
        store.insert_vault(&b).unwrap();
        store.create_entry(&a, &input("in a", Some("p"))).unwrap();
        store.create_entry(&b, &input("in b", Some("q"))).unwrap();

        assert!(matches!(
            store.rename_vault(&mut a, "b"),
            Err(Error::VaultExists(_))
        ));
        store.rename_vault(&mut a, " Работа ").unwrap();
        assert_eq!(a.meta().name, "Работа");
        assert!(store.vault_meta("Работа").is_ok());

        let a_id = a.meta.id.clone();
        store.delete_vault(a).unwrap();
        assert!(store.vault_meta("Работа").is_err());
        assert_eq!(store.entry_count(&a_id).unwrap(), 0);
        assert_eq!(titles(&store, &b), ["in b"]);
        let left: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1);
    }

    #[test]
    fn card_and_note_roundtrip() {
        let (_d, store) = store();
        let v = Vault::create("main", "pw").unwrap();
        store.insert_vault(&v).unwrap();

        let mut i = EntryInput::default();
        i.kind = EntryKind::Card;
        i.title = "Сбер".into();
        i.favorite = true;
        i.card = Some(Card {
            holder: "ALEKSEI KIM".into(),
            number: "2200 0000 0000 0004".into(),
            expiry: "08/28".into(),
            cvv: "123".into(),
            pin: "0000".into(),
        });
        let card_id = store.create_entry(&v, &i).unwrap();

        let mut n = EntryInput::default();
        n.kind = EntryKind::Note;
        n.title = "Wi-Fi".into();
        n.notes = Some("SSID home\npass 12345678".into());
        // Card fields on a non-card entry are dropped.
        n.card = i.card.clone();
        store.create_entry(&v, &n).unwrap();

        let list = store.list_entries(&v).unwrap();
        assert_eq!(
            list.iter().map(|e| e.title.as_str()).collect::<Vec<_>>(),
            ["Wi-Fi", "Сбер"]
        );
        let card = list.iter().find(|e| e.id == card_id).unwrap();
        assert_eq!(card.kind, EntryKind::Card);
        assert!(card.favorite);
        assert_eq!(card.card.as_ref().unwrap().cvv, "123");
        let note = &list[0];
        assert_eq!(note.kind, EntryKind::Note);
        assert_eq!(note.card, None);

        // Nothing readable in plaintext columns.
        let (title, issuer): (String, Option<String>) = store
            .conn
            .query_row(
                "SELECT title, totp_issuer FROM entries WHERE id = ?1",
                [&card_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((title.as_str(), issuer), ("", None));
    }

    #[test]
    fn legacy_titles_are_encrypted_on_upgrade() {
        let (_d, store) = store();
        let v = Vault::create("only", "pw").unwrap();
        store.insert_vault(&v).unwrap();
        insert_legacy(&store, "GitHub", &v, Some("x"));
        store
            .conn
            .execute("UPDATE entries SET totp_issuer = 'GitHub Inc'", [])
            .unwrap();

        // Readable before the upgrade (plaintext fallback)...
        store.claim_entries(&v).unwrap();
        assert_eq!(titles(&store, &v), ["GitHub"]);
        // ...and after it, with the plaintext columns cleared.
        assert_eq!(store.upgrade_entries(&v).unwrap(), 1);
        assert_eq!(store.upgrade_entries(&v).unwrap(), 0);
        let e = &store.list_entries(&v).unwrap()[0];
        assert_eq!(e.title, "GitHub");
        assert_eq!(e.totp_issuer.as_deref(), Some("GitHub Inc"));
        assert_eq!(e.kind, EntryKind::Login);
        let plain: (String, Option<String>) = store
            .conn
            .query_row("SELECT title, totp_issuer FROM entries", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(plain, (String::new(), None));
    }

    #[test]
    fn favorite_does_not_touch_updated_at() {
        let (_d, store) = store();
        let v = Vault::create("main", "pw").unwrap();
        store.insert_vault(&v).unwrap();
        let id = store.create_entry(&v, &input("x", Some("p"))).unwrap();
        store
            .conn
            .execute("UPDATE entries SET updated_at = 42", [])
            .unwrap();
        store.set_favorite(&v, &id, true).unwrap();
        let e = store.get_entry(&v, &id).unwrap();
        assert!(e.favorite);
        assert_eq!(e.updated_at, 42);
        assert_eq!(e.password.as_deref(), Some("p"));
        store.set_favorite(&v, &id, false).unwrap();
        assert!(!store.get_entry(&v, &id).unwrap().favorite);
    }

    #[test]
    fn folder_lifecycle() {
        let (_d, store) = store();
        let v = Vault::create("main", "pw").unwrap();
        store.insert_vault(&v).unwrap();

        let work = store.create_folder(&v, " Работа ", "#8F81FF").unwrap();
        let home = store.create_folder(&v, "Личное", "#3DD68C").unwrap();
        assert!(matches!(
            store.create_folder(&v, "работа", ""),
            Err(Error::FolderExists(_))
        ));
        let folders = store.list_folders(&v).unwrap();
        assert_eq!(
            folders
                .iter()
                .map(|f| (f.name.as_str(), f.position))
                .collect::<Vec<_>>(),
            [("Работа", 0), ("Личное", 1)]
        );
        assert_eq!(folders[0].color, "#8F81FF");

        // Names are not stored in plaintext.
        let blob: Vec<u8> = store
            .conn
            .query_row("SELECT data FROM folders WHERE id = ?1", [&work], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("Работа"));

        store.update_folder(&v, &home, "Дом", "#FFB224").unwrap();
        assert!(matches!(
            store.update_folder(&v, &home, "Работа", ""),
            Err(Error::FolderExists(_))
        ));
        // Same name, other colour: not a conflict with itself.
        store.update_folder(&v, &home, "дом", "#FFB224").unwrap();
        assert_eq!(store.list_folders(&v).unwrap()[1].name, "дом");

        let mut i = input("GitHub", Some("p"));
        i.folder = Some(work.clone());
        let a = store.create_entry(&v, &i).unwrap();
        let b = store.create_entry(&v, &input("Gmail", Some("q"))).unwrap();
        assert_eq!(
            store.get_entry(&v, &a).unwrap().folder.as_deref(),
            Some(work.as_str())
        );

        i.folder = Some("missing".into());
        assert!(matches!(
            store.create_entry(&v, &i),
            Err(Error::FolderNotFound)
        ));
        assert!(matches!(
            store.set_folder(&v, &b, Some("missing")),
            Err(Error::FolderNotFound)
        ));

        store
            .conn
            .execute("UPDATE entries SET updated_at = 42", [])
            .unwrap();
        store.set_folder(&v, &b, Some(&work)).unwrap();
        let e = store.get_entry(&v, &b).unwrap();
        assert_eq!(e.folder.as_deref(), Some(work.as_str()));
        assert_eq!(e.updated_at, 42);
        assert_eq!(e.password.as_deref(), Some("q"));

        // Deleting a folder keeps its entries, outside any folder.
        assert_eq!(store.delete_folder(&v, &work).unwrap(), 2);
        assert!(matches!(
            store.delete_folder(&v, &work),
            Err(Error::FolderNotFound)
        ));
        let list = store.list_entries(&v).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.iter().all(|e| e.folder.is_none()));
        assert_eq!(store.list_folders(&v).unwrap().len(), 1);
    }

    #[test]
    fn folders_are_isolated() {
        let (_d, store) = store();
        let a = Vault::create("a", "1").unwrap();
        let b = Vault::create("b", "2").unwrap();
        store.insert_vault(&a).unwrap();
        store.insert_vault(&b).unwrap();
        let fa = store.create_folder(&a, "Работа", "").unwrap();
        // Same name in another vault is fine.
        store.create_folder(&b, "Работа", "").unwrap();
        assert_eq!(store.list_folders(&b).unwrap().len(), 1);

        let id_b = store.create_entry(&b, &input("x", None)).unwrap();
        assert!(matches!(
            store.set_folder(&b, &id_b, Some(&fa)),
            Err(Error::FolderNotFound)
        ));
        assert!(matches!(
            store.update_folder(&b, &fa, "y", ""),
            Err(Error::FolderNotFound)
        ));
        assert!(matches!(
            store.delete_folder(&b, &fa),
            Err(Error::FolderNotFound)
        ));

        store.delete_vault(a).unwrap();
        let left: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM folders", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 1);
    }

    #[test]
    fn reopen_keeps_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vykey.db");
        drop(Store::open(&path).unwrap());
        let store = Store::open(&path).unwrap();
        let versions: Vec<i64> = store
            .conn
            .prepare("SELECT version_id FROM goose_db_version ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(versions, vec![0, 1, 2, 3, 4]);
    }
}
