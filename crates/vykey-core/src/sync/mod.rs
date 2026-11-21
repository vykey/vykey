//! Client side of sync (`docs/sync-protocol.md`).
//!
//! [`sync`] runs one round against a [`Transport`]: pull everything new,
//! merge it into the database, push local changes, resolve conflicts. The
//! server never sees plaintext and cannot merge; every decision is here.
//!
//! Merge rules, per record:
//!
//! - Not changed locally: the server's version is taken, unless it is
//!   older than ours (lower edit counter: the server was restored or rolled
//!   back), then ours is pushed again.
//! - Changed on both sides: the later change wins (device id breaks ties).
//!   For entries whose secrets differ, the losing side is kept as a new
//!   entry "… (conflict)", so nothing is lost silently.
//! - Deleted on one side, edited on the other: the edit wins, except for
//!   whole vaults, where the deletion (which needed the master password)
//!   wins.
//! - Vault records (name, salt, wrapped key, verifier) are never merged:
//!   when the master password was changed elsewhere, that version wins.
//!
//! Folders and entries need the vault key: only the unlocked vault is
//! merged; records of other vaults wait in an inbox until it is unlocked.

#[cfg(feature = "http")]
pub mod http;
mod local;
pub mod record;

use std::collections::HashSet;

use vykey_sync_proto::{
    ChangesResponse, ErrorCode, Id, Kind, MAX_BLOB_LEN, MAX_PUSH_RECORDS, PushRecord, PushRequest,
    PushResponse, PushResult, Record,
};

pub use local::SyncAccount;
use local::{State, entry_record, folder_record, vault_record};
use record::{EntryRecord, FolderRecord};
/// Wire types, for callers matching on server error codes.
pub use vykey_sync_proto as proto;

use crate::error::Error;
use crate::store::{Store, Vault};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("{0}")]
    Store(#[from] Error),
    #[error("this database is not connected to a sync account")]
    NotConnected,
    #[error("{0}")]
    Address(AddressError),
    /// An error answer from the server.
    #[error("{message}")]
    Server {
        status: u16,
        code: Option<ErrorCode>,
        message: String,
        /// Seconds to wait (429).
        retry_after: Option<u64>,
    },
    #[error("cannot reach the server: {0}")]
    Network(String),
    #[error("unexpected answer from the server: {0}")]
    Protocol(String),
}

/// Why a server address was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("not a server address")]
    Invalid,
    /// `http://` to another machine: the token would travel in the clear.
    #[error("plain http:// is allowed only for localhost; use https://")]
    Insecure,
}

impl SyncError {
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            SyncError::Server { code, .. } => *code,
            _ => None,
        }
    }
}

/// How the engine talks to a server.
pub trait Transport {
    fn changes(&self, since: u64, limit: usize) -> Result<ChangesResponse, SyncError>;
    fn push(&self, req: &PushRequest) -> Result<PushResponse, SyncError>;
}

/// What one sync round did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Records from the server applied locally.
    pub pulled: usize,
    /// Local changes the server accepted.
    pub pushed: usize,
    /// Records changed on both sides.
    pub conflicts: usize,
    /// Records that could not be read or sent (logged, not fatal).
    pub skipped: usize,
    /// Vaults were added, renamed, re-keyed or deleted.
    pub vaults_changed: bool,
    /// Folders or entries of the unlocked vault changed.
    pub open_vault_changed: bool,
    /// The unlocked vault was deleted on another device.
    pub open_vault_deleted: bool,
    /// Vaults whose master password was changed on another device, over a
    /// change made here.
    pub password_changed: Vec<String>,
    /// Seconds the server asks to wait before the next poll.
    pub poll_after: Option<u32>,
}

/// Records per pull page.
const PAGE: usize = 500;
/// Blob bytes per push request (the server takes up to 8 MiB of JSON).
const PUSH_BYTES: usize = 4 * 1024 * 1024;
/// Push rounds: conflicts resolved in one round are pushed in the next.
const ROUNDS: usize = 4;
pub const CONFLICT_SUFFIX: &str = "(conflict)";
/// The vykey Cloud sync server, offered by default.
pub const CLOUD_SERVER: &str = "https://sync.vykey.dev";

/// One sync round. `vault` is the unlocked vault, if any: its folders and
/// entries are merged and pushed; other vaults' wait for their unlock.
pub fn sync(store: &Store, vault: Option<&Vault>, t: &dyn Transport) -> Result<Report, SyncError> {
    let account = store.sync_account()?.ok_or(SyncError::NotConnected)?;
    let mut s = Session {
        store,
        vault,
        device: account.device_id,
        report: Report::default(),
    };
    if let Some(v) = vault {
        s.apply_inbox(v)?;
    }
    s.pull(account.last_rev, t)?;
    for _ in 0..ROUNDS {
        if !s.push(t)? {
            break;
        }
    }
    store.set_synced_now()?;
    Ok(s.report)
}

struct Session<'a> {
    store: &'a Store,
    vault: Option<&'a Vault>,
    device: String,
    report: Report,
}

/// What a pushed record was, to settle its result.
struct Pending {
    kind: Kind,
    id: String,
    vault_id: String,
    version: u64,
    tombstone: bool,
}

impl Session<'_> {
    // ---------- pull ----------

    fn pull(&mut self, mut since: u64, t: &dyn Transport) -> Result<(), SyncError> {
        let mut full = false;
        let mut seen = HashSet::new();
        loop {
            let page = match t.changes(since, PAGE) {
                Ok(p) => p,
                Err(e) if e.code() == Some(ErrorCode::ResyncRequired) && !full => {
                    full = true;
                    since = 0;
                    continue;
                }
                Err(e) => return Err(e),
            };
            for r in &page.records {
                if full {
                    seen.insert(r.id.to_string());
                }
                self.apply(r, full)?;
            }
            self.report.poll_after = Some(page.poll_after);
            since = page.until;
            // A full resync only counts once it is complete.
            if !full {
                self.store.set_last_rev(since)?;
            }
            if !page.more {
                break;
            }
        }
        if full {
            self.forget_unseen(&seen)?;
            self.store.set_last_rev(since)?;
        }
        Ok(())
    }

    /// After a full resync: what was on the server but is no longer there
    /// was deleted (its tombstone is gone); changed records are pushed anew.
    fn forget_unseen(&mut self, seen: &HashSet<String>) -> Result<(), SyncError> {
        for kind in [Kind::Entry, Kind::Folder, Kind::Vault] {
            for id in self.store.synced_ids(kind, None)? {
                if seen.contains(&id) {
                    continue;
                }
                let Some((st, vault_id)) = self.store.state(kind, &id)? else {
                    continue;
                };
                if st.dirty {
                    self.store.mark(kind, &id, 0, None, None)?;
                } else {
                    self.store.drop_local(kind, &id)?;
                    self.note_local_change(kind, &vault_id, true);
                }
            }
        }
        for tb in self.store.tombstones()? {
            if !seen.contains(&tb.id) {
                self.store.drop_tombstone(&tb.id)?;
            }
        }
        Ok(())
    }

    fn apply_inbox(&mut self, v: &Vault) -> Result<(), SyncError> {
        for r in self.store.inbox_list(&v.meta.id)? {
            self.apply_item(v, &r, false)?;
        }
        self.store.inbox_clear(&v.meta.id)?;
        Ok(())
    }

    fn apply(&mut self, r: &Record, full: bool) -> Result<(), SyncError> {
        if r.kind == Kind::Vault {
            return self.apply_vault(r, full);
        }
        match self.vault {
            Some(v) if v.meta.id == r.vault_id.to_string() => self.apply_item(v, r, full),
            // A deletion needs no key: applied at once, even when locked.
            _ if r.deleted => self.apply_deletion(r, full),
            _ => Ok(self.store.inbox_put(r)?),
        }
    }

    /// A folder or entry deleted on the server.
    fn apply_deletion(&mut self, r: &Record, full: bool) -> Result<(), SyncError> {
        let id = r.id.to_string();
        let vault_id = r.vault_id.to_string();
        // Whatever waited for an unlock is superseded.
        self.store.inbox_drop(&id)?;
        let local = match self.store.state(r.kind, &id)? {
            Some((_, v)) if v != vault_id => {
                self.report.skipped += 1;
                return Ok(());
            }
            other => other.map(|(st, _)| st),
        };
        if !full && local.is_some_and(|st| r.rev <= st.sync_rev) {
            return Ok(());
        }
        match local {
            None => {
                if self.store.tombstone(&id)?.is_some() {
                    self.store.drop_tombstone(&id)?;
                }
            }
            Some(st) if !st.dirty => {
                self.store.drop_local(r.kind, &id)?;
                self.note_local_change(r.kind, &vault_id, true);
                self.report.pulled += 1;
            }
            // Edited here, deleted there: the edit comes back.
            Some(_) => self.store.mark(r.kind, &id, r.rev, None, None)?,
        }
        Ok(())
    }

    fn note_local_change(&mut self, kind: Kind, vault_id: &str, deleted: bool) {
        let open = self.vault.is_some_and(|v| v.meta.id == vault_id);
        match kind {
            Kind::Vault => {
                self.report.vaults_changed = true;
                if open && deleted {
                    self.report.open_vault_deleted = true;
                }
            }
            _ if open => self.report.open_vault_changed = true,
            _ => {}
        }
    }

    fn apply_vault(&mut self, r: &Record, full: bool) -> Result<(), SyncError> {
        let id = r.id.to_string();
        let local = self.store.state(Kind::Vault, &id)?.map(|(st, _)| st);
        if !full && local.is_some_and(|st| r.rev <= st.sync_rev) {
            return Ok(());
        }
        let tomb = self.store.tombstone(&id)?;

        if r.deleted {
            if tomb.is_some() {
                self.store.drop_tombstone(&id)?;
            }
            if local.is_some() {
                self.store.drop_local(Kind::Vault, &id)?;
                self.note_local_change(Kind::Vault, &id, true);
                self.report.pulled += 1;
            }
            return Ok(());
        }
        let Ok(rec) = record::parse_vault(&r.blob) else {
            self.report.skipped += 1;
            return Ok(());
        };
        if let Some(tomb_rev) = tomb {
            // The version we deleted, or a later change: the deletion wins
            // either way (and goes on top of a later change).
            if r.rev > tomb_rev {
                self.store.set_tombstone_rev(&id, r.rev)?;
            }
            return Ok(());
        }
        match local {
            None => {
                self.store.put_vault(&id, &rec, r.rev)?;
                self.note_local_change(Kind::Vault, &id, false);
                self.report.pulled += 1;
            }
            Some(st) if !st.dirty => {
                if rec.version < st.version {
                    self.store.mark(Kind::Vault, &id, r.rev, None, Some(true))?;
                } else {
                    self.store.put_vault(&id, &rec, r.rev)?;
                    self.note_local_change(Kind::Vault, &id, false);
                    self.report.pulled += 1;
                }
            }
            Some(st) => {
                self.report.conflicts += 1;
                let mine = self
                    .store
                    .vault_by_id(&id)?
                    .ok_or(Error::VaultNotFound(id.clone()))?;
                let same_password = mine.salt == rec.salt
                    && mine.wrapped_key == rec.wrapped_key
                    && mine.verifier == rec.verifier;
                if same_password {
                    // Only our name differs: it goes on top of theirs.
                    let version = st.version.max(rec.version) + 1;
                    self.store
                        .mark(Kind::Vault, &id, r.rev, Some(version), Some(true))?;
                } else {
                    if mine.salt != rec.salt || mine.wrapped_key != rec.wrapped_key {
                        self.report.password_changed.push(rec.name.clone());
                    }
                    self.store.put_vault(&id, &rec, r.rev)?;
                    self.note_local_change(Kind::Vault, &id, false);
                }
            }
        }
        Ok(())
    }

    fn apply_item(&mut self, v: &Vault, r: &Record, full: bool) -> Result<(), SyncError> {
        let id = r.id.to_string();
        let kind = r.kind;
        let local = match self.store.state(kind, &id)? {
            Some((_, vault_id)) if vault_id != v.meta.id => {
                // Same id in another vault: not ours to touch.
                self.report.skipped += 1;
                return Ok(());
            }
            other => other.map(|(st, _)| st),
        };
        if r.deleted {
            return self.apply_deletion(r, full);
        }
        if !full && local.is_some_and(|st| r.rev <= st.sync_rev) {
            return Ok(());
        }
        let tomb = self.store.tombstone(&id)?;
        if local.is_none() && tomb.is_some_and(|t| r.rev <= t) {
            // The version we deleted (our own push coming back).
            return Ok(());
        }

        let vid = r.vault_id;
        let remote = match kind {
            Kind::Folder => {
                record::open::<FolderRecord>(&r.blob, kind, &vid, &r.id, &v.key).map(Item::Folder)
            }
            _ => record::open::<EntryRecord>(&r.blob, kind, &vid, &r.id, &v.key)
                .map(|e| Item::Entry(Box::new(e))),
        };
        let Ok(remote) = remote else {
            self.report.skipped += 1;
            return Ok(());
        };

        match local {
            None => {
                if tomb.is_some() {
                    // Deleted here, edited there later: the edit wins.
                    self.store.drop_tombstone(&id)?;
                }
                self.put(v, &id, &remote, r.rev)?;
            }
            Some(st) if !st.dirty => {
                if remote.version() < st.version {
                    self.store.mark(kind, &id, r.rev, None, Some(true))?;
                } else {
                    self.put(v, &id, &remote, r.rev)?;
                }
            }
            Some(st) => self.resolve(v, &id, st, &remote, r.rev)?,
        }
        Ok(())
    }

    /// Both sides changed the record.
    fn resolve(
        &mut self,
        v: &Vault,
        id: &str,
        st: State,
        remote: &Item,
        rev: u64,
    ) -> Result<(), SyncError> {
        self.report.conflicts += 1;
        let (remote_at, remote_by) = remote.when();
        let remote_wins = (remote_at, remote_by) > (st.modified_at, self.device.as_str());
        if let Item::Entry(theirs) = remote {
            let mine = entry_record(&self.store.get_entry(v, id)?, &st, &self.device);
            if mine.secrets_differ(theirs) {
                let loser = if remote_wins { &mine } else { theirs.as_ref() };
                self.store.conflict_copy(v, loser, CONFLICT_SUFFIX)?;
                self.report.open_vault_changed = true;
            }
        }
        if remote_wins {
            self.put(v, id, remote, rev)?;
        } else {
            let version = st.version.max(remote.version()) + 1;
            self.store
                .mark(remote.kind(), id, rev, Some(version), Some(true))?;
        }
        Ok(())
    }

    fn put(&mut self, v: &Vault, id: &str, item: &Item, rev: u64) -> Result<(), SyncError> {
        match item {
            Item::Folder(f) => self.store.put_folder(v, id, f, rev, false)?,
            Item::Entry(e) => self.store.put_entry(v, id, e, rev, false)?,
        }
        self.report.pulled += 1;
        self.report.open_vault_changed = true;
        Ok(())
    }

    // ---------- push ----------

    /// Pushes everything dirty; `true` if conflicts need another round.
    fn push(&mut self, t: &dyn Transport) -> Result<bool, SyncError> {
        let items = self.collect()?;
        if items.is_empty() {
            return Ok(false);
        }
        let mut again = false;
        for batch in batches(items) {
            let req = PushRequest {
                records: batch.iter().map(|(r, _)| r.clone()).collect(),
            };
            let resp = t.push(&req)?;
            if resp.results.len() != batch.len() {
                return Err(SyncError::Protocol(format!(
                    "{} results for {} records",
                    resp.results.len(),
                    batch.len()
                )));
            }
            for ((_, p), result) in batch.into_iter().zip(resp.results) {
                match result {
                    PushResult::Ok { rev, .. } => {
                        if p.tombstone {
                            self.store.drop_tombstone(&p.id)?;
                        } else {
                            self.store.ack(p.kind, &p.id, rev, p.version)?;
                        }
                        self.report.pushed += 1;
                    }
                    PushResult::Conflict { current, .. } => {
                        again = true;
                        self.settle_conflict(&p, current)?;
                    }
                }
            }
        }
        Ok(again)
    }

    fn settle_conflict(&mut self, p: &Pending, current: Option<Record>) -> Result<(), SyncError> {
        let Some(cur) = current else {
            // The server no longer has the record (garbage collected).
            if p.tombstone {
                self.store.drop_tombstone(&p.id)?;
            } else {
                self.store.mark(p.kind, &p.id, 0, None, None)?;
            }
            return Ok(());
        };
        if !p.tombstone {
            return self.apply(&cur, false);
        }
        if cur.deleted {
            self.store.drop_tombstone(&p.id)?;
            return Ok(());
        }
        // Deleted here, changed there.
        let vault_gone = p.kind == Kind::Vault
            || self.store.vault_by_id(&p.vault_id)?.is_none()
            || self.store.tombstone(&p.vault_id)?.is_some();
        if vault_gone {
            // A deleted vault stays deleted, with everything in it.
            self.store.set_tombstone_rev(&p.id, cur.rev)?;
        } else {
            self.store.drop_tombstone(&p.id)?;
            self.apply(&cur, false)?;
        }
        Ok(())
    }

    fn collect(&mut self) -> Result<Vec<(PushRecord, Pending)>, SyncError> {
        let mut out = Vec::new();
        for (m, st) in self.store.dirty_vaults()? {
            let Some(id) = self.id(&m.id) else { continue };
            let blob = record::vault_blob(&vault_record(&m, &st));
            out.push(self.live(Kind::Vault, id, id, &st, blob, &m.id));
        }
        if let Some(v) = self.vault
            && let Some(vid) = self.id(&v.meta.id)
        {
            for (f, st) in self.store.dirty_folders(v)? {
                let Some(id) = self.id(&f.id) else { continue };
                let rec = folder_record(&f, &st, &self.device);
                let blob = record::seal(&rec, Kind::Folder, &vid, &id, &v.key)
                    .map_err(|e| Error::Data(e.to_string()))?;
                out.push(self.live(Kind::Folder, id, vid, &st, blob, &v.meta.id));
            }
            for (e, st) in self.store.dirty_entries(v)? {
                let Some(id) = self.id(&e.id) else { continue };
                let rec = entry_record(&e, &st, &self.device);
                let blob = record::seal(&rec, Kind::Entry, &vid, &id, &v.key)
                    .map_err(|e| Error::Data(e.to_string()))?;
                if blob.len() > MAX_BLOB_LEN {
                    // Notes this long cannot be synced.
                    self.report.skipped += 1;
                    continue;
                }
                out.push(self.live(Kind::Entry, id, vid, &st, blob, &v.meta.id));
            }
        }
        for tb in self.store.tombstones()? {
            let (Some(id), Some(vid)) = (self.id(&tb.id), self.id(&tb.vault_id)) else {
                continue;
            };
            out.push((
                PushRecord {
                    id,
                    kind: tb.kind,
                    vault_id: vid,
                    base_rev: tb.sync_rev,
                    deleted: true,
                    blob: Vec::new(),
                },
                Pending {
                    kind: tb.kind,
                    id: tb.id,
                    vault_id: tb.vault_id,
                    version: 0,
                    tombstone: true,
                },
            ));
        }
        Ok(out)
    }

    fn live(
        &self,
        kind: Kind,
        id: Id,
        vault_id: Id,
        st: &State,
        blob: Vec<u8>,
        local_vault: &str,
    ) -> (PushRecord, Pending) {
        (
            PushRecord {
                id,
                kind,
                vault_id,
                base_rev: st.sync_rev,
                deleted: false,
                blob,
            },
            Pending {
                kind,
                id: id.to_string(),
                vault_id: local_vault.to_owned(),
                version: st.version,
                tombstone: false,
            },
        )
    }

    /// Local ids are UUIDs; anything else cannot be synced.
    fn id(&mut self, s: &str) -> Option<Id> {
        let id = record::parse_id(s).ok();
        if id.is_none() {
            self.report.skipped += 1;
        }
        id
    }
}

/// A decrypted folder or entry from the server.
enum Item {
    Folder(FolderRecord),
    Entry(Box<EntryRecord>),
}

impl Item {
    fn kind(&self) -> Kind {
        match self {
            Item::Folder(_) => Kind::Folder,
            Item::Entry(_) => Kind::Entry,
        }
    }

    fn version(&self) -> u64 {
        match self {
            Item::Folder(f) => f.stamp.version,
            Item::Entry(e) => e.stamp.version,
        }
    }

    fn when(&self) -> (i64, &str) {
        match self {
            Item::Folder(f) => (f.stamp.modified_at, &f.modified_by),
            Item::Entry(e) => (e.stamp.modified_at, &e.modified_by),
        }
    }
}

/// Splits a push into requests within the server's limits.
fn batches(items: Vec<(PushRecord, Pending)>) -> Vec<Vec<(PushRecord, Pending)>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut bytes = 0;
    for item in items {
        let len = item.0.blob.len();
        if !cur.is_empty() && (cur.len() == MAX_PUSH_RECORDS || bytes + len > PUSH_BYTES) {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        bytes += len;
        cur.push(item);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests;
