//! Storage of accounts and records.
//!
//! [`Storage`] is what the API needs; [`RedbStore`] implements it on one
//! redb file. Tables (byte layout in [`crate::codec`]):
//!
//! | table       | key                              | value                 |
//! |-------------|----------------------------------|-----------------------|
//! | `meta`      | `"schema"`                       | layout version        |
//! | `accounts`  | account                          | [`Account`]           |
//! | `records`   | account ‖ record id              | [`Stored`]            |
//! | `changes`   | account ‖ rev                    | record id             |
//! | `graveyard` | deleted_at ‖ account ‖ record id | — (tombstones by age) |
//!
//! Each record has exactly one `changes` row, under its latest revision, so
//! a pull is one range scan over `changes`.

use std::fmt;
use std::path::Path;

use redb::{
    Database, Key, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition, Value,
};
use vykey_sync_proto::{Id, PushRecord, PushResponse, PushResult, Record};

use crate::codec::{
    self, Account, AcctId, CorruptValue, Stored, change_key, grave_key, record_key,
};

const META: TableDefinition<&str, u64> = TableDefinition::new("meta");
const ACCOUNTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("accounts");
const RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("records");
const CHANGES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("changes");
const GRAVEYARD: TableDefinition<&[u8], ()> = TableDefinition::new("graveyard");

/// Layout version of the database file.
const SCHEMA: u64 = 1;
/// Rows per transaction in garbage collection and backups.
const BATCH: usize = 10_000;

#[derive(Debug)]
pub enum StoreError {
    NoAccount,
    AccountExists,
    /// `since` is ahead of the account (server restored from a backup) or
    /// behind its garbage-collection floor.
    ResyncRequired,
    /// Nothing was stored.
    QuotaExceeded,
    /// A push tried to change a record's kind or vault.
    Invalid(String),
    /// Another process has the database open.
    InUse,
    /// The file was written by a newer server.
    NewerSchema(u64),
    Corrupt,
    Db(redb::Error),
    Io(std::io::Error),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NoAccount => f.write_str("no such account"),
            StoreError::AccountExists => f.write_str("account already exists"),
            StoreError::ResyncRequired => f.write_str("full resync required"),
            StoreError::QuotaExceeded => f.write_str("account quota exceeded"),
            StoreError::Invalid(m) => f.write_str(m),
            StoreError::InUse => {
                f.write_str("the database is in use by another process (is the server running?)")
            }
            StoreError::NewerSchema(v) => write!(
                f,
                "the database has layout version {v}, this server knows up to {SCHEMA}"
            ),
            StoreError::Corrupt => f.write_str("corrupt value in the database"),
            StoreError::Db(e) => write!(f, "database: {e}"),
            StoreError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<CorruptValue> for StoreError {
    fn from(_: CorruptValue) -> Self {
        StoreError::Corrupt
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        match e {
            redb::DatabaseError::DatabaseAlreadyOpen => StoreError::InUse,
            e => StoreError::Db(e.into()),
        }
    }
}

macro_rules! from_redb {
    ($($t:ty),*) => {$(
        impl From<$t> for StoreError {
            fn from(e: $t) -> Self {
                StoreError::Db(e.into())
            }
        }
    )*};
}
from_redb!(
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

/// Per-account limits checked by a push.
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    pub bytes: u64,
    pub records: u64,
}

/// A page of `changes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changes {
    pub records: Vec<Record>,
    pub until: u64,
    pub more: bool,
}

/// Totals over all accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    pub accounts: u64,
    pub records: u64,
    pub bytes: u64,
}

/// What the API needs from storage. Every method is one transaction.
pub trait Storage: Send + Sync {
    fn create_account(&self, acct: &AcctId, now: u64) -> Result<(), StoreError>;
    fn account(&self, acct: &AcctId) -> Result<Option<Account>, StoreError>;
    /// Removes the account and all its records; `false` if there was none.
    fn delete_account(&self, acct: &AcctId) -> Result<bool, StoreError>;
    /// Records the day of the last request.
    fn touch(&self, acct: &AcctId, day: u64) -> Result<(), StoreError>;
    /// Records changed after `since`, at most `limit`. `since = 0` returns
    /// every record the server keeps.
    fn changes(&self, acct: &AcctId, since: u64, limit: usize) -> Result<Changes, StoreError>;
    /// Applies the records whose `base_rev` matches, reports the others as
    /// conflicts. All or nothing on errors (quota, invalid record).
    /// Records must already be validated (sizes, unique ids).
    fn push(
        &self,
        acct: &AcctId,
        records: &[PushRecord],
        quota: Quota,
        now: u64,
    ) -> Result<PushResponse, StoreError>;
    /// Removes tombstones deleted before `deleted_before` (unix seconds);
    /// returns how many.
    fn gc(&self, deleted_before: u64) -> Result<u64, StoreError>;
}

pub struct RedbStore {
    db: Database,
}

impl RedbStore {
    /// Opens or creates the database file (mode 0600 on Unix).
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        restrict_permissions(path)?;
        Self::init(db)
    }

    /// A database in memory, for tests.
    pub fn in_memory() -> Result<Self, StoreError> {
        let db = Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?;
        Self::init(db)
    }

    fn init(db: Database) -> Result<Self, StoreError> {
        let tx = db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            let version = meta.get("schema")?.map(|v| v.value());
            match version {
                None => {
                    meta.insert("schema", SCHEMA)?;
                }
                Some(v) if v > SCHEMA => return Err(StoreError::NewerSchema(v)),
                Some(_) => {}
            }
            tx.open_table(ACCOUNTS)?;
            tx.open_table(RECORDS)?;
            tx.open_table(CHANGES)?;
            tx.open_table(GRAVEYARD)?;
        }
        tx.commit()?;
        Ok(RedbStore { db })
    }

    /// Writes a consistent copy of the database to `path` while the server
    /// keeps running (one read transaction). The copy is written next to
    /// `path` and renamed into place.
    pub fn backup(&self, path: &Path) -> Result<(), StoreError> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        if tmp.exists() {
            std::fs::remove_file(&tmp)?;
        }
        {
            let out = Database::create(&tmp)?;
            restrict_permissions(&tmp)?;
            let rtx = self.db.begin_read()?;
            copy_table(&rtx, &out, META)?;
            copy_table(&rtx, &out, ACCOUNTS)?;
            copy_table(&rtx, &out, RECORDS)?;
            copy_table(&rtx, &out, CHANGES)?;
            copy_table(&rtx, &out, GRAVEYARD)?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn stats(&self) -> Result<Stats, StoreError> {
        let rtx = self.db.begin_read()?;
        let accounts = rtx.open_table(ACCOUNTS)?;
        let mut s = Stats::default();
        for row in accounts.iter()? {
            let (_, v) = row?;
            let a = Account::decode(v.value())?;
            s.accounts += 1;
            s.records += a.records;
            s.bytes += a.bytes;
        }
        Ok(s)
    }
}

impl Storage for RedbStore {
    fn create_account(&self, acct: &AcctId, now: u64) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        {
            let mut accounts = tx.open_table(ACCOUNTS)?;
            if accounts.get(&acct[..])?.is_some() {
                return Err(StoreError::AccountExists);
            }
            let a = Account {
                created: now,
                last_seen_day: now / 86_400,
                ..Account::default()
            };
            accounts.insert(&acct[..], &a.encode()[..])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn account(&self, acct: &AcctId) -> Result<Option<Account>, StoreError> {
        let rtx = self.db.begin_read()?;
        let accounts = rtx.open_table(ACCOUNTS)?;
        let a = accounts.get(&acct[..])?;
        Ok(a.map(|v| Account::decode(v.value())).transpose()?)
    }

    fn delete_account(&self, acct: &AcctId) -> Result<bool, StoreError> {
        let tx = self.db.begin_write()?;
        {
            let mut accounts = tx.open_table(ACCOUNTS)?;
            if accounts.remove(&acct[..])?.is_none() {
                return Ok(false);
            }
            // Graveyard rows of the account are left behind; `gc` drops
            // rows whose record is gone.
            remove_range(&mut tx.open_table(RECORDS)?, codec::acct_range::<16>(acct))?;
            remove_range(&mut tx.open_table(CHANGES)?, codec::acct_range::<8>(acct))?;
        }
        tx.commit()?;
        Ok(true)
    }

    fn touch(&self, acct: &AcctId, day: u64) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        {
            let mut accounts = tx.open_table(ACCOUNTS)?;
            let current = accounts.get(&acct[..])?.map(|v| Account::decode(v.value()));
            let mut a = current.ok_or(StoreError::NoAccount)??;
            if a.last_seen_day == day {
                return Ok(());
            }
            a.last_seen_day = day;
            accounts.insert(&acct[..], &a.encode()[..])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn changes(&self, acct: &AcctId, since: u64, limit: usize) -> Result<Changes, StoreError> {
        let rtx = self.db.begin_read()?;
        let accounts = rtx.open_table(ACCOUNTS)?;
        let a = accounts
            .get(&acct[..])?
            .map(|v| Account::decode(v.value()))
            .ok_or(StoreError::NoAccount)??;
        if since > a.rev || (since != 0 && since < a.gc_floor) {
            return Err(StoreError::ResyncRequired);
        }
        let changes = rtx.open_table(CHANGES)?;
        let records = rtx.open_table(RECORDS)?;
        let lo = change_key(acct, since.saturating_add(1));
        let hi = change_key(acct, u64::MAX);
        let mut out = Vec::new();
        let mut more = false;
        for row in changes.range(&lo[..]..=&hi[..])? {
            if out.len() == limit {
                more = true;
                break;
            }
            let (_, v) = row?;
            let id = Id(v.value().try_into().map_err(|_| StoreError::Corrupt)?);
            let stored = records
                .get(&record_key(acct, &id)[..])?
                .map(|v| Stored::decode(v.value()))
                .ok_or(StoreError::Corrupt)??;
            out.push(stored.into_record(id));
        }
        let until = match (more, out.last()) {
            (true, Some(last)) => last.rev,
            _ => a.rev,
        };
        Ok(Changes {
            records: out,
            until,
            more,
        })
    }

    fn push(
        &self,
        acct_id: &AcctId,
        records: &[PushRecord],
        quota: Quota,
        now: u64,
    ) -> Result<PushResponse, StoreError> {
        let tx = self.db.begin_write()?;
        let mut results = Vec::with_capacity(records.len());
        let rev = {
            let mut accounts = tx.open_table(ACCOUNTS)?;
            let mut table = tx.open_table(RECORDS)?;
            let mut changes = tx.open_table(CHANGES)?;
            let mut graveyard = tx.open_table(GRAVEYARD)?;

            let current = accounts
                .get(&acct_id[..])?
                .map(|v| Account::decode(v.value()));
            let mut a = current.ok_or(StoreError::NoAccount)??;
            let before = a;

            for r in records {
                let key = record_key(acct_id, &r.id);
                let existing = match table.get(&key[..])? {
                    Some(v) => Some(Stored::decode(v.value())?),
                    None => None,
                };
                if let Some(e) = &existing
                    && (e.kind != r.kind || e.vault_id != r.vault_id)
                {
                    return Err(StoreError::Invalid(format!(
                        "record {} cannot change its kind or vault",
                        r.id
                    )));
                }
                let current_rev = existing.as_ref().map_or(0, |e| e.rev);
                if r.base_rev != current_rev {
                    results.push(PushResult::Conflict {
                        id: r.id,
                        current: existing.map(|e| e.into_record(r.id)),
                    });
                    continue;
                }

                a.rev += 1;
                match &existing {
                    Some(e) => {
                        changes.remove(&change_key(acct_id, e.rev)[..])?;
                        if e.deleted {
                            graveyard.remove(&grave_key(e.deleted_at, acct_id, &r.id)[..])?;
                        }
                        a.bytes = a.bytes.saturating_sub(e.blob.len() as u64);
                    }
                    None => a.records += 1,
                }
                let deleted_at = if r.deleted {
                    graveyard.insert(&grave_key(now, acct_id, &r.id)[..], ())?;
                    now
                } else {
                    0
                };
                a.bytes += r.blob.len() as u64;
                let stored = Stored {
                    rev: a.rev,
                    kind: r.kind,
                    vault_id: r.vault_id,
                    deleted: r.deleted,
                    deleted_at,
                    blob: if r.deleted {
                        Vec::new()
                    } else {
                        r.blob.clone()
                    },
                };
                changes.insert(&change_key(acct_id, a.rev)[..], &r.id.0[..])?;
                table.insert(&key[..], &stored.encode()[..])?;
                results.push(PushResult::Ok {
                    id: r.id,
                    rev: a.rev,
                });
            }

            // A push that does not grow usage is allowed even over quota, so
            // an account above a lowered quota can still delete records.
            let over_bytes = a.bytes > quota.bytes && a.bytes > before.bytes;
            let over_records = a.records > quota.records && a.records > before.records;
            if over_bytes || over_records {
                return Err(StoreError::QuotaExceeded);
            }
            accounts.insert(&acct_id[..], &a.encode()[..])?;
            a.rev
        };
        tx.commit()?;
        Ok(PushResponse { results, rev })
    }

    fn gc(&self, deleted_before: u64) -> Result<u64, StoreError> {
        let hi = grave_key(deleted_before, &[0; 32], &Id([0; 16]));
        let mut removed = 0;
        loop {
            let tx = self.db.begin_write()?;
            let done = {
                let mut graveyard = tx.open_table(GRAVEYARD)?;
                let mut accounts = tx.open_table(ACCOUNTS)?;
                let mut records = tx.open_table(RECORDS)?;
                let mut changes = tx.open_table(CHANGES)?;
                let keys: Vec<Vec<u8>> = graveyard
                    .range(..&hi[..])?
                    .take(BATCH)
                    .map(|row| row.map(|(k, _)| k.value().to_vec()))
                    .collect::<Result<_, _>>()?;
                for key in &keys {
                    graveyard.remove(key.as_slice())?;
                    let (acct, id) = codec::split_grave_key(key)?;
                    let rkey = record_key(&acct, &id);
                    let stored = match records.get(&rkey[..])? {
                        Some(v) => Stored::decode(v.value())?,
                        None => continue, // account deleted
                    };
                    if !stored.deleted {
                        continue; // stale row; the record was restored
                    }
                    records.remove(&rkey[..])?;
                    changes.remove(&change_key(&acct, stored.rev)[..])?;
                    let current = accounts.get(&acct[..])?.map(|v| Account::decode(v.value()));
                    if let Some(a) = current {
                        let mut a = a?;
                        a.records = a.records.saturating_sub(1);
                        a.gc_floor = a.gc_floor.max(stored.rev);
                        accounts.insert(&acct[..], &a.encode()[..])?;
                    }
                    removed += 1;
                }
                keys.len() < BATCH
            };
            tx.commit()?;
            if done {
                return Ok(removed);
            }
        }
    }
}

fn remove_range(
    table: &mut redb::Table<&[u8], &[u8]>,
    (lo, hi): (Vec<u8>, Vec<u8>),
) -> Result<(), StoreError> {
    let keys: Vec<Vec<u8>> = table
        .range(lo.as_slice()..=hi.as_slice())?
        .map(|row| row.map(|(k, _)| k.value().to_vec()))
        .collect::<Result<_, _>>()?;
    for k in keys {
        table.remove(k.as_slice())?;
    }
    Ok(())
}

fn copy_table<K: Key + 'static, V: Value + 'static>(
    rtx: &ReadTransaction,
    out: &Database,
    def: TableDefinition<K, V>,
) -> Result<(), StoreError> {
    let src = rtx.open_table(def)?;
    let mut rows = src.iter()?;
    loop {
        let tx = out.begin_write()?;
        let mut n = 0;
        {
            let mut dst = tx.open_table(def)?;
            for row in rows.by_ref().take(BATCH) {
                let (k, v) = row?;
                dst.insert(k.value(), v.value())?;
                n += 1;
            }
        }
        tx.commit()?;
        if n < BATCH {
            return Ok(());
        }
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use vykey_sync_proto::Kind;

    use super::*;

    const ACCT: AcctId = [1; 32];
    const QUOTA: Quota = Quota {
        bytes: 1 << 20,
        records: 1000,
    };

    fn store() -> RedbStore {
        let s = RedbStore::in_memory().unwrap();
        s.create_account(&ACCT, 1000).unwrap();
        s
    }

    fn id(n: u8) -> Id {
        Id([n; 16])
    }

    fn rec(n: u8, base_rev: u64, blob: &[u8]) -> PushRecord {
        PushRecord {
            id: id(n),
            kind: Kind::Entry,
            vault_id: id(0),
            base_rev,
            deleted: false,
            blob: blob.to_vec(),
        }
    }

    fn tomb(n: u8, base_rev: u64) -> PushRecord {
        PushRecord {
            deleted: true,
            ..rec(n, base_rev, b"")
        }
    }

    fn push(s: &RedbStore, recs: &[PushRecord]) -> PushResponse {
        s.push(&ACCT, recs, QUOTA, 2000).unwrap()
    }

    fn ok(rev: u64, n: u8) -> PushResult {
        PushResult::Ok { id: id(n), rev }
    }

    #[test]
    fn push_assigns_increasing_revisions() {
        let s = store();
        let r = push(&s, &[rec(1, 0, b"a"), rec(2, 0, b"bb")]);
        assert_eq!(r.results, vec![ok(1, 1), ok(2, 2)]);
        assert_eq!(r.rev, 2);
        let r = push(&s, &[rec(1, 1, b"a2")]);
        assert_eq!(r.results, vec![ok(3, 1)]);
        let a = s.account(&ACCT).unwrap().unwrap();
        assert_eq!((a.rev, a.records, a.bytes), (3, 2, 4));
    }

    #[test]
    fn stale_base_rev_is_a_conflict_and_others_still_apply() {
        let s = store();
        push(&s, &[rec(1, 0, b"v1")]);
        push(&s, &[rec(1, 1, b"v2")]); // rev 2, from another device
        let r = push(&s, &[rec(1, 1, b"mine"), rec(2, 0, b"new")]);
        let PushResult::Conflict { current, .. } = &r.results[0] else {
            panic!("{r:?}");
        };
        let current = current.as_ref().unwrap();
        assert_eq!((current.rev, current.blob.as_slice()), (2, &b"v2"[..]));
        assert_eq!(r.results[1], ok(3, 2));
    }

    #[test]
    fn creating_an_existing_record_conflicts() {
        let s = store();
        push(&s, &[rec(1, 0, b"x")]);
        let r = push(&s, &[rec(1, 0, b"y")]);
        assert!(matches!(
            r.results[0],
            PushResult::Conflict {
                current: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn unknown_record_with_base_rev_conflicts_without_current() {
        let s = store();
        let r = push(&s, &[rec(1, 5, b"x")]);
        assert_eq!(
            r.results,
            vec![PushResult::Conflict {
                id: id(1),
                current: None
            }]
        );
        assert_eq!(r.rev, 0);
    }

    #[test]
    fn record_cannot_change_kind_or_vault() {
        let s = store();
        push(&s, &[rec(1, 0, b"x")]);
        let mut bad = rec(1, 1, b"y");
        bad.kind = Kind::Folder;
        assert!(matches!(
            s.push(&ACCT, &[rec(2, 0, b"z"), bad], QUOTA, 0),
            Err(StoreError::Invalid(_))
        ));
        // The whole push was rolled back.
        assert_eq!(s.account(&ACCT).unwrap().unwrap().rev, 1);
        let mut bad = rec(1, 1, b"y");
        bad.vault_id = id(9);
        assert!(s.push(&ACCT, &[bad], QUOTA, 0).is_err());
    }

    #[test]
    fn changes_pages_and_keeps_only_latest_revision() {
        let s = store();
        push(&s, &[rec(1, 0, b"a"), rec(2, 0, b"b"), rec(3, 0, b"c")]);
        push(&s, &[rec(1, 1, b"a2")]); // rec 1 moves to rev 4

        let all = s.changes(&ACCT, 0, 100).unwrap();
        let revs: Vec<_> = all.records.iter().map(|r| (r.id, r.rev)).collect();
        assert_eq!(revs, vec![(id(2), 2), (id(3), 3), (id(1), 4)]);
        assert_eq!((all.until, all.more), (4, false));

        let p1 = s.changes(&ACCT, 0, 2).unwrap();
        assert_eq!((p1.records.len(), p1.until, p1.more), (2, 3, true));
        let p2 = s.changes(&ACCT, p1.until, 2).unwrap();
        assert_eq!(p2.records[0].blob, b"a2");
        assert_eq!((p2.records.len(), p2.until, p2.more), (1, 4, false));

        let none = s.changes(&ACCT, 4, 2).unwrap();
        assert_eq!((none.records.len(), none.until, none.more), (0, 4, false));
    }

    #[test]
    fn exact_page_boundary_reports_no_more() {
        let s = store();
        push(&s, &[rec(1, 0, b"a"), rec(2, 0, b"b")]);
        let p = s.changes(&ACCT, 0, 2).unwrap();
        assert_eq!((p.records.len(), p.until, p.more), (2, 2, false));
    }

    #[test]
    fn since_ahead_of_account_requires_resync() {
        let s = store();
        push(&s, &[rec(1, 0, b"a")]);
        assert!(matches!(
            s.changes(&ACCT, 2, 10),
            Err(StoreError::ResyncRequired)
        ));
    }

    #[test]
    fn tombstone_drops_blob_and_can_be_restored() {
        let s = store();
        push(&s, &[rec(1, 0, b"secret")]);
        assert_eq!(push(&s, &[tomb(1, 1)]).results, vec![ok(2, 1)]);
        let c = s.changes(&ACCT, 1, 10).unwrap();
        assert!(c.records[0].deleted && c.records[0].blob.is_empty());
        assert_eq!(s.account(&ACCT).unwrap().unwrap().bytes, 0);

        assert_eq!(push(&s, &[rec(1, 2, b"back")]).results, vec![ok(3, 1)]);
        // Restored before gc: gc must leave it alone.
        assert_eq!(s.gc(u64::MAX).unwrap(), 0);
        assert_eq!(s.changes(&ACCT, 0, 10).unwrap().records[0].blob, b"back");
    }

    #[test]
    fn gc_removes_old_tombstones_and_raises_floor() {
        let s = store();
        push(&s, &[rec(1, 0, b"a"), rec(2, 0, b"b")]);
        s.push(&ACCT, &[tomb(1, 1)], QUOTA, 100).unwrap(); // rev 3, deleted at 100
        s.push(&ACCT, &[tomb(2, 2)], QUOTA, 500).unwrap(); // rev 4, deleted at 500

        assert_eq!(s.gc(100).unwrap(), 0, "cutoff is exclusive");
        assert_eq!(s.gc(200).unwrap(), 1);
        let a = s.account(&ACCT).unwrap().unwrap();
        assert_eq!((a.records, a.gc_floor, a.rev), (1, 3, 4));

        // A client that saw rev 2 may have missed the removed tombstone.
        assert!(matches!(
            s.changes(&ACCT, 2, 10),
            Err(StoreError::ResyncRequired)
        ));
        // Up to date past the floor, or a full pull: fine.
        assert_eq!(s.changes(&ACCT, 3, 10).unwrap().records.len(), 1);
        let full = s.changes(&ACCT, 0, 10).unwrap();
        assert_eq!(
            full.records.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![id(2)]
        );

        // The removed record is unknown again.
        let r = push(&s, &[rec(1, 3, b"x")]);
        assert!(matches!(
            r.results[0],
            PushResult::Conflict { current: None, .. }
        ));
    }

    #[test]
    fn deleting_twice_moves_the_graveyard_row() {
        let s = store();
        push(&s, &[rec(1, 0, b"a")]);
        s.push(&ACCT, &[tomb(1, 1)], QUOTA, 100).unwrap();
        s.push(&ACCT, &[tomb(1, 2)], QUOTA, 900).unwrap();
        assert_eq!(s.gc(500).unwrap(), 0);
        assert_eq!(s.gc(1000).unwrap(), 1);
    }

    #[test]
    fn quota_rejects_growth_but_allows_shrinking() {
        let s = store();
        let small = Quota {
            bytes: 10,
            records: 2,
        };
        s.push(&ACCT, &[rec(1, 0, b"12345")], small, 0).unwrap();
        assert!(matches!(
            s.push(&ACCT, &[rec(2, 0, b"123456")], small, 0),
            Err(StoreError::QuotaExceeded)
        ));
        assert_eq!(s.account(&ACCT).unwrap().unwrap().rev, 1, "rolled back");

        s.push(&ACCT, &[rec(2, 0, b"1")], small, 0).unwrap();
        assert!(matches!(
            s.push(&ACCT, &[rec(3, 0, b"1")], small, 0),
            Err(StoreError::QuotaExceeded)
        ));

        // Over a lowered quota, a push that does not grow usage passes.
        let tiny = Quota {
            bytes: 1,
            records: 1,
        };
        s.push(&ACCT, &[rec(1, 1, b"123")], tiny, 0).unwrap();
        s.push(&ACCT, &[tomb(2, 2)], tiny, 0).unwrap();
    }

    #[test]
    fn accounts_are_isolated() {
        let s = store();
        let other = [2u8; 32];
        s.create_account(&other, 0).unwrap();
        push(&s, &[rec(1, 0, b"mine")]);
        s.push(&other, &[rec(1, 0, b"theirs")], QUOTA, 0).unwrap();
        assert_eq!(s.changes(&other, 0, 10).unwrap().records[0].blob, b"theirs");
        assert_eq!(s.changes(&ACCT, 0, 10).unwrap().records[0].blob, b"mine");
    }

    #[test]
    fn delete_account_removes_everything_of_it_only() {
        let s = store();
        let other = [2u8; 32];
        s.create_account(&other, 0).unwrap();
        push(&s, &[rec(1, 0, b"a")]);
        s.push(&ACCT, &[tomb(1, 1)], QUOTA, 0).unwrap();
        s.push(&other, &[rec(1, 0, b"b")], QUOTA, 0).unwrap();

        assert!(s.delete_account(&ACCT).unwrap());
        assert!(!s.delete_account(&ACCT).unwrap());
        assert!(s.account(&ACCT).unwrap().is_none());
        assert!(matches!(
            s.changes(&ACCT, 0, 10),
            Err(StoreError::NoAccount)
        ));
        // The orphaned graveyard row is dropped without touching anything.
        assert_eq!(s.gc(u64::MAX).unwrap(), 0);
        assert_eq!(s.changes(&other, 0, 10).unwrap().records.len(), 1);
    }

    #[test]
    fn create_account_twice_fails() {
        let s = store();
        assert!(matches!(
            s.create_account(&ACCT, 0),
            Err(StoreError::AccountExists)
        ));
    }

    #[test]
    fn unknown_account() {
        let s = store();
        let nobody = [9u8; 32];
        assert!(s.account(&nobody).unwrap().is_none());
        assert!(matches!(
            s.push(&nobody, &[rec(1, 0, b"x")], QUOTA, 0),
            Err(StoreError::NoAccount)
        ));
        assert!(matches!(s.touch(&nobody, 1), Err(StoreError::NoAccount)));
    }

    #[test]
    fn touch_updates_last_seen_day() {
        let s = store();
        s.touch(&ACCT, 77).unwrap();
        assert_eq!(s.account(&ACCT).unwrap().unwrap().last_seen_day, 77);
    }

    #[test]
    fn file_survives_reopen_and_backup_is_a_copy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.redb");
        let backup = dir.path().join("backup.redb");
        {
            let s = RedbStore::open(&path).unwrap();
            s.create_account(&ACCT, 0).unwrap();
            push(&s, &[rec(1, 0, b"a"), tomb(2, 0)]);
            s.backup(&backup).unwrap();
            push(&s, &[rec(3, 0, b"after backup")]);
        }
        let s = RedbStore::open(&path).unwrap();
        assert_eq!(s.changes(&ACCT, 0, 10).unwrap().records.len(), 3);
        drop(s);

        let b = RedbStore::open(&backup).unwrap();
        let c = b.changes(&ACCT, 0, 10).unwrap();
        assert_eq!(c.records.len(), 2);
        assert_eq!(c.until, 2);
        assert_eq!(b.gc(u64::MAX).unwrap(), 1, "graveyard copied too");
        assert_eq!(
            b.stats().unwrap(),
            Stats {
                accounts: 1,
                records: 1,
                bytes: 1
            }
        );
        assert!(!dir.path().join("backup.redb.tmp").exists());
    }

    #[test]
    fn second_open_reports_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.redb");
        let _s = RedbStore::open(&path).unwrap();
        assert!(matches!(RedbStore::open(&path), Err(StoreError::InUse)));
    }

    #[cfg(unix)]
    #[test]
    fn database_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.redb");
        RedbStore::open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
