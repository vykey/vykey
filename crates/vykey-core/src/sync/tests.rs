//! Sync against the real server code, in process.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use vykey_server::api::{Api, Config, Request};
use vykey_server::store::{RedbStore, Storage};
use vykey_sync_proto::{ErrorBody, Token};

use super::*;
use crate::{EntryInput, EntryKind};

struct Server {
    api: Arc<Api>,
    db: Arc<RedbStore>,
}

impl Server {
    fn new() -> Self {
        let db = Arc::new(RedbStore::in_memory().unwrap());
        let api = Arc::new(Api::new(db.clone(), Config::default()));
        Server { api, db }
    }

    fn account(&self) -> Token {
        vykey_server::api::create_account(self.db.as_ref(), 1).unwrap()
    }
}

struct Direct<'a> {
    api: &'a Api,
    auth: String,
}

impl Direct<'_> {
    fn call<T: for<'de> serde::Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Result<T, SyncError> {
        let r = self.api.handle(&Request {
            method,
            path,
            query,
            authorization: Some(&self.auth),
            invite: None,
            body,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });
        if (200..300).contains(&r.status) {
            return serde_json::from_slice(&r.body).map_err(|e| SyncError::Protocol(e.to_string()));
        }
        let e: ErrorBody = serde_json::from_slice(&r.body).unwrap();
        Err(SyncError::Server {
            status: r.status,
            code: Some(e.error),
            message: e.message,
            retry_after: r.retry_after,
        })
    }
}

impl Transport for Direct<'_> {
    fn changes(&self, since: u64, limit: usize) -> Result<ChangesResponse, SyncError> {
        self.call(
            "GET",
            "/v1/changes",
            &format!("since={since}&limit={limit}"),
            b"",
        )
    }

    fn push(&self, req: &PushRequest) -> Result<PushResponse, SyncError> {
        self.call("POST", "/v1/push", "", &serde_json::to_vec(req).unwrap())
    }
}

/// One device: its own database, connected to the account.
struct Device {
    _dir: tempfile::TempDir,
    store: Store,
    token: Token,
}

impl Device {
    fn new(token: &Token) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("vykey.db")).unwrap();
        store.set_sync_account("http://test", token).unwrap();
        Device {
            _dir: dir,
            store,
            token: token.clone(),
        }
    }

    fn sync(&self, server: &Server, vault: Option<&Vault>) -> Report {
        let t = Direct {
            api: &server.api,
            auth: format!("Bearer {}", self.token),
        };
        sync(&self.store, vault, &t).unwrap()
    }

    /// The vault named `name`, opened with a key from another device (no
    /// Argon2 in tests).
    fn open(&self, name: &str, key: &Vault) -> Vault {
        Vault::unlock_with_key(self.store.vault_meta(name).unwrap(), key.key().clone()).unwrap()
    }
}

fn login(title: &str, password: &str) -> EntryInput {
    let mut e = EntryInput::default();
    e.kind = EntryKind::Login;
    e.title = title.into();
    e.username = Some("me".into());
    e.password = Some(password.into());
    e
}

type Snapshot = (
    BTreeMap<String, (String, Option<String>, bool, Option<String>)>,
    BTreeMap<String, String>,
);

fn snapshot(store: &Store, v: &Vault) -> Snapshot {
    let entries = store
        .list_entries(v)
        .unwrap()
        .into_iter()
        .map(|e| {
            (
                e.id.clone(),
                (
                    e.title.clone(),
                    e.password.clone(),
                    e.favorite,
                    e.folder.clone(),
                ),
            )
        })
        .collect();
    let folders = store
        .list_folders(v)
        .unwrap()
        .into_iter()
        .map(|f| (f.id, f.name))
        .collect();
    (entries, folders)
}

fn titles(store: &Store, v: &Vault) -> Vec<String> {
    let mut t: Vec<_> = store
        .list_entries(v)
        .unwrap()
        .into_iter()
        .map(|e| e.title.clone())
        .collect();
    t.sort();
    t
}

fn clean(store: &Store) -> bool {
    let n: i64 = store
        .conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM entries WHERE dirty = 1) + \
             (SELECT COUNT(*) FROM folders WHERE dirty = 1) + \
             (SELECT COUNT(*) FROM vault_meta WHERE dirty = 1) + \
             (SELECT COUNT(*) FROM sync_tombstones)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    n == 0
}

/// A, with vault "Personal": one folder and two entries.
fn seeded(server: &Server, token: &Token) -> (Device, Vault, String, String) {
    let a = Device::new(token);
    let v = Vault::create("Personal", "pw").unwrap();
    a.store.insert_vault(&v).unwrap();
    let folder = a.store.create_folder(&v, "Work", "#ff0000").unwrap();
    let mut gh = login("GitHub", "gh-pass");
    gh.folder = Some(folder.clone());
    let gh = a.store.create_entry(&v, &gh).unwrap();
    let mail = a
        .store
        .create_entry(&v, &login("Mail", "mail-pass"))
        .unwrap();
    let r = a.sync(server, Some(&v));
    assert_eq!(r.pushed, 4, "{r:?}");
    assert!(clean(&a.store));
    (a, v, gh, mail)
}

#[test]
fn second_device_gets_everything_once_unlocked() {
    let server = Server::new();
    let token = server.account();
    let (a, va, _, _) = seeded(&server, &token);

    let b = Device::new(&token);
    // Locked: the vault arrives, its contents wait in the inbox.
    let r = b.sync(&server, None);
    assert!(r.vaults_changed);
    assert_eq!(b.store.list_vaults().unwrap().len(), 1);
    assert_eq!(b.store.sync_inbox_len().unwrap(), 3);

    let vb = b.open("Personal", &va);
    let r = b.sync(&server, Some(&vb));
    assert!(r.open_vault_changed);
    assert_eq!(b.store.sync_inbox_len().unwrap(), 0);
    assert_eq!(snapshot(&b.store, &vb), snapshot(&a.store, &va));
    assert!(clean(&b.store), "nothing to push back");
    // Nothing new either way.
    let r = b.sync(&server, Some(&vb));
    assert_eq!((r.pulled, r.pushed), (0, 0));
}

#[test]
fn edits_moves_and_deletions_propagate() {
    let server = Server::new();
    let token = server.account();
    let (a, va, gh, mail) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);
    let vb = b.open("Personal", &va);
    b.sync(&server, Some(&vb));

    b.store
        .update_entry(&vb, &gh, &login("GitHub", "new-pass"))
        .unwrap();
    b.store.set_favorite(&vb, &gh, true).unwrap();
    b.store.delete_entry(&vb, &mail).unwrap();
    let folder = b.store.list_folders(&vb).unwrap()[0].id.clone();
    b.store
        .update_folder(&vb, &folder, "Job", "#00ff00")
        .unwrap();
    b.sync(&server, Some(&vb));
    assert!(clean(&b.store));

    let r = a.sync(&server, Some(&va));
    assert!(r.open_vault_changed);
    assert_eq!(snapshot(&a.store, &va), snapshot(&b.store, &vb));
    let e = a.store.get_entry(&va, &gh).unwrap();
    assert_eq!(
        (e.password.as_deref(), e.favorite),
        (Some("new-pass"), true)
    );
    assert!(a.store.get_entry(&va, &mail).is_err());
    assert!(clean(&a.store));
}

#[test]
fn concurrent_edits_keep_the_losing_secret_as_a_copy() {
    let server = Server::new();
    let token = server.account();
    let (a, va, gh, _) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);
    let vb = b.open("Personal", &va);
    b.sync(&server, Some(&vb));

    a.store
        .update_entry(&va, &gh, &login("GitHub", "from-a"))
        .unwrap();
    b.store
        .update_entry(&vb, &gh, &login("GitHub", "from-b"))
        .unwrap();
    a.sync(&server, Some(&va));
    let r = b.sync(&server, Some(&vb));
    assert_eq!(r.conflicts, 1, "{r:?}");
    a.sync(&server, Some(&va));

    assert_eq!(snapshot(&a.store, &va), snapshot(&b.store, &vb));
    let passwords: Vec<_> = a
        .store
        .list_entries(&va)
        .unwrap()
        .into_iter()
        .filter(|e| e.title.starts_with("GitHub"))
        .map(|e| (e.title.clone(), e.password.clone().unwrap()))
        .collect();
    assert_eq!(passwords.len(), 2, "{passwords:?}");
    assert!(passwords.iter().any(|(t, _)| t == "GitHub (conflict)"));
    let mut pw: Vec<_> = passwords.iter().map(|(_, p)| p.as_str()).collect();
    pw.sort();
    assert_eq!(pw, ["from-a", "from-b"], "both secrets survive");
}

#[test]
fn concurrent_title_edits_do_not_copy() {
    let server = Server::new();
    let token = server.account();
    let (a, va, gh, _) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);
    let vb = b.open("Personal", &va);
    b.sync(&server, Some(&vb));

    a.store
        .update_entry(&va, &gh, &login("GH from A", "gh-pass"))
        .unwrap();
    b.store
        .update_entry(&vb, &gh, &login("GH from B", "gh-pass"))
        .unwrap();
    a.sync(&server, Some(&va));
    b.sync(&server, Some(&vb));
    a.sync(&server, Some(&va));
    assert_eq!(snapshot(&a.store, &va), snapshot(&b.store, &vb));
    assert_eq!(a.store.list_entries(&va).unwrap().len(), 2);
}

#[test]
fn an_edit_beats_a_deletion() {
    let server = Server::new();
    let token = server.account();
    let (a, va, gh, _) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);
    let vb = b.open("Personal", &va);
    b.sync(&server, Some(&vb));

    // A deletes first, B edits without having seen it.
    a.store.delete_entry(&va, &gh).unwrap();
    a.sync(&server, Some(&va));
    b.store
        .update_entry(&vb, &gh, &login("GitHub", "kept"))
        .unwrap();
    b.sync(&server, Some(&vb));
    a.sync(&server, Some(&va));
    assert_eq!(
        a.store.get_entry(&va, &gh).unwrap().password.as_deref(),
        Some("kept")
    );
    assert_eq!(snapshot(&a.store, &va), snapshot(&b.store, &vb));

    // And the other way round: B deletes an entry A edited unseen.
    a.store
        .update_entry(&va, &gh, &login("GitHub", "edited again"))
        .unwrap();
    a.sync(&server, Some(&va));
    b.store.delete_entry(&vb, &gh).unwrap();
    b.sync(&server, Some(&vb));
    a.sync(&server, Some(&va));
    b.sync(&server, Some(&vb));
    assert_eq!(snapshot(&a.store, &va), snapshot(&b.store, &vb));
    assert!(a.store.get_entry(&va, &gh).is_ok(), "edit wins");
}

#[test]
fn deleting_a_vault_deletes_it_everywhere() {
    let server = Server::new();
    let token = server.account();
    let (a, va, _, _) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);
    let vb = b.open("Personal", &va);
    b.sync(&server, Some(&vb));

    b.store.delete_vault(vb).unwrap();
    b.sync(&server, None);
    assert!(clean(&b.store));
    let r = a.sync(&server, Some(&va));
    assert!(r.open_vault_deleted);
    assert!(a.store.list_vaults().unwrap().is_empty());
    assert_eq!(a.store.entry_count(&va.meta().id).unwrap(), 0);
    // A fresh device sees nothing.
    let c = Device::new(&token);
    c.sync(&server, None);
    assert!(c.store.list_vaults().unwrap().is_empty());
    assert_eq!(c.store.sync_inbox_len().unwrap(), 0);
}

#[test]
fn vault_rename_and_password_change_reach_other_devices() {
    let server = Server::new();
    let token = server.account();
    let (a, mut va, _, _) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);

    a.store.rename_vault(&mut va, "Private").unwrap();
    let wrap = va.password_change().prepare("pw", "new pw").unwrap();
    a.store.change_password(&mut va, wrap).unwrap();
    a.sync(&server, Some(&va));
    let r = b.sync(&server, None);
    assert!(r.vaults_changed);
    let meta = b.store.vault_meta("Private").unwrap();
    // The new password opens it on B; the data key did not change.
    let vb = Vault::unlock(meta, "new pw").unwrap();
    assert_eq!(**vb.key(), **va.key());
}

#[test]
fn password_changed_elsewhere_wins_over_a_local_change() {
    let server = Server::new();
    let token = server.account();
    let (a, mut va, _, _) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);
    let mut vb = b.open("Personal", &va);

    let wrap = va.password_change().prepare("pw", "from a").unwrap();
    a.store.change_password(&mut va, wrap).unwrap();
    a.sync(&server, Some(&va));
    let wrap = vb.password_change().prepare("pw", "from b").unwrap();
    b.store.change_password(&mut vb, wrap).unwrap();
    let r = b.sync(&server, Some(&vb));
    assert_eq!(r.password_changed, ["Personal"]);
    let meta = b.store.vault_meta("Personal").unwrap();
    assert!(Vault::unlock(meta.clone(), "from a").is_ok());
    assert!(Vault::unlock(meta, "from b").is_err());
    assert!(clean(&b.store));
}

#[test]
fn same_vault_name_on_two_devices_gets_a_suffix() {
    let server = Server::new();
    let token = server.account();
    let (_a, _va, _, _) = seeded(&server, &token);
    let b = Device::new(&token);
    let own = Vault::create("Personal", "other").unwrap();
    b.store.insert_vault(&own).unwrap();
    b.sync(&server, None);
    let mut names: Vec<_> = b
        .store
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    names.sort();
    assert_eq!(names, ["Personal", "Personal (2)"]);
    // The rename is pushed, so every device agrees.
    b.sync(&server, None);
    let c = Device::new(&token);
    c.sync(&server, None);
    let mut c_names: Vec<_> = c
        .store
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    c_names.sort();
    assert_eq!(c_names, names);
}

#[test]
fn full_resync_after_garbage_collection() {
    let server = Server::new();
    let token = server.account();
    let (a, va, gh, mail) = seeded(&server, &token);
    let b = Device::new(&token);
    b.sync(&server, None);
    let vb = b.open("Personal", &va);
    b.sync(&server, Some(&vb));

    // A deletes while B is away; the server forgets the tombstone.
    a.store.delete_entry(&va, &mail).unwrap();
    a.store
        .update_entry(&va, &gh, &login("GitHub", "after gc"))
        .unwrap();
    a.sync(&server, Some(&va));
    assert_eq!(server.db.gc(u64::MAX).unwrap(), 1);

    // B's last revision is below the floor: 410, then a full pull.
    b.sync(&server, Some(&vb));
    assert_eq!(snapshot(&b.store, &vb), snapshot(&a.store, &va));
    assert!(b.store.get_entry(&vb, &mail).is_err());
    assert!(clean(&b.store));
}

#[test]
fn reconnecting_an_account_duplicates_nothing() {
    let server = Server::new();
    let token = server.account();
    let (a, va, _, _) = seeded(&server, &token);
    a.store.clear_sync_account().unwrap();
    assert!(a.store.sync_account().unwrap().is_none());
    a.store.set_sync_account("http://test", &token).unwrap();
    a.sync(&server, Some(&va));
    a.sync(&server, Some(&va));
    assert_eq!(titles(&a.store, &va), ["GitHub", "Mail"]);
    assert!(clean(&a.store));
}

#[test]
fn not_connected() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("vykey.db")).unwrap();
    let server = Server::new();
    let t = Direct {
        api: &server.api,
        auth: String::new(),
    };
    assert!(matches!(
        sync(&store, None, &t),
        Err(SyncError::NotConnected)
    ));
}

const SEEDS: u64 = 12;

/// Three devices, random operations and random sync points; after every
/// device has synced twice in a row, all three agree and nothing is dirty.
#[test]
fn random_operations_converge() {
    for seed in 1..=SEEDS {
        let server = Server::new();
        let token = server.account();
        let (a, va, _, _) = seeded(&server, &token);
        let mut devices = vec![(a, va)];
        for _ in 0..2 {
            let d = Device::new(&token);
            d.sync(&server, None);
            let v = d.open("Personal", &devices[0].1);
            d.sync(&server, Some(&v));
            devices.push((d, v));
        }

        let mut rng = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut next = |n: u64| {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng % n
        };
        for step in 0..60 {
            let (d, v) = &devices[next(3) as usize];
            let entries = d.store.list_entries(v).unwrap();
            let pick = |i: u64| {
                entries
                    .get(i as usize % entries.len().max(1))
                    .map(|e| e.id.clone())
            };
            match next(9) {
                0 => {
                    d.store
                        .create_entry(v, &login(&format!("e{step}"), &format!("p{step}")))
                        .unwrap();
                }
                1 => {
                    if let Some(id) = pick(next(100)) {
                        d.store
                            .update_entry(v, &id, &login(&format!("t{step}"), &format!("p{step}")))
                            .unwrap();
                    }
                }
                2 => {
                    if let Some(id) = pick(next(100)) {
                        d.store.delete_entry(v, &id).unwrap();
                    }
                }
                3 => {
                    if let Some(id) = pick(next(100)) {
                        d.store.set_favorite(v, &id, next(2) == 0).unwrap();
                    }
                }
                4 => {
                    if let Some(id) = pick(next(100)) {
                        let folders = d.store.list_folders(v).unwrap();
                        let to = folders.get(next(3) as usize).map(|f| f.id.clone());
                        d.store.set_folder(v, &id, to.as_deref()).unwrap();
                    }
                }
                5 => {
                    let _ = d.store.create_folder(v, &format!("f{step}"), "#123456");
                }
                6 => {
                    // Locked: folders and entries wait in the inbox.
                    d.sync(&server, None);
                }
                _ => {
                    d.sync(&server, Some(v));
                }
            }
        }
        for _ in 0..2 {
            for (d, v) in &devices {
                d.sync(&server, Some(v));
            }
        }
        let first = snapshot(&devices[0].0.store, &devices[0].1);
        for (d, v) in &devices {
            assert_eq!(snapshot(&d.store, v), first, "seed {seed}");
            assert!(clean(&d.store), "seed {seed}");
        }
    }
}
