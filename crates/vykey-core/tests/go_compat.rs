//! Known-answer vectors produced by the Go implementation
//! (`internal/crypto` of github.com/stickpro/kyp). If these fail, the Rust
//! app can no longer open vaults created by the Go app.

use vykey_core::crypto::{check_verifier, decrypt, derive_key};

const PASSWORD: &[u8] = b"correct horse";
const SALT: &[u8] = b"0123456789abcdef";
const KEY: &str = "4d1172cbf9fac7225b066a16fdd82ff6e7f978b755582d1aa0a3fb06197f7f92";
const VERIFIER: &str =
    "e18eb5ba61907e9f6c32cf41fc69e93abc3f58a3eef04c94bc0f0a230eed59624e04f6d2e206d624";
const CIPHERTEXT: &str = "0a30a635fd1ac2f6948237c9e7bf350c89f9c38ed12d6135e2a3e028d7c07dbfba29711a181caa44199cad5fb4a42d";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn argon2id_matches_go() {
    let key = derive_key(PASSWORD, SALT).unwrap();
    assert_eq!(key.as_slice(), hex(KEY).as_slice());
}

#[test]
fn verifier_from_go_accepted() {
    let key = derive_key(PASSWORD, SALT).unwrap();
    assert!(check_verifier(&hex(VERIFIER), &key));
}

#[test]
fn ciphertext_from_go_decrypts() {
    let key = derive_key(PASSWORD, SALT).unwrap();
    let plain = decrypt(&hex(CIPHERTEXT), &key).unwrap();
    assert_eq!(std::str::from_utf8(&plain).unwrap(), "s3cr3t-пароль");
}

/// `testdata/go-fixture.db` was created by the Go app (vault "fixture",
/// password "correct horse"). Work on a copy so the fixture stays pristine.
fn fixture_copy() -> (tempfile::TempDir, std::path::PathBuf) {
    copy_fixture("go-fixture.db")
}

fn copy_fixture(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(name);
    let dir = tempfile::tempdir().unwrap();
    let dst = dir.path().join("vykey.db");
    std::fs::copy(src, &dst).unwrap();
    (dir, dst)
}

#[test]
fn reads_go_database() {
    use vykey_core::{Store, Vault};
    let (_dir, path) = fixture_copy();
    let store = Store::open(&path).unwrap();
    let vaults = store.list_vaults().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].name, "fixture");

    assert!(Vault::unlock(vaults[0].clone(), "wrong").is_err());
    let vault = Vault::unlock(store.vault_meta("fixture").unwrap(), "correct horse").unwrap();
    let entries = store.list_entries(&vault).unwrap();
    let titles: Vec<&str> = entries.iter().map(|e| e.title.as_str()).collect();
    assert_eq!(titles, ["Empty", "GitHub", "Почта"]);

    let gh = &entries[1];
    assert_eq!(gh.username.as_deref(), Some("alex@example.com"));
    assert_eq!(gh.password.as_deref(), Some("gh-Pa55!word"));
    assert_eq!(gh.url.as_deref(), Some("https://github.com"));
    assert_eq!(gh.notes.as_deref(), Some("Коды восстановления: 1111-2222"));
    assert_eq!(gh.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    assert_eq!(gh.totp_issuer.as_deref(), Some("GitHub"));
    assert_eq!((gh.totp_digits, gh.totp_period), (6, 30));
    assert!(vykey_core::totp::code(gh.totp_secret.as_ref().unwrap(), 0, 6, 30).is_ok());

    let empty = &entries[0];
    assert_eq!(
        (empty.username.as_ref(), empty.password.as_ref()),
        (None, None)
    );
}

/// `testdata/go-fixture-v2.db`: schema v2 written by the Go app, two vaults
/// ("Работа" / "correct horse", "Личное" / "battery staple").
#[test]
fn reads_go_multi_vault_database() {
    use vykey_core::{Store, Vault};
    let (_dir, path) = copy_fixture("go-fixture-v2.db");
    let store = Store::open(&path).unwrap();
    let names: Vec<String> = store
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|v| v.name)
        .collect();
    assert_eq!(names.len(), 2);

    let work = Vault::unlock(store.vault_meta("Работа").unwrap(), "correct horse").unwrap();
    let home = Vault::unlock(store.vault_meta("Личное").unwrap(), "battery staple").unwrap();
    assert_eq!(store.claim_entries(&work).unwrap(), 0);

    let titles = |v: &Vault| -> Vec<String> {
        store
            .list_entries(v)
            .unwrap()
            .iter()
            .map(|e| e.title.clone())
            .collect()
    };
    assert_eq!(titles(&work), ["GitLab"]);
    assert_eq!(titles(&home), ["Банк", "Почта"]);
    let gitlab = &store.list_entries(&work).unwrap()[0];
    assert_eq!(gitlab.password.as_deref(), Some("w0rk-Pa55!"));
}

/// A Go vault has no wrapped key (the password key is the data key). Opening
/// it backs the database up first; a password change then wraps that same
/// key, so the entries stay readable without being re-encrypted.
#[test]
fn legacy_vault_password_change() {
    use vykey_core::{Store, Vault};
    let (dir, path) = fixture_copy();
    let store = Store::open(&path).unwrap();
    assert!(dir.path().join("vykey.db.bak-v1").exists());

    let meta = store.vault_meta("fixture").unwrap();
    assert!(meta.wrapped_key.is_none());
    let mut vault = Vault::unlock(meta, "correct horse").unwrap();
    let old_key = vault.key().clone();

    let change = vault.password_change();
    assert!(matches!(
        vault.password_change().prepare("wrong", "new password"),
        Err(vykey_core::Error::WrongPassword)
    ));
    let wrap = change.prepare("correct horse", "new password").unwrap();
    store.change_password(&mut vault, wrap).unwrap();
    drop(store);

    let store = Store::open(&path).unwrap();
    let meta = store.vault_meta("fixture").unwrap();
    assert!(meta.wrapped_key.is_some());
    assert!(Vault::unlock(meta.clone(), "correct horse").is_err());
    let vault = Vault::unlock(meta.clone(), "new password").unwrap();
    assert_eq!(vault.key().as_slice(), old_key.as_slice());
    let entries = store.list_entries(&vault).unwrap();
    assert_eq!(entries[1].password.as_deref(), Some("gh-Pa55!word"));
    // A key kept for fingerprint unlock still opens it.
    Vault::unlock_with_key(meta, old_key).unwrap();
}
