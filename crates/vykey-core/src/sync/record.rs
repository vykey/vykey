//! What a vault, folder or entry looks like on the sync server
//! (`docs/sync-protocol.md`, "Blob format").
//!
//! Folder and entry blobs: `version (1) ‖ nonce (12) ‖ AES-256-GCM ‖ tag (16)`
//! over the JSON of the whole record, padded with spaces to a multiple of
//! 256 bytes, with `AAD = "vykey-sync-v1" ‖ kind ‖ vault id ‖ record id` so a
//! blob moved to another record or vault does not decrypt. Vault records
//! must be readable before unlocking: plain JSON (name, salt, wrapped key,
//! verifier).

use serde::{Deserialize, Serialize};
use vykey_sync_proto::{Id, Kind};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{self, Key};
use crate::store::{Card, EntryKind};

const BLOB_V1: u8 = 1;
const AAD_PREFIX: &[u8] = b"vykey-sync-v1";
const PAD: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("record does not decrypt (wrong vault key, or moved by the server)")]
    Decrypt,
    #[error("malformed record: {0}")]
    Malformed(String),
}

/// Fields that order concurrent edits and detect stale copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Stamp {
    /// Edit counter of the record; grows with every change.
    pub version: u64,
    /// Unix seconds of the last change of any kind.
    pub modified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRecord {
    pub name: String,
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64")]
    pub verifier: Vec<u8>,
    #[serde(with = "b64_opt", default)]
    pub wrapped_key: Option<Vec<u8>>,
    pub created_at: i64,
    pub updated_at: i64,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRecord {
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub position: i64,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(flatten)]
    pub stamp: Stamp,
    /// Device that made the last change (breaks ties between equal times).
    #[serde(default)]
    pub modified_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryRecord {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    #[zeroize(skip)]
    pub kind: EntryKind,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub card: Option<Card>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub totp_secret: Option<String>,
    #[serde(default)]
    pub totp_issuer: Option<String>,
    #[serde(default = "default_algorithm")]
    pub totp_algorithm: String,
    #[serde(default = "default_digits")]
    pub totp_digits: u32,
    #[serde(default = "default_period")]
    pub totp_period: u32,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(flatten)]
    #[zeroize(skip)]
    pub stamp: Stamp,
    #[serde(default)]
    pub modified_by: String,
}

fn default_algorithm() -> String {
    "SHA1".into()
}
fn default_digits() -> u32 {
    6
}
fn default_period() -> u32 {
    30
}

impl EntryRecord {
    /// Whether two versions differ in something hard to re-type: then the
    /// loser of a conflict is kept as a copy instead of dropped.
    pub fn secrets_differ(&self, other: &EntryRecord) -> bool {
        let card = |r: &EntryRecord| {
            r.card
                .as_ref()
                .map(|c| (c.number.clone(), c.cvv.clone(), c.pin.clone()))
        };
        self.password != other.password
            || self.totp_secret != other.totp_secret
            || self.notes != other.notes
            || card(self) != card(other)
    }
}

pub fn parse_id(s: &str) -> Result<Id, RecordError> {
    s.parse()
        .map_err(|_| RecordError::Malformed(format!("id {s:?} is not a UUID")))
}

fn aad(kind: Kind, vault_id: &Id, id: &Id) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_PREFIX.len() + 1 + 32);
    a.extend_from_slice(AAD_PREFIX);
    a.push(kind.to_u8());
    a.extend_from_slice(&vault_id.0);
    a.extend_from_slice(&id.0);
    a
}

/// Encrypts a folder or entry record.
pub fn seal<T: Serialize>(
    value: &T,
    kind: Kind,
    vault_id: &Id,
    id: &Id,
    key: &Key,
) -> Result<Vec<u8>, RecordError> {
    let mut plain = Zeroizing::new(
        serde_json::to_vec(value).map_err(|e| RecordError::Malformed(e.to_string()))?,
    );
    let padded = plain.len().div_ceil(PAD).max(1) * PAD;
    plain.resize(padded, b' ');
    let ct = crypto::encrypt_aad(&plain, &aad(kind, vault_id, id), key)
        .map_err(|_| RecordError::Decrypt)?;
    let mut blob = Vec::with_capacity(1 + ct.len());
    blob.push(BLOB_V1);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// Decrypts a folder or entry record.
pub fn open<T: for<'de> Deserialize<'de>>(
    blob: &[u8],
    kind: Kind,
    vault_id: &Id,
    id: &Id,
    key: &Key,
) -> Result<T, RecordError> {
    let (&version, ct) = blob
        .split_first()
        .ok_or_else(|| RecordError::Malformed("empty blob".into()))?;
    if version != BLOB_V1 {
        return Err(RecordError::Malformed(format!(
            "blob format {version} is newer than this vykey"
        )));
    }
    let plain =
        crypto::decrypt_aad(ct, &aad(kind, vault_id, id), key).map_err(|_| RecordError::Decrypt)?;
    // serde_json ignores the trailing padding.
    serde_json::from_slice(&plain).map_err(|e| RecordError::Malformed(e.to_string()))
}

pub fn vault_blob(v: &VaultRecord) -> Vec<u8> {
    serde_json::to_vec(v).expect("a vault record always serializes")
}

pub fn parse_vault(blob: &[u8]) -> Result<VaultRecord, RecordError> {
    serde_json::from_slice(blob).map_err(|e| RecordError::Malformed(e.to_string()))
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&data_encoding::BASE64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        data_encoding::BASE64
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

mod b64_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_some(&data_encoding::BASE64.encode(v)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| {
                data_encoding::BASE64
                    .decode(s.as_bytes())
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> EntryRecord {
        EntryRecord {
            title: "GitHub".into(),
            kind: EntryKind::Login,
            favorite: true,
            folder: None,
            card: None,
            username: Some("me".into()),
            password: Some("hunter2".into()),
            url: None,
            notes: None,
            totp_secret: None,
            totp_issuer: None,
            totp_algorithm: "SHA1".into(),
            totp_digits: 6,
            totp_period: 30,
            created_at: 1,
            updated_at: 2,
            stamp: Stamp {
                version: 3,
                modified_at: 4,
            },
            modified_by: "dev".into(),
        }
    }

    #[test]
    fn sealed_entry_round_trips_and_is_padded() {
        let key = crypto::generate_key();
        let (v, id) = (Id([1; 16]), Id([2; 16]));
        let blob = seal(&entry(), Kind::Entry, &v, &id, &key).unwrap();
        assert_eq!(blob[0], BLOB_V1);
        assert_eq!((blob.len() - 1 - 12 - 16) % PAD, 0);
        let back: EntryRecord = open(&blob, Kind::Entry, &v, &id, &key).unwrap();
        assert_eq!(back, entry());
    }

    #[test]
    fn a_blob_does_not_open_elsewhere() {
        let key = crypto::generate_key();
        let (v, id) = (Id([1; 16]), Id([2; 16]));
        let blob = seal(&entry(), Kind::Entry, &v, &id, &key).unwrap();
        let other = |k, vv, ii| open::<EntryRecord>(&blob, k, vv, ii, &key).is_err();
        assert!(other(Kind::Entry, &v, &Id([3; 16])), "other record");
        assert!(other(Kind::Entry, &Id([9; 16]), &id), "other vault");
        assert!(other(Kind::Folder, &v, &id), "other kind");
        assert!(open::<EntryRecord>(&blob, Kind::Entry, &v, &id, &crypto::generate_key()).is_err());
    }

    #[test]
    fn padding_hides_field_lengths() {
        let key = crypto::generate_key();
        let (v, id) = (Id([1; 16]), Id([2; 16]));
        let short = seal(&entry(), Kind::Entry, &v, &id, &key).unwrap();
        let mut long = entry();
        long.password = Some("a much longer password than before".into());
        let long = seal(&long, Kind::Entry, &v, &id, &key).unwrap();
        assert_eq!(short.len(), long.len());
    }

    #[test]
    fn newer_blob_format_is_reported() {
        let key = crypto::generate_key();
        let (v, id) = (Id([1; 16]), Id([2; 16]));
        let mut blob = seal(&entry(), Kind::Entry, &v, &id, &key).unwrap();
        blob[0] = 2;
        assert!(matches!(
            open::<EntryRecord>(&blob, Kind::Entry, &v, &id, &key),
            Err(RecordError::Malformed(_))
        ));
    }

    #[test]
    fn vault_record_json() {
        let v = VaultRecord {
            name: "Личное".into(),
            salt: vec![1; 16],
            verifier: vec![2; 40],
            wrapped_key: None,
            created_at: 1,
            updated_at: 2,
            version: 3,
        };
        let back = parse_vault(&vault_blob(&v)).unwrap();
        assert_eq!(back, v);
        let json: serde_json::Value = serde_json::from_slice(&vault_blob(&v)).unwrap();
        assert!(json["wrapped_key"].is_null());
    }

    #[test]
    fn secrets_differ() {
        let a = entry();
        let mut b = entry();
        b.title = "Renamed".into();
        assert!(!a.secrets_differ(&b));
        b.password = Some("new".into());
        assert!(a.secrets_differ(&b));
    }
}
