//! Byte layout of keys and values in redb.
//!
//! Keys are concatenations of fixed-size parts compared as byte strings, so
//! a range over one account is a prefix range, and revisions (big-endian)
//! sort numerically. Values start with a layout version byte; integers in
//! values are little-endian.

use vykey_sync_proto::{Id, Kind, Record};

/// SHA-256 of an account token: the account's key on the server.
pub type AcctId = [u8; 32];

const ACCOUNT_V1: u8 = 1;
const RECORD_V1: u8 = 1;

#[derive(Debug)]
pub struct CorruptValue;

impl std::fmt::Display for CorruptValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("corrupt value in the database")
    }
}

impl std::error::Error for CorruptValue {}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// `records`: account ‖ record id.
pub fn record_key(acct: &AcctId, id: &Id) -> [u8; 48] {
    let mut k = [0u8; 48];
    k[..32].copy_from_slice(acct);
    k[32..].copy_from_slice(&id.0);
    k
}

/// `changes`: account ‖ revision (big-endian).
pub fn change_key(acct: &AcctId, rev: u64) -> [u8; 40] {
    let mut k = [0u8; 40];
    k[..32].copy_from_slice(acct);
    k[32..].copy_from_slice(&rev.to_be_bytes());
    k
}

pub fn change_key_rev(key: &[u8]) -> Result<u64, CorruptValue> {
    Ok(u64::from_be_bytes(
        key.get(32..40)
            .ok_or(CorruptValue)?
            .try_into()
            .map_err(|_| CorruptValue)?,
    ))
}

/// `graveyard`: deletion time (big-endian) ‖ account ‖ record id, so
/// tombstones older than a cutoff are a prefix range.
pub fn grave_key(deleted_at: u64, acct: &AcctId, id: &Id) -> [u8; 56] {
    let mut k = [0u8; 56];
    k[..8].copy_from_slice(&deleted_at.to_be_bytes());
    k[8..40].copy_from_slice(acct);
    k[40..].copy_from_slice(&id.0);
    k
}

pub fn split_grave_key(key: &[u8]) -> Result<(AcctId, Id), CorruptValue> {
    if key.len() != 56 {
        return Err(CorruptValue);
    }
    let acct: AcctId = key[8..40].try_into().map_err(|_| CorruptValue)?;
    let id = Id(key[40..].try_into().map_err(|_| CorruptValue)?);
    Ok((acct, id))
}

/// Inclusive bounds of all keys of `acct` in a table keyed by account ‖ N
/// bytes.
pub fn acct_range<const N: usize>(acct: &AcctId) -> (Vec<u8>, Vec<u8>) {
    let mut lo = acct.to_vec();
    lo.extend_from_slice(&[0u8; N]);
    let mut hi = acct.to_vec();
    hi.extend_from_slice(&[0xffu8; N]);
    (lo, hi)
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// `accounts` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Account {
    /// Last revision assigned (0: nothing stored yet).
    pub rev: u64,
    /// Sum of blob lengths.
    pub bytes: u64,
    /// Records, tombstones included.
    pub records: u64,
    /// Unix seconds.
    pub created: u64,
    /// Day (unix seconds / 86400) of the last authenticated request.
    pub last_seen_day: u64,
    /// Highest revision of a tombstone removed by garbage collection; a
    /// client whose `since` is below it may have missed a deletion.
    pub gc_floor: u64,
}

impl Account {
    const LEN: usize = 1 + 6 * 8;

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut v = [0u8; Self::LEN];
        v[0] = ACCOUNT_V1;
        let fields = [
            self.rev,
            self.bytes,
            self.records,
            self.created,
            self.last_seen_day,
            self.gc_floor,
        ];
        for (i, f) in fields.iter().enumerate() {
            v[1 + i * 8..9 + i * 8].copy_from_slice(&f.to_le_bytes());
        }
        v
    }

    pub fn decode(v: &[u8]) -> Result<Self, CorruptValue> {
        if v.len() != Self::LEN || v[0] != ACCOUNT_V1 {
            return Err(CorruptValue);
        }
        let f = |i: usize| u64_le(&v[1 + i * 8..9 + i * 8]);
        Ok(Account {
            rev: f(0)?,
            bytes: f(1)?,
            records: f(2)?,
            created: f(3)?,
            last_seen_day: f(4)?,
            gc_floor: f(5)?,
        })
    }
}

/// `records` value: the envelope and the blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub rev: u64,
    pub kind: Kind,
    pub vault_id: Id,
    pub deleted: bool,
    /// Unix seconds; 0 unless `deleted`.
    pub deleted_at: u64,
    pub blob: Vec<u8>,
}

impl Stored {
    const HEADER: usize = 1 + 8 + 1 + 16 + 1 + 8;

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::HEADER + self.blob.len());
        v.push(RECORD_V1);
        v.extend_from_slice(&self.rev.to_le_bytes());
        v.push(self.kind.to_u8());
        v.extend_from_slice(&self.vault_id.0);
        v.push(u8::from(self.deleted));
        v.extend_from_slice(&self.deleted_at.to_le_bytes());
        v.extend_from_slice(&self.blob);
        v
    }

    pub fn decode(v: &[u8]) -> Result<Self, CorruptValue> {
        if v.len() < Self::HEADER || v[0] != RECORD_V1 {
            return Err(CorruptValue);
        }
        Ok(Stored {
            rev: u64_le(&v[1..9])?,
            kind: Kind::from_u8(v[9]).map_err(|_| CorruptValue)?,
            vault_id: Id(v[10..26].try_into().map_err(|_| CorruptValue)?),
            deleted: match v[26] {
                0 => false,
                1 => true,
                _ => return Err(CorruptValue),
            },
            deleted_at: u64_le(&v[27..35])?,
            blob: v[Self::HEADER..].to_vec(),
        })
    }

    pub fn into_record(self, id: Id) -> Record {
        Record {
            id,
            kind: self.kind,
            vault_id: self.vault_id,
            rev: self.rev,
            deleted: self.deleted,
            blob: self.blob,
        }
    }
}

fn u64_le(b: &[u8]) -> Result<u64, CorruptValue> {
    Ok(u64::from_le_bytes(b.try_into().map_err(|_| CorruptValue)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_round_trip() {
        let a = Account {
            rev: 1,
            bytes: u64::MAX,
            records: 3,
            created: 4,
            last_seen_day: 5,
            gc_floor: 6,
        };
        assert_eq!(Account::decode(&a.encode()).unwrap(), a);
    }

    #[test]
    fn account_rejects_other_layouts() {
        let mut v = Account::default().encode();
        v[0] = 2;
        assert!(Account::decode(&v).is_err());
        assert!(Account::decode(&v[..10]).is_err());
    }

    #[test]
    fn stored_round_trip() {
        let s = Stored {
            rev: 42,
            kind: Kind::Folder,
            vault_id: Id([9; 16]),
            deleted: true,
            deleted_at: 1_800_000_000,
            blob: vec![1, 2, 3],
        };
        assert_eq!(Stored::decode(&s.encode()).unwrap(), s);
        let empty = Stored {
            blob: Vec::new(),
            ..s
        };
        assert_eq!(Stored::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn stored_rejects_garbage() {
        let s = Stored {
            rev: 1,
            kind: Kind::Entry,
            vault_id: Id([0; 16]),
            deleted: false,
            deleted_at: 0,
            blob: vec![],
        };
        let mut v = s.encode();
        v[9] = 7; // kind
        assert!(Stored::decode(&v).is_err());
        let mut v = s.encode();
        v[26] = 2; // deleted flag
        assert!(Stored::decode(&v).is_err());
        assert!(Stored::decode(&s.encode()[..20]).is_err());
    }

    #[test]
    fn change_keys_sort_by_revision() {
        let acct = [7u8; 32];
        let keys: Vec<_> = [1u64, 255, 256, 1 << 40]
            .iter()
            .map(|&r| change_key(&acct, r))
            .collect();
        assert!(keys.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(change_key_rev(&keys[2]).unwrap(), 256);
    }

    #[test]
    fn grave_key_round_trip() {
        let acct = [3u8; 32];
        let id = Id([4; 16]);
        let k = grave_key(99, &acct, &id);
        assert_eq!(split_grave_key(&k).unwrap(), (acct, id));
        assert!(grave_key(98, &[0xff; 32], &id) < k);
    }

    #[test]
    fn acct_range_covers_only_that_account() {
        let (lo, hi) = acct_range::<16>(&[5u8; 32]);
        let inside = record_key(&[5u8; 32], &Id([0x80; 16]));
        let before = record_key(&[4u8; 32], &Id([0xff; 16]));
        let after = record_key(&[6u8; 32], &Id([0; 16]));
        assert!(lo.as_slice() <= &inside[..] && &inside[..] <= hi.as_slice());
        assert!(&before[..] < lo.as_slice());
        assert!(&after[..] > hi.as_slice());
    }
}
