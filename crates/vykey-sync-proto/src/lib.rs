//! Wire types of the vykey sync protocol (`docs/sync-protocol.md`).
//!
//! The server stores opaque records: it never sees vault contents, only the
//! envelope below (id, kind, vault, revision, tombstone flag) and an
//! encrypted blob. Every type here is shared by the client and the server.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Path prefix of every endpoint.
pub const API_PREFIX: &str = "/v1";
/// Header carrying the invite key when open registration is off.
pub const INVITE_HEADER: &str = "X-Vykey-Invite";

/// Largest blob of one record, in bytes (after base64 decoding).
pub const MAX_BLOB_LEN: usize = 64 * 1024;
/// Most records in one push.
pub const MAX_PUSH_RECORDS: usize = 500;
/// Largest request body the server reads, in bytes.
pub const MAX_BODY_LEN: usize = 8 * 1024 * 1024;
/// Page size of `GET /v1/changes` when `limit` is not given.
pub const DEFAULT_PAGE: usize = 500;
/// Largest page of `GET /v1/changes`.
pub const MAX_PAGE: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Token,
    Id,
    Kind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParseError::Token => "invalid account token",
            ParseError::Id => "invalid record id",
            ParseError::Kind => "invalid record kind",
        })
    }
}

impl std::error::Error for ParseError {}

// ---------------------------------------------------------------------------
// Account token
// ---------------------------------------------------------------------------

/// Anonymous account token: 160 random bits, the only credential of an
/// account. Shown as `vy1-` and eight groups of four base32 characters.
///
/// Whoever holds it can download the vault salts and verifiers (and so try
/// master passwords offline) and overwrite records, so it is a secret even
/// though it looks like an identifier. `Debug` does not print it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token([u8; Token::LEN]);

impl Token {
    pub const LEN: usize = 20;
    const PREFIX: &'static str = "VY1";

    /// Token from random bytes (the caller supplies the randomness).
    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Token(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body = data_encoding::BASE32_NOPAD.encode(&self.0);
        f.write_str("vy1")?;
        for group in body.as_bytes().chunks(4) {
            f.write_str("-")?;
            // Base32 output is ASCII.
            f.write_str(std::str::from_utf8(group).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

impl FromStr for Token {
    type Err = ParseError;

    /// Accepts the displayed form with any case, spaces and dashes, so a
    /// token typed by hand or copied with line breaks still parses.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let clean: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        // '1' is not in the base32 alphabet, so the prefix is unambiguous.
        let body = clean.strip_prefix(Self::PREFIX).ok_or(ParseError::Token)?;
        let bytes = data_encoding::BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| ParseError::Token)?;
        Ok(Token(bytes.try_into().map_err(|_| ParseError::Token)?))
    }
}

impl Serialize for Token {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Token {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Record id
// ---------------------------------------------------------------------------

/// Id of a record: the UUID of the vault, folder or entry on the client.
/// Written as a hyphenated lowercase UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(pub [u8; 16]);

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Id {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let s = s.as_bytes();
        if s.len() != 36 || [8, 13, 18, 23].iter().any(|&i| s[i] != b'-') {
            return Err(ParseError::Id);
        }
        let hex: Vec<u8> = s.iter().copied().filter(|&c| c != b'-').collect();
        let mut out = [0u8; 16];
        for (byte, pair) in out.iter_mut().zip(hex.chunks(2)) {
            *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        Ok(Id(out))
    }
}

fn hex_digit(c: u8) -> Result<u8, ParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ParseError::Id),
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// What a record is. A vault record carries the vault header (salt, wrapped
/// key, verifier, name); folder and entry records belong to a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Vault,
    Folder,
    Entry,
}

impl Kind {
    pub fn to_u8(self) -> u8 {
        match self {
            Kind::Vault => 0,
            Kind::Folder => 1,
            Kind::Entry => 2,
        }
    }

    pub fn from_u8(v: u8) -> Result<Self, ParseError> {
        match v {
            0 => Ok(Kind::Vault),
            1 => Ok(Kind::Folder),
            2 => Ok(Kind::Entry),
            _ => Err(ParseError::Kind),
        }
    }
}

/// A record as stored on the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: Id,
    pub kind: Kind,
    /// The vault the record belongs to; a vault record's own id.
    pub vault_id: Id,
    /// Revision of the last change, assigned by the server.
    pub rev: u64,
    /// Tombstone: the record was deleted; `blob` is empty.
    pub deleted: bool,
    #[serde(with = "base64")]
    pub blob: Vec<u8>,
}

/// One record of a push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRecord {
    pub id: Id,
    pub kind: Kind,
    pub vault_id: Id,
    /// Revision the change is based on: the `rev` the client last saw, or 0
    /// for a record the server has never had. A mismatch is a conflict.
    pub base_rev: u64,
    #[serde(default)]
    pub deleted: bool,
    /// Empty for a tombstone, non-empty otherwise.
    #[serde(with = "base64", default)]
    pub blob: Vec<u8>,
}

/// `POST /v1/push` body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRequest {
    pub records: Vec<PushRecord>,
}

/// Outcome of one pushed record, in the order of the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PushResult {
    /// Stored under the new revision `rev`.
    Ok { id: Id, rev: u64 },
    /// Not stored: `base_rev` did not match. `current` is the server's
    /// version (`None` if the server has no such record, e.g. a tombstone
    /// removed by garbage collection).
    Conflict { id: Id, current: Option<Record> },
}

/// `POST /v1/push` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushResponse {
    pub results: Vec<PushResult>,
    /// Account revision after the push.
    pub rev: u64,
}

/// `GET /v1/changes?since=N` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangesResponse {
    /// Records changed after `since`, by ascending `rev`.
    pub records: Vec<Record>,
    /// The client is up to date to this revision: pass it as the next
    /// `since`.
    pub until: u64,
    /// More changes follow; ask again with `since = until`.
    pub more: bool,
    /// Seconds the client should wait before polling again.
    pub poll_after: u32,
}

/// `GET /v1/account/challenge` response: a proof-of-work puzzle that
/// `POST /v1/account` needs on servers that ask for one (others answer
/// 404). Solve it with [`pow::solve`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// Opaque, signed by the server; hashed as is.
    #[serde(with = "base64")]
    pub challenge: Vec<u8>,
    /// Leading zero bits the hash must have.
    pub difficulty: u8,
    /// Seconds the challenge stays valid.
    pub expires_in: u32,
}

/// `POST /v1/account` body on servers that ask for proof of work; empty
/// otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccount {
    #[serde(with = "base64")]
    pub challenge: Vec<u8>,
    pub nonce: u64,
}

/// `POST /v1/account` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCreated {
    pub token: Token,
}

/// `GET /v1/account` response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Current account revision.
    pub rev: u64,
    /// Bytes of stored blobs.
    pub bytes: u64,
    /// Stored records, tombstones included.
    pub records: u64,
    pub quota_bytes: u64,
    pub quota_records: u64,
    /// Unix seconds.
    pub created: u64,
}

/// Body of every error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 400: malformed request.
    BadRequest,
    /// 401: missing, malformed or unknown token.
    Unauthorized,
    /// 403: open registration is off and no valid invite key was given.
    RegistrationClosed,
    /// 403: the proof of work is missing, wrong, expired or already used;
    /// get a new challenge.
    ChallengeFailed,
    /// 404
    NotFound,
    /// 405
    MethodNotAllowed,
    /// 410: `since` is older than the oldest kept tombstone; the client must
    /// pull everything from `since=0` and drop local records the server no
    /// longer has (unless changed locally).
    ResyncRequired,
    /// 413: body or blob too large, or too many records in one push.
    PayloadTooLarge,
    /// 507: the push would exceed the account quota; nothing was stored.
    QuotaExceeded,
    /// 429: see the `Retry-After` header.
    RateLimited,
    /// 500
    Internal,
}

impl ErrorCode {
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::RegistrationClosed | ErrorCode::ChallengeFailed => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::MethodNotAllowed => 405,
            ErrorCode::ResyncRequired => 410,
            ErrorCode::PayloadTooLarge => 413,
            ErrorCode::RateLimited => 429,
            ErrorCode::Internal => 500,
            ErrorCode::QuotaExceeded => 507,
        }
    }
}

/// Proof of work for account creation: find a `nonce` such that
/// `SHA-256(challenge ‖ nonce as 8 little-endian bytes)` starts with
/// `difficulty` zero bits. About `2^difficulty` hashes on average.
pub mod pow {
    use sha2::{Digest, Sha256};

    pub fn hash(challenge: &[u8], nonce: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(challenge);
        h.update(nonce.to_le_bytes());
        h.finalize().into()
    }

    pub fn leading_zero_bits(bytes: &[u8]) -> u32 {
        let mut n = 0;
        for &b in bytes {
            if b == 0 {
                n += 8;
            } else {
                return n + b.leading_zeros();
            }
        }
        n
    }

    pub fn check(challenge: &[u8], nonce: u64, difficulty: u8) -> bool {
        leading_zero_bits(&hash(challenge, nonce)) >= u32::from(difficulty)
    }

    /// Highest difficulty a client should accept; servers never ask more.
    /// 32 bits is minutes of CPU, far past any sane registration cost.
    pub const MAX_DIFFICULTY: u8 = 32;

    /// The first nonce that solves the challenge, or `None` above
    /// [`MAX_DIFFICULTY`] (a broken or hostile server). Blocks for as long
    /// as it takes: on a 2025 laptop CPU about 0.2 s at difficulty 22 and
    /// 1 s at 24; each bit doubles it.
    pub fn solve(challenge: &[u8], difficulty: u8) -> Option<u64> {
        if difficulty > MAX_DIFFICULTY {
            return None;
        }
        (0..=u64::MAX).find(|&n| check(challenge, n, difficulty))
    }
}

/// Blobs as standard base64 with padding.
mod base64 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip() {
        let t = Token::from_bytes(std::array::from_fn(|i| i as u8 * 13));
        let s = t.to_string();
        assert_eq!(s.len(), 4 + 8 * 5 - 1);
        assert!(s.starts_with("vy1-"));
        assert_eq!(s.parse::<Token>().unwrap(), t);
    }

    #[test]
    fn token_parse_is_lenient() {
        let t = Token::from_bytes([0xa5; Token::LEN]);
        let messy = t.to_string().to_lowercase().replace('-', " - ") + "\n";
        assert_eq!(messy.parse::<Token>().unwrap(), t);
        let compact: String = t.to_string().chars().filter(|&c| c != '-').collect();
        assert_eq!(compact.parse::<Token>().unwrap(), t);
    }

    #[test]
    fn token_parse_rejects_bad_input() {
        let good = Token::from_bytes([7; Token::LEN]).to_string();
        for bad in [
            "",
            "vy1",
            &good[..good.len() - 1],         // too short
            &format!("{good}A"),             // too long
            &good.replacen("vy1", "vy2", 1), // other version
            &good.replacen("vy1-", "", 1),   // no prefix
            &good.replacen('A', "8", 1),     // '8' is not base32
        ] {
            assert_eq!(bad.parse::<Token>(), Err(ParseError::Token), "{bad:?}");
        }
    }

    #[test]
    fn token_debug_hides_secret() {
        let t = Token::from_bytes([1; Token::LEN]);
        assert_eq!(format!("{t:?}"), "Token(..)");
    }

    #[test]
    fn id_round_trip() {
        let s = "889d5e79-94b2-4d3a-9fd4-5726fcc86288";
        let id: Id = s.parse().unwrap();
        assert_eq!(id.0[0], 0x88);
        assert_eq!(id.to_string(), s);
        assert_eq!(s.to_uppercase().parse::<Id>().unwrap(), id);
    }

    #[test]
    fn id_rejects_bad_input() {
        for bad in [
            "",
            "889d5e7994b24d3a9fd45726fcc86288",
            "889d5e79-94b2-4d3a-9fd4-5726fcc8628",
            "889d5e79-94b2-4d3a-9fd4-5726fcc8628g",
            "889d5e79+94b2-4d3a-9fd4-5726fcc86288",
        ] {
            assert_eq!(bad.parse::<Id>(), Err(ParseError::Id), "{bad:?}");
        }
    }

    #[test]
    fn kind_byte_round_trip() {
        for k in [Kind::Vault, Kind::Folder, Kind::Entry] {
            assert_eq!(Kind::from_u8(k.to_u8()), Ok(k));
        }
        assert_eq!(Kind::from_u8(3), Err(ParseError::Kind));
    }

    #[test]
    fn push_json_shape() {
        let id: Id = "889d5e79-94b2-4d3a-9fd4-5726fcc86288".parse().unwrap();
        let req = PushRequest {
            records: vec![PushRecord {
                id,
                kind: Kind::Entry,
                vault_id: id,
                base_rev: 0,
                deleted: false,
                blob: b"\x01\x02\x03".to_vec(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["records"][0]["kind"], "entry");
        assert_eq!(json["records"][0]["blob"], "AQID");
        let back: PushRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);

        let res = PushResult::Conflict { id, current: None };
        let json = serde_json::to_value(&res).unwrap();
        assert_eq!(json["status"], "conflict");
        assert!(json["current"].is_null());
    }

    #[test]
    fn tombstone_push_may_omit_blob() {
        let json = r#"{"id":"889d5e79-94b2-4d3a-9fd4-5726fcc86288","kind":"folder",
            "vault_id":"889d5e79-94b2-4d3a-9fd4-5726fcc86288","base_rev":4,"deleted":true}"#;
        let r: PushRecord = serde_json::from_str(json).unwrap();
        assert!(r.deleted && r.blob.is_empty());
    }

    #[test]
    fn pow_leading_zero_bits() {
        assert_eq!(pow::leading_zero_bits(&[0xff]), 0);
        assert_eq!(pow::leading_zero_bits(&[0x01]), 7);
        assert_eq!(pow::leading_zero_bits(&[0, 0x10, 0]), 11);
        assert_eq!(pow::leading_zero_bits(&[0, 0]), 16);
    }

    #[test]
    fn pow_solve_and_check() {
        let c = b"some challenge";
        let n = pow::solve(c, 12).unwrap();
        assert!(pow::check(c, n, 12));
        assert!(pow::leading_zero_bits(&pow::hash(c, n)) >= 12);
        // The first solution: every smaller nonce fails.
        assert!((0..n).all(|m| !pow::check(c, m, 12)));
        assert_eq!(pow::solve(c, pow::MAX_DIFFICULTY + 1), None);
        assert_eq!(pow::solve(c, 0), Some(0));
    }

    #[test]
    fn create_account_json() {
        let body = CreateAccount {
            challenge: vec![1, 2, 3],
            nonce: 42,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json, serde_json::json!({"challenge": "AQID", "nonce": 42}));
        assert_eq!(serde_json::from_value::<CreateAccount>(json).unwrap(), body);
        let err = serde_json::to_value(ErrorCode::ChallengeFailed).unwrap();
        assert_eq!(err, "challenge_failed");
        assert_eq!(ErrorCode::ChallengeFailed.status(), 403);
    }

    #[test]
    fn error_code_json() {
        let body = ErrorBody {
            error: ErrorCode::ResyncRequired,
            message: String::new(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["error"], "resync_required");
    }
}
