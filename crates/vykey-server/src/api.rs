//! The protocol, independent of the HTTP library: a [`Request`] in, a
//! [`Response`] out.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use sha2::{Digest, Sha256};
use vykey_sync_proto::{
    API_PREFIX, AccountCreated, AccountInfo, ChangesResponse, CreateAccount, DEFAULT_PAGE,
    ErrorBody, ErrorCode, Kind, MAX_BLOB_LEN, MAX_BODY_LEN, MAX_PAGE, MAX_PUSH_RECORDS,
    PushRequest, Token,
};

use crate::codec::AcctId;
use crate::limit::RateLimiter;
use crate::pow::{Pow, PowConfig};
use crate::store::{Quota, Storage, StoreError};

#[derive(Debug, Clone)]
pub struct Config {
    /// Anyone may create an account with `POST /v1/account`. Off by
    /// default: a server is private until its operator opens it.
    pub open_registration: bool,
    /// With open registration off, `POST /v1/account` still works with this
    /// key in the invite header.
    pub invite_key: Option<String>,
    pub quota: Quota,
    /// Seconds clients wait between polls.
    pub poll_after: u32,
    /// Account creations per address per hour.
    pub registrations_per_hour: u32,
    /// Failed authentications per address per 10 minutes.
    pub auth_failures_per_10min: u32,
    /// Proof of work for open registration; invited clients skip it.
    pub pow: Option<PowConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            open_registration: false,
            invite_key: None,
            quota: Quota {
                bytes: 10 * 1024 * 1024,
                records: 20_000,
            },
            poll_after: 300,
            registrations_per_hour: 10,
            auth_failures_per_10min: 30,
            pow: None,
        }
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    /// Path without the query string.
    pub path: &'a str,
    pub query: &'a str,
    pub authorization: Option<&'a str>,
    pub invite: Option<&'a str>,
    pub body: &'a [u8],
    pub ip: IpAddr,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// JSON, or empty for 204.
    pub body: Vec<u8>,
    /// Seconds, for 429.
    pub retry_after: Option<u64>,
}

impl Response {
    fn json<T: Serialize>(status: u16, value: &T) -> Self {
        Response {
            status,
            body: serde_json::to_vec(value).unwrap_or_default(),
            retry_after: None,
        }
    }

    fn no_content() -> Self {
        Response {
            status: 204,
            body: Vec::new(),
            retry_after: None,
        }
    }

    /// An error response, for failures before the API sees the request.
    pub fn error(code: ErrorCode, message: &str) -> Self {
        ApiError::new(code, message).into_response()
    }
}

/// An error answered with an [`ErrorBody`].
#[derive(Debug)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl ApiError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError {
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    fn rate_limited(retry_after: u64) -> Self {
        ApiError {
            retry_after: Some(retry_after),
            ..ApiError::new(ErrorCode::RateLimited, "too many requests")
        }
    }

    fn into_response(self) -> Response {
        let mut r = Response::json(
            self.code.status(),
            &ErrorBody {
                error: self.code,
                message: self.message,
            },
        );
        r.retry_after = self.retry_after;
        r
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NoAccount => ApiError::new(ErrorCode::Unauthorized, "unknown account"),
            StoreError::ResyncRequired => ApiError::new(
                ErrorCode::ResyncRequired,
                "pull everything from since=0 and reconcile",
            ),
            StoreError::QuotaExceeded => {
                ApiError::new(ErrorCode::QuotaExceeded, "account quota exceeded")
            }
            StoreError::Invalid(m) => ApiError::new(ErrorCode::BadRequest, m),
            e => {
                eprintln!("vykey-server: storage error: {e}");
                ApiError::new(ErrorCode::Internal, "internal error")
            }
        }
    }
}

/// What the server remembers about an account between requests, so that a
/// poll without changes does not touch the database.
#[derive(Clone, Copy)]
struct Cached {
    rev: u64,
    seen_day: u64,
}

pub type Clock = Box<dyn Fn() -> u64 + Send + Sync>;

pub struct Api {
    store: Arc<dyn Storage>,
    cfg: Config,
    clock: Clock,
    cache: Mutex<HashMap<AcctId, Cached>>,
    registrations: RateLimiter,
    auth_failures: RateLimiter,
    pow: Option<Pow>,
}

impl Api {
    pub fn new(store: Arc<dyn Storage>, cfg: Config) -> Self {
        Self::with_clock(store, cfg, Box::new(unix_now))
    }

    /// `clock` returns unix seconds.
    pub fn with_clock(store: Arc<dyn Storage>, cfg: Config, clock: Clock) -> Self {
        Api {
            pow: cfg
                .pow
                .map(|p| Pow::new(p).expect("no system randomness for the challenge key")),
            registrations: RateLimiter::new(cfg.registrations_per_hour, 3600),
            auth_failures: RateLimiter::new(cfg.auth_failures_per_10min, 600),
            store,
            cfg,
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn handle(&self, req: &Request) -> Response {
        match self.route(req) {
            Ok(r) => r,
            Err(e) => e.into_response(),
        }
    }

    fn route(&self, req: &Request) -> Result<Response, ApiError> {
        if req.body.len() > MAX_BODY_LEN {
            return Err(ApiError::new(ErrorCode::PayloadTooLarge, "body too large"));
        }
        let path = req
            .path
            .strip_prefix(API_PREFIX)
            .ok_or_else(|| ApiError::new(ErrorCode::NotFound, "not found"))?;
        match (req.method, path) {
            ("GET", "/health") => Ok(Response::json(200, &serde_json::json!({"status": "ok"}))),
            ("POST", "/account") => self.create_account(req),
            ("GET", "/account/challenge") => self.challenge(),
            ("GET", "/account") => self.account_info(req),
            ("DELETE", "/account") => self.delete_account(req),
            ("GET", "/changes") => self.changes(req),
            ("POST", "/push") => self.push(req),
            (_, "/health" | "/account" | "/account/challenge" | "/changes" | "/push") => Err(
                ApiError::new(ErrorCode::MethodNotAllowed, "method not allowed"),
            ),
            _ => Err(ApiError::new(ErrorCode::NotFound, "not found")),
        }
    }

    // -- accounts -----------------------------------------------------------

    /// A proof-of-work puzzle for open registration. 404 when the server
    /// does not ask for one, 403 when registration needs an invite.
    fn challenge(&self) -> Result<Response, ApiError> {
        let Some(pow) = &self.pow else {
            return Err(ApiError::new(
                ErrorCode::NotFound,
                "this server does not ask for proof of work",
            ));
        };
        if !self.cfg.open_registration {
            return Err(closed());
        }
        let c = pow.issue((self.clock)()).map_err(|e| {
            eprintln!("vykey-server: no randomness: {e}");
            ApiError::new(ErrorCode::Internal, "internal error")
        })?;
        Ok(Response::json(200, &c))
    }

    fn create_account(&self, req: &Request) -> Result<Response, ApiError> {
        let now = (self.clock)();
        // Counted before the invite check, so invite keys cannot be guessed
        // faster than accounts can be created.
        self.registrations
            .hit(req.ip, now)
            .map_err(ApiError::rate_limited)?;
        let invited = match (&self.cfg.invite_key, req.invite) {
            (Some(key), Some(given)) => constant_time_eq(key.as_bytes(), given.trim().as_bytes()),
            _ => false,
        };
        if !self.cfg.open_registration && !invited {
            return Err(closed());
        }
        if let Some(pow) = &self.pow
            && !invited
        {
            let failed = |m: &str| ApiError::new(ErrorCode::ChallengeFailed, m);
            let body: CreateAccount = serde_json::from_slice(req.body)
                .map_err(|_| failed("solve GET /v1/account/challenge and send it"))?;
            pow.verify(&body.challenge, body.nonce, now)
                .map_err(failed)?;
        }
        let token = create_account(self.store.as_ref(), now)?;
        if let Some(pow) = &self.pow {
            pow.record_registration(now);
        }
        self.remember(&account_id(&token), 0, now);
        Ok(Response::json(201, &AccountCreated { token }))
    }

    fn account_info(&self, req: &Request) -> Result<Response, ApiError> {
        let acct = self.authenticate(req)?;
        let a = self.store.account(&acct)?.ok_or_else(|| self.gone(&acct))?;
        Ok(Response::json(
            200,
            &AccountInfo {
                rev: a.rev,
                bytes: a.bytes,
                records: a.records,
                quota_bytes: self.cfg.quota.bytes,
                quota_records: self.cfg.quota.records,
                created: a.created,
            },
        ))
    }

    fn delete_account(&self, req: &Request) -> Result<Response, ApiError> {
        let acct = self.authenticate(req)?;
        self.store.delete_account(&acct)?;
        self.forget(&acct);
        Ok(Response::no_content())
    }

    // -- sync ---------------------------------------------------------------

    fn changes(&self, req: &Request) -> Result<Response, ApiError> {
        let acct = self.authenticate(req)?;
        let mut since = 0u64;
        let mut limit = DEFAULT_PAGE;
        for pair in req.query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let bad = || ApiError::new(ErrorCode::BadRequest, format!("invalid {k}"));
            match k {
                "since" => since = v.parse().map_err(|_| bad())?,
                "limit" => limit = v.parse::<usize>().map_err(|_| bad())?.clamp(1, MAX_PAGE),
                _ => {}
            }
        }

        if self.cached_rev(&acct) == Some(since) {
            return Ok(Response::json(
                200,
                &ChangesResponse {
                    records: Vec::new(),
                    until: since,
                    more: false,
                    poll_after: self.cfg.poll_after,
                },
            ));
        }
        let c = self
            .store
            .changes(&acct, since, limit)
            .map_err(|e| self.store_error(&acct, e))?;
        if !c.more {
            self.raise_rev(&acct, c.until);
        }
        Ok(Response::json(
            200,
            &ChangesResponse {
                records: c.records,
                until: c.until,
                more: c.more,
                poll_after: self.cfg.poll_after,
            },
        ))
    }

    fn push(&self, req: &Request) -> Result<Response, ApiError> {
        let acct = self.authenticate(req)?;
        let body: PushRequest = serde_json::from_slice(req.body)
            .map_err(|e| ApiError::new(ErrorCode::BadRequest, format!("invalid push: {e}")))?;
        validate_push(&body)?;
        let res = self
            .store
            .push(&acct, &body.records, self.cfg.quota, (self.clock)())
            .map_err(|e| self.store_error(&acct, e))?;
        self.raise_rev(&acct, res.rev);
        Ok(Response::json(200, &res))
    }

    // -- authentication and cache -------------------------------------------

    fn authenticate(&self, req: &Request) -> Result<AcctId, ApiError> {
        let now = (self.clock)();
        self.auth_failures
            .check(req.ip, now)
            .map_err(ApiError::rate_limited)?;
        let token = req
            .authorization
            .and_then(|h| h.strip_prefix("Bearer "))
            .and_then(|t| t.trim().parse::<Token>().ok());
        let Some(token) = token else {
            return Err(self.auth_failed(req.ip, now));
        };
        let acct = account_id(&token);
        let day = now / 86_400;

        let cached = self.lock_cache().get(&acct).copied();
        let (rev, seen_day) = match cached {
            Some(c) => (c.rev, c.seen_day),
            None => match self.store.account(&acct)? {
                Some(a) => (a.rev, a.last_seen_day),
                None => return Err(self.auth_failed(req.ip, now)),
            },
        };
        if seen_day != day {
            // At most one write per account per day.
            self.store
                .touch(&acct, day)
                .map_err(|e| self.store_error(&acct, e))?;
        }
        self.remember(&acct, rev, now);
        Ok(acct)
    }

    fn auth_failed(&self, ip: IpAddr, now: u64) -> ApiError {
        match self.auth_failures.hit(ip, now) {
            Err(wait) => ApiError::rate_limited(wait),
            Ok(()) => ApiError::new(ErrorCode::Unauthorized, "missing or unknown account token"),
        }
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, HashMap<AcctId, Cached>> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn cached_rev(&self, acct: &AcctId) -> Option<u64> {
        self.lock_cache().get(acct).map(|c| c.rev)
    }

    fn remember(&self, acct: &AcctId, rev: u64, now: u64) {
        let day = now / 86_400;
        let mut cache = self.lock_cache();
        let c = cache.entry(*acct).or_insert(Cached { rev, seen_day: day });
        // Revisions only grow; concurrent requests may report them out of
        // order.
        c.rev = c.rev.max(rev);
        c.seen_day = day;
    }

    fn raise_rev(&self, acct: &AcctId, rev: u64) {
        if let Some(c) = self.lock_cache().get_mut(acct) {
            c.rev = c.rev.max(rev);
        }
    }

    fn forget(&self, acct: &AcctId) {
        self.lock_cache().remove(acct);
    }

    /// The account vanished between authentication and use (deleted by a
    /// concurrent request).
    fn gone(&self, acct: &AcctId) -> ApiError {
        self.forget(acct);
        StoreError::NoAccount.into()
    }

    fn store_error(&self, acct: &AcctId, e: StoreError) -> ApiError {
        if matches!(e, StoreError::NoAccount) {
            self.forget(acct);
        }
        e.into()
    }
}

fn closed() -> ApiError {
    ApiError::new(
        ErrorCode::RegistrationClosed,
        "registration is closed on this server",
    )
}

/// Creates an account under a fresh random token.
pub fn create_account(store: &dyn Storage, now: u64) -> Result<Token, ApiError> {
    // A collision of 160 random bits does not happen; retry anyway rather
    // than hand out someone else's account.
    for _ in 0..3 {
        let mut bytes = [0u8; Token::LEN];
        getrandom::fill(&mut bytes).map_err(|e| {
            eprintln!("vykey-server: no randomness: {e}");
            ApiError::new(ErrorCode::Internal, "internal error")
        })?;
        let token = Token::from_bytes(bytes);
        match store.create_account(&account_id(&token), now) {
            Ok(()) => return Ok(token),
            Err(StoreError::AccountExists) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(ApiError::new(ErrorCode::Internal, "internal error"))
}

/// The server's key of an account: SHA-256 of the token. The token itself
/// is never stored.
pub fn account_id(token: &Token) -> AcctId {
    Sha256::digest(token.as_bytes()).into()
}

fn validate_push(req: &PushRequest) -> Result<(), ApiError> {
    if req.records.len() > MAX_PUSH_RECORDS {
        return Err(ApiError::new(
            ErrorCode::PayloadTooLarge,
            format!("at most {MAX_PUSH_RECORDS} records per push"),
        ));
    }
    let mut seen = HashSet::with_capacity(req.records.len());
    for r in &req.records {
        let bad = |m: &str| {
            Err(ApiError::new(
                ErrorCode::BadRequest,
                format!("record {}: {m}", r.id),
            ))
        };
        if !seen.insert(r.id) {
            return bad("listed twice");
        }
        if r.blob.len() > MAX_BLOB_LEN {
            return Err(ApiError::new(
                ErrorCode::PayloadTooLarge,
                format!("record {}: blob over {MAX_BLOB_LEN} bytes", r.id),
            ));
        }
        if r.deleted && !r.blob.is_empty() {
            return bad("a tombstone has no blob");
        }
        if !r.deleted && r.blob.is_empty() {
            return bad("empty blob");
        }
        if r.kind == Kind::Vault && r.vault_id != r.id {
            return bad("a vault record's vault_id is its own id");
        }
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::{Value, json};

    use super::*;
    use crate::store::RedbStore;

    const ID1: &str = "11111111-1111-4111-8111-111111111111";
    const ID2: &str = "22222222-2222-4222-8222-222222222222";
    const VAULT: &str = "00000000-0000-4000-8000-000000000000";

    struct Fixture {
        api: Api,
        store: Arc<RedbStore>,
        now: Arc<AtomicU64>,
    }

    fn open() -> Config {
        Config {
            open_registration: true,
            ..Config::default()
        }
    }

    fn fixture(cfg: Config) -> Fixture {
        let store = Arc::new(RedbStore::in_memory().unwrap());
        let now = Arc::new(AtomicU64::new(1_800_000_000));
        let clock = now.clone();
        let api = Api::with_clock(
            store.clone(),
            cfg,
            Box::new(move || clock.load(Ordering::SeqCst)),
        );
        Fixture { api, store, now }
    }

    fn ip(n: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, n])
    }

    impl Fixture {
        fn call(&self, method: &str, url: &str, token: Option<&str>, body: &str) -> (u16, Value) {
            self.call_from(ip(1), method, url, token, body, None)
        }

        fn call_from(
            &self,
            ip: IpAddr,
            method: &str,
            url: &str,
            token: Option<&str>,
            body: &str,
            invite: Option<&str>,
        ) -> (u16, Value) {
            let (path, query) = url.split_once('?').unwrap_or((url, ""));
            let auth = token.map(|t| format!("Bearer {t}"));
            let r = self.api.handle(&Request {
                method,
                path,
                query,
                authorization: auth.as_deref(),
                invite,
                body: body.as_bytes(),
                ip,
            });
            let v = if r.body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&r.body).unwrap()
            };
            (r.status, v)
        }

        fn register(&self) -> String {
            let (status, v) = self.call("POST", "/v1/account", None, "");
            assert_eq!(status, 201, "{v}");
            v["token"].as_str().unwrap().to_owned()
        }

        fn push(&self, token: &str, records: Value) -> (u16, Value) {
            self.call(
                "POST",
                "/v1/push",
                Some(token),
                &json!({ "records": records }).to_string(),
            )
        }
    }

    fn entry(id: &str, base_rev: u64, blob: &str) -> Value {
        json!({"id": id, "kind": "entry", "vault_id": VAULT, "base_rev": base_rev, "blob": blob})
    }

    #[test]
    fn health() {
        let f = fixture(open());
        assert_eq!(f.call("GET", "/v1/health", None, "").0, 200);
    }

    #[test]
    fn register_then_sync_round_trip() {
        let f = fixture(open());
        let token = f.register();
        assert!(token.parse::<Token>().is_ok());

        let (s, v) = f.push(
            &token,
            json!([entry(ID1, 0, "AAEC"), entry(ID2, 0, "Aw==")]),
        );
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["rev"], 2);
        assert_eq!(
            v["results"][0],
            json!({"status": "ok", "id": ID1, "rev": 1})
        );

        let (s, v) = f.call("GET", "/v1/changes?since=0", Some(&token), "");
        assert_eq!(s, 200);
        assert_eq!(v["until"], 2);
        assert_eq!(v["more"], false);
        assert_eq!(v["poll_after"], 300);
        assert_eq!(v["records"][0]["blob"], "AAEC");
        assert_eq!(v["records"][1]["id"], ID2);

        let (_, v) = f.call("GET", "/v1/account", Some(&token), "");
        assert_eq!(
            (v["rev"].as_u64(), v["records"].as_u64()),
            (Some(2), Some(2))
        );
        assert_eq!(v["bytes"], 4);
    }

    #[test]
    fn poll_without_changes_and_after_a_change() {
        let f = fixture(open());
        let token = f.register();
        f.push(&token, json!([entry(ID1, 0, "AQ==")]));
        let (_, v) = f.call("GET", "/v1/changes?since=1", Some(&token), "");
        assert_eq!(v["records"], json!([]));
        assert_eq!(v["until"], 1);

        f.push(&token, json!([entry(ID1, 1, "Ag==")]));
        let (_, v) = f.call("GET", "/v1/changes?since=1", Some(&token), "");
        assert_eq!(v["records"][0]["rev"], 2);
        assert_eq!(v["until"], 2);
    }

    #[test]
    fn paging_through_changes() {
        let f = fixture(open());
        let token = f.register();
        f.push(
            &token,
            json!([entry(ID1, 0, "AQ=="), entry(ID2, 0, "Ag==")]),
        );
        let (_, v) = f.call("GET", "/v1/changes?since=0&limit=1", Some(&token), "");
        assert_eq!(
            (v["until"].as_u64(), v["more"].as_bool()),
            (Some(1), Some(true))
        );
        let (_, v) = f.call("GET", "/v1/changes?since=1&limit=1", Some(&token), "");
        assert_eq!(
            (v["until"].as_u64(), v["more"].as_bool()),
            (Some(2), Some(false))
        );
        // limit=0 is clamped to 1, not an endless empty page.
        let (_, v) = f.call("GET", "/v1/changes?limit=0", Some(&token), "");
        assert_eq!(v["records"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn conflict_returns_current_version() {
        let f = fixture(open());
        let token = f.register();
        f.push(&token, json!([entry(ID1, 0, "AQ==")]));
        f.push(&token, json!([entry(ID1, 1, "Ag==")]));
        let (s, v) = f.push(&token, json!([entry(ID1, 1, "Aw==")]));
        assert_eq!(s, 200);
        assert_eq!(v["results"][0]["status"], "conflict");
        assert_eq!(v["results"][0]["current"]["blob"], "Ag==");
        assert_eq!(v["rev"], 2);
    }

    #[test]
    fn since_ahead_of_server_requires_resync() {
        let f = fixture(open());
        let token = f.register();
        let (s, v) = f.call("GET", "/v1/changes?since=5", Some(&token), "");
        assert_eq!((s, v["error"].as_str()), (410, Some("resync_required")));
    }

    #[test]
    fn bad_requests() {
        let f = fixture(open());
        let token = f.register();
        let code = |r: (u16, Value)| (r.0, r.1["error"].as_str().unwrap_or("").to_owned());

        assert_eq!(
            code(f.call("GET", "/v1/changes?since=x", Some(&token), "")).0,
            400
        );
        assert_eq!(code(f.call("POST", "/v1/push", Some(&token), "{")).0, 400);
        let tomb_with_blob = json!([{"id": ID1, "kind": "entry", "vault_id": VAULT,
            "base_rev": 0, "deleted": true, "blob": "AQ=="}]);
        let vault_elsewhere = json!([{"id": ID1, "kind": "vault", "vault_id": VAULT,
            "base_rev": 0, "blob": "AQ=="}]);
        for records in [
            json!([entry(ID1, 0, "AQ=="), entry(ID1, 0, "Ag==")]),
            json!([entry(ID1, 0, "")]),
            tomb_with_blob,
            vault_elsewhere,
            json!([entry("not-a-uuid", 0, "AQ==")]),
            json!([entry(ID1, 0, "not base64!")]),
        ] {
            let (s, v) = f.push(&token, records.clone());
            assert_eq!(
                (s, v["error"].as_str()),
                (400, Some("bad_request")),
                "{records}"
            );
        }

        let big = data_encoding_free_base64(&vec![0u8; MAX_BLOB_LEN + 1]);
        assert_eq!(f.push(&token, json!([entry(ID1, 0, &big)])).0, 413);
        let many: Vec<Value> = (0..=MAX_PUSH_RECORDS)
            .map(|i| entry(&format!("{i:08x}-0000-4000-8000-000000000000"), 0, "AQ=="))
            .collect();
        assert_eq!(f.push(&token, Value::Array(many)).0, 413);

        // Nothing of the above was stored.
        let (_, v) = f.call("GET", "/v1/account", Some(&token), "");
        assert_eq!(v["rev"], 0);
    }

    /// Base64 without pulling the encoder into the server's dependencies.
    fn data_encoding_free_base64(bytes: &[u8]) -> String {
        let r = vykey_sync_proto::Record {
            id: vykey_sync_proto::Id([0; 16]),
            kind: Kind::Entry,
            vault_id: vykey_sync_proto::Id([0; 16]),
            rev: 0,
            deleted: false,
            blob: bytes.to_vec(),
        };
        serde_json::to_value(r).unwrap()["blob"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn routing() {
        let f = fixture(open());
        assert_eq!(f.call("GET", "/v1/nope", None, "").0, 404);
        assert_eq!(f.call("GET", "/push", None, "").0, 404);
        assert_eq!(f.call("PUT", "/v1/push", None, "").0, 405);
        assert_eq!(f.call("POST", "/v1/health", None, "").0, 405);
    }

    #[test]
    fn unauthenticated_requests_are_rejected() {
        let f = fixture(open());
        let unknown = Token::from_bytes([3; Token::LEN]).to_string();
        for token in [None, Some("garbage"), Some(unknown.as_str())] {
            let (s, v) = f.call("GET", "/v1/changes", token, "");
            assert_eq!((s, v["error"].as_str()), (401, Some("unauthorized")));
        }
        // Not "Bearer".
        let r = f.api.handle(&Request {
            method: "GET",
            path: "/v1/account",
            query: "",
            authorization: Some(&format!("Basic {unknown}")),
            invite: None,
            body: b"",
            ip: ip(1),
        });
        assert_eq!(r.status, 401);
    }

    #[test]
    fn repeated_auth_failures_lock_out_the_address() {
        let f = fixture(Config {
            auth_failures_per_10min: 3,
            ..open()
        });
        let token = f.register();
        for _ in 0..3 {
            assert_eq!(f.call("GET", "/v1/account", Some("bad"), "").0, 401);
        }
        let r = f.api.handle(&Request {
            method: "GET",
            path: "/v1/account",
            query: "",
            authorization: Some(&format!("Bearer {token}")),
            invite: None,
            body: b"",
            ip: ip(1),
        });
        assert_eq!(r.status, 429, "even a valid token waits");
        assert_eq!(r.retry_after, Some(600));
        // Other addresses are unaffected; the lockout ends.
        assert_eq!(
            f.call_from(ip(2), "GET", "/v1/account", Some(&token), "", None)
                .0,
            200
        );
        f.now.fetch_add(600, Ordering::SeqCst);
        assert_eq!(f.call("GET", "/v1/account", Some(&token), "").0, 200);
    }

    #[test]
    fn registration_is_rate_limited() {
        let f = fixture(Config {
            registrations_per_hour: 2,
            ..open()
        });
        f.register();
        f.register();
        let (s, v) = f.call("POST", "/v1/account", None, "");
        assert_eq!((s, v["error"].as_str()), (429, Some("rate_limited")));
        assert_eq!(
            f.call_from(ip(2), "POST", "/v1/account", None, "", None).0,
            201
        );
    }

    #[test]
    fn registration_is_closed_by_default() {
        let f = fixture(Config::default());
        let (s, v) = f.call("POST", "/v1/account", None, "");
        assert_eq!((s, v["error"].as_str()), (403, Some("registration_closed")));
    }

    #[test]
    fn closed_registration_and_invite_key() {
        let f = fixture(Config {
            open_registration: false,
            invite_key: Some("letmein".into()),
            ..open()
        });
        let (s, v) = f.call("POST", "/v1/account", None, "");
        assert_eq!((s, v["error"].as_str()), (403, Some("registration_closed")));
        let wrong = f.call_from(ip(1), "POST", "/v1/account", None, "", Some("letmeout"));
        assert_eq!(wrong.0, 403);
        let ok = f.call_from(ip(1), "POST", "/v1/account", None, "", Some(" letmein "));
        assert_eq!(ok.0, 201);
    }

    #[test]
    fn delete_account() {
        let f = fixture(open());
        let token = f.register();
        f.push(&token, json!([entry(ID1, 0, "AQ==")]));
        assert_eq!(f.call("DELETE", "/v1/account", Some(&token), "").0, 204);
        assert_eq!(f.call("GET", "/v1/changes", Some(&token), "").0, 401);
        assert_eq!(f.store.stats().unwrap().accounts, 0);
    }

    #[test]
    fn quota_exceeded() {
        let f = fixture(Config {
            quota: Quota {
                bytes: 2,
                records: 10,
            },
            ..open()
        });
        let token = f.register();
        let (s, v) = f.push(&token, json!([entry(ID1, 0, "AQID")]));
        assert_eq!((s, v["error"].as_str()), (507, Some("quota_exceeded")));
    }

    #[test]
    fn last_seen_is_written_once_a_day() {
        let f = fixture(open());
        let token = f.register();
        let acct = account_id(&token.parse().unwrap());
        let day = f.now.load(Ordering::SeqCst) / 86_400;
        f.call("GET", "/v1/changes", Some(&token), "");
        assert_eq!(f.store.account(&acct).unwrap().unwrap().last_seen_day, day);
        f.now.fetch_add(86_400, Ordering::SeqCst);
        f.call("GET", "/v1/changes", Some(&token), "");
        assert_eq!(
            f.store.account(&acct).unwrap().unwrap().last_seen_day,
            day + 1
        );
    }

    #[test]
    fn token_is_not_stored() {
        let f = fixture(open());
        let token: Token = f.register().parse().unwrap();
        let acct = account_id(&token);
        assert_ne!(&acct[..Token::LEN], token.as_bytes());
        assert!(f.store.account(&acct).unwrap().is_some());
    }

    fn with_pow() -> Config {
        Config {
            pow: Some(PowConfig {
                base_bits: 8,
                target_per_hour: 100,
            }),
            ..open()
        }
    }

    fn solve(f: &Fixture) -> String {
        let (s, v) = f.call("GET", "/v1/account/challenge", None, "");
        assert_eq!(s, 200, "{v}");
        let c: vykey_sync_proto::Challenge = serde_json::from_value(v).unwrap();
        let nonce = vykey_sync_proto::pow::solve(&c.challenge, c.difficulty).unwrap();
        serde_json::to_string(&CreateAccount {
            challenge: c.challenge,
            nonce,
        })
        .unwrap()
    }

    #[test]
    fn no_challenge_without_pow() {
        let f = fixture(open());
        let (s, v) = f.call("GET", "/v1/account/challenge", None, "");
        assert_eq!((s, v["error"].as_str()), (404, Some("not_found")));
        // A body is ignored.
        assert_eq!(f.call("POST", "/v1/account", None, "{\"x\":1}").0, 201);
    }

    #[test]
    fn registration_with_proof_of_work() {
        let f = fixture(with_pow());
        let (s, v) = f.call("GET", "/v1/account/challenge", None, "");
        assert_eq!(
            (v["difficulty"].as_u64(), v["expires_in"].as_u64()),
            (Some(8), Some(600))
        );
        assert_eq!(s, 200);

        for body in ["", "{}", r#"{"challenge":"AQID","nonce":1}"#] {
            let (s, v) = f.call("POST", "/v1/account", None, body);
            assert_eq!(
                (s, v["error"].as_str()),
                (403, Some("challenge_failed")),
                "{body}"
            );
        }

        let body = solve(&f);
        let (s, v) = f.call("POST", "/v1/account", None, &body);
        assert_eq!(s, 201, "{v}");
        assert!(v["token"].as_str().unwrap().starts_with("vy1-"));
        let (s, v) = f.call("POST", "/v1/account", None, &body);
        assert_eq!(
            (s, v["message"].as_str()),
            (403, Some("challenge already used"))
        );
    }

    #[test]
    fn wrong_nonce_is_refused() {
        let f = fixture(with_pow());
        let mut body: CreateAccount = serde_json::from_str(&solve(&f)).unwrap();
        body.nonce = (0..)
            .find(|&n| !vykey_sync_proto::pow::check(&body.challenge, n, 8))
            .unwrap();
        let (s, v) = f.call(
            "POST",
            "/v1/account",
            None,
            &serde_json::to_string(&body).unwrap(),
        );
        assert_eq!((s, v["message"].as_str()), (403, Some("wrong solution")));
    }

    #[test]
    fn expired_challenge_is_refused() {
        let f = fixture(with_pow());
        let body = solve(&f);
        f.now.fetch_add(crate::pow::TTL, Ordering::SeqCst);
        let (s, v) = f.call("POST", "/v1/account", None, &body);
        assert_eq!((s, v["message"].as_str()), (403, Some("challenge expired")));
    }

    #[test]
    fn invited_clients_skip_proof_of_work() {
        let f = fixture(Config {
            open_registration: false,
            invite_key: Some("k".into()),
            ..with_pow()
        });
        let (s, v) = f.call("GET", "/v1/account/challenge", None, "");
        assert_eq!((s, v["error"].as_str()), (403, Some("registration_closed")));
        let ok = f.call_from(ip(1), "POST", "/v1/account", None, "", Some("k"));
        assert_eq!(ok.0, 201);
        let (s, v) = f.call("POST", "/v1/account", None, "");
        assert_eq!((s, v["error"].as_str()), (403, Some("registration_closed")));
    }

    #[test]
    fn challenge_method_not_allowed() {
        let f = fixture(with_pow());
        assert_eq!(f.call("POST", "/v1/account/challenge", None, "").0, 405);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
