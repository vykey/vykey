//! HTTP client for the sync server (ureq, rustls).

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use vykey_sync_proto::{
    AccountCreated, AccountInfo, Challenge, ChangesResponse, CreateAccount, ErrorBody, ErrorCode,
    INVITE_HEADER, PushRequest, PushResponse, Token, pow,
};

use super::{AddressError, SyncError, Transport};

/// Longest a request may take, connecting included.
const TIMEOUT: Duration = Duration::from_secs(60);
/// Largest response read (a page of changes can be big).
const MAX_RESPONSE: u64 = 96 * 1024 * 1024;

pub struct HttpClient {
    base: String,
    agent: ureq::Agent,
    auth: Option<String>,
}

/// Checks and normalises a server address: `https://` is added when no
/// scheme is given; plain `http://` only for this machine, since the token
/// would travel in the clear.
pub fn normalize_server_url(input: &str) -> Result<String, SyncError> {
    let bad = || SyncError::Address(AddressError::Invalid);
    let s = input.trim();
    let (scheme, rest) = match s.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("https".to_owned(), s),
    };
    if scheme != "https" && scheme != "http" {
        return Err(bad());
    }
    let rest = rest.trim_end_matches('/');
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains(char::is_whitespace) || host.contains('@') {
        return Err(bad());
    }
    if scheme == "http" {
        let name = host
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
            .map_or(host, |(name, _)| name);
        if !matches!(name, "localhost" | "127.0.0.1" | "[::1]") {
            return Err(SyncError::Address(AddressError::Insecure));
        }
    }
    Ok(format!("{scheme}://{rest}"))
}

impl HttpClient {
    pub fn new(server: &str) -> Result<Self, SyncError> {
        let base = normalize_server_url(server)?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(TIMEOUT))
            .user_agent(concat!("vykey/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(HttpClient {
            base,
            agent,
            auth: None,
        })
    }

    pub fn with_token(mut self, token: &Token) -> Self {
        self.auth = Some(format!("Bearer {token}"));
        self
    }

    pub fn server_url(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, SyncError> {
        let mut req = self.agent.get(self.url(path));
        if let Some(a) = &self.auth {
            req = req.header("Authorization", a);
        }
        read(req.call())
    }

    fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: Option<&B>,
        invite: Option<&str>,
    ) -> Result<T, SyncError> {
        let mut req = self.agent.post(self.url(path));
        if let Some(a) = &self.auth {
            req = req.header("Authorization", a);
        }
        if let Some(k) = invite {
            req = req.header(INVITE_HEADER, k);
        }
        read(match body {
            Some(b) => req.send_json(b),
            None => req.send_empty(),
        })
    }

    /// Creates an account. With an invite key the server skips proof of
    /// work; otherwise a challenge is solved if the server asks for one
    /// (seconds of CPU: call it off the UI thread).
    pub fn create_account(&self, invite: Option<&str>) -> Result<Token, SyncError> {
        let invite = invite.map(str::trim).filter(|k| !k.is_empty());
        if invite.is_some() {
            let r: AccountCreated = self.post("/v1/account", None::<&()>, invite)?;
            return Ok(r.token);
        }
        // A challenge can expire or predate a server restart: one retry.
        for attempt in 0..2 {
            let challenge = match self.get::<Challenge>("/v1/account/challenge") {
                Ok(c) => Some(c),
                Err(e) if e.code() == Some(ErrorCode::NotFound) => None,
                Err(e) => return Err(e),
            };
            let result = match challenge {
                None => self.post::<AccountCreated, ()>("/v1/account", None, None),
                Some(c) => {
                    let nonce = pow::solve(&c.challenge, c.difficulty).ok_or_else(|| {
                        SyncError::Protocol(format!(
                            "the server asks for an unreasonable proof of work ({} bits)",
                            c.difficulty
                        ))
                    })?;
                    let body = CreateAccount {
                        challenge: c.challenge,
                        nonce,
                    };
                    self.post("/v1/account", Some(&body), None)
                }
            };
            match result {
                Err(e) if e.code() == Some(ErrorCode::ChallengeFailed) && attempt == 0 => continue,
                other => return other.map(|r| r.token),
            }
        }
        unreachable!("the loop returns on its second attempt")
    }

    pub fn account_info(&self) -> Result<AccountInfo, SyncError> {
        self.get("/v1/account")
    }
}

impl Transport for HttpClient {
    fn changes(&self, since: u64, limit: usize) -> Result<ChangesResponse, SyncError> {
        self.get(&format!("/v1/changes?since={since}&limit={limit}"))
    }

    fn push(&self, req: &PushRequest) -> Result<PushResponse, SyncError> {
        self.post("/v1/push", Some(req), None)
    }
}

fn read<T: DeserializeOwned>(
    resp: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<T, SyncError> {
    let mut resp = resp.map_err(|e| SyncError::Network(e.to_string()))?;
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok());
    let body = resp
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_vec()
        .map_err(|e| SyncError::Network(e.to_string()))?;
    if (200..300).contains(&status) {
        return serde_json::from_slice(&body).map_err(|e| SyncError::Protocol(e.to_string()));
    }
    // Errors from the API are JSON; a proxy's are not.
    Err(match serde_json::from_slice::<ErrorBody>(&body) {
        Ok(e) => SyncError::Server {
            status,
            code: Some(e.error),
            message: e.message,
            retry_after,
        },
        Err(_) => SyncError::Server {
            status,
            code: None,
            message: format!("HTTP {status}"),
            retry_after,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use vykey_server::api::{Api, Config};
    use vykey_server::http::{Options, TestServer};
    use vykey_server::pow::PowConfig;
    use vykey_server::store::RedbStore;

    use super::*;
    use crate::Store;
    use crate::store::Vault;

    #[test]
    fn server_addresses() {
        let ok = |s: &str| normalize_server_url(s).unwrap();
        assert_eq!(ok("sync.example.com"), "https://sync.example.com");
        assert_eq!(
            ok(" https://sync.example.com/ "),
            "https://sync.example.com"
        );
        assert_eq!(ok("https://example.com/vykey"), "https://example.com/vykey");
        assert_eq!(ok("http://localhost:8470"), "http://localhost:8470");
        assert_eq!(ok("http://127.0.0.1:8470"), "http://127.0.0.1:8470");
        assert_eq!(ok("http://[::1]:8470"), "http://[::1]:8470");
        assert!(matches!(
            normalize_server_url("http://example.com"),
            Err(SyncError::Address(AddressError::Insecure))
        ));
        for bad in [
            "",
            "http://example.com",
            "http://192.168.1.2:8470",
            "ftp://x",
            "https://",
            "https:///path",
            "https://user@host",
            "two words",
        ] {
            assert!(normalize_server_url(bad).is_err(), "{bad:?}");
        }
    }

    fn server(cfg: Config) -> TestServer {
        let db = Arc::new(RedbStore::in_memory().unwrap());
        let api = Arc::new(Api::new(db, cfg));
        TestServer::start(
            api,
            Options {
                log: false,
                ..Options::default()
            },
        )
    }

    #[test]
    fn create_account_with_proof_of_work_and_sync_over_http() {
        let srv = server(Config {
            open_registration: true,
            pow: Some(PowConfig {
                base_bits: 10,
                target_per_hour: 100,
            }),
            ..Config::default()
        });
        let url = format!("http://127.0.0.1:{}", srv.addr.port());
        let token = HttpClient::new(&url).unwrap().create_account(None).unwrap();
        let client = HttpClient::new(&url).unwrap().with_token(&token);
        assert_eq!(client.account_info().unwrap().rev, 0);

        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("vykey.db")).unwrap();
        store.set_sync_account(&url, &token).unwrap();
        let v = Vault::create("Personal", "pw").unwrap();
        store.insert_vault(&v).unwrap();
        let r = super::super::sync(&store, Some(&v), &client).unwrap();
        assert_eq!(r.pushed, 1);
        assert_eq!(r.poll_after, Some(300));
        assert_eq!(client.account_info().unwrap().records, 1);
    }

    #[test]
    fn closed_registration_needs_the_invite() {
        let srv = server(Config {
            invite_key: Some("k".into()),
            ..Config::default()
        });
        let url = format!("http://127.0.0.1:{}", srv.addr.port());
        let c = HttpClient::new(&url).unwrap();
        let err = c.create_account(None).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::RegistrationClosed), "{err}");
        assert!(c.create_account(Some(" k ")).is_ok());
        let wrong = c.create_account(Some("nope")).unwrap_err();
        assert_eq!(wrong.code(), Some(ErrorCode::RegistrationClosed));
    }

    #[test]
    fn unknown_token_and_unreachable_server() {
        let srv = server(Config::default());
        let url = format!("http://127.0.0.1:{}", srv.addr.port());
        let c = HttpClient::new(&url)
            .unwrap()
            .with_token(&Token::from_bytes([9; Token::LEN]));
        assert_eq!(
            c.account_info().unwrap_err().code(),
            Some(ErrorCode::Unauthorized)
        );
        drop(srv);
        assert!(matches!(c.account_info(), Err(SyncError::Network(_))));
    }
}
