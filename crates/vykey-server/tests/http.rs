//! End to end over real sockets.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use vykey_server::api::{Api, Config};
use vykey_server::http::{Options, TestServer};
use vykey_server::store::RedbStore;

fn start(opts: Options) -> TestServer {
    let store = Arc::new(RedbStore::in_memory().unwrap());
    let cfg = Config {
        open_registration: true,
        ..Config::default()
    };
    let api = Arc::new(Api::new(store, cfg));
    TestServer::start(api, Options { log: false, ..opts })
}

fn connect(srv: &TestServer) -> TcpStream {
    let s = TcpStream::connect(srv.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}

fn read_all(s: &mut TcpStream) -> String {
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// Sends raw bytes, returns everything until the server closes.
fn raw(srv: &TestServer, bytes: &[u8]) -> String {
    let mut s = connect(srv);
    s.write_all(bytes).unwrap();
    read_all(&mut s)
}

fn statuses(raw: &str) -> Vec<u16> {
    raw.match_indices("HTTP/1.1 ")
        .map(|(i, _)| raw[i + 9..i + 12].parse().unwrap())
        .collect()
}

/// One request on a fresh connection: status, head, JSON body.
fn request(
    srv: &TestServer,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> (u16, String, Value) {
    let auth = token.map_or(String::new(), |t| format!("Authorization: Bearer {t}\r\n"));
    let out = raw(
        srv,
        format!(
            "{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n{auth}\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    let status = statuses(head)[0];
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(body).unwrap()
    };
    (status, head.to_lowercase(), body)
}

#[test]
fn two_devices_sync_through_the_server() {
    let srv = start(Options::default());

    let (status, head, v) = request(&srv, "POST", "/v1/account", None, "");
    assert_eq!(status, 201);
    assert!(head.contains("content-type: application/json"));
    assert!(head.contains("cache-control: no-store"));
    let token = v["token"].as_str().unwrap().to_owned();

    // Device A creates a vault and an entry.
    let vault = "aaaaaaaa-0000-4000-8000-000000000000";
    let entry = "bbbbbbbb-0000-4000-8000-000000000000";
    let push = json!({"records": [
        {"id": vault, "kind": "vault", "vault_id": vault, "base_rev": 0, "blob": "dmF1bHQ="},
        {"id": entry, "kind": "entry", "vault_id": vault, "base_rev": 0, "blob": "ZW50cnk="},
    ]});
    let (status, _, v) = request(&srv, "POST", "/v1/push", Some(&token), &push.to_string());
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["rev"], 2);

    // Device B pulls everything.
    let (_, _, v) = request(&srv, "GET", "/v1/changes?since=0", Some(&token), "");
    assert_eq!(v["records"].as_array().unwrap().len(), 2);
    assert_eq!(v["until"], 2);

    // B deletes the entry; A, editing from the old revision, conflicts.
    let del = json!({"records": [
        {"id": entry, "kind": "entry", "vault_id": vault, "base_rev": 2, "deleted": true},
    ]});
    let (_, _, v) = request(&srv, "POST", "/v1/push", Some(&token), &del.to_string());
    assert_eq!(v["results"][0]["rev"], 3);
    let edit = json!({"records": [
        {"id": entry, "kind": "entry", "vault_id": vault, "base_rev": 2, "blob": "ZWRpdA=="},
    ]});
    let (_, _, v) = request(&srv, "POST", "/v1/push", Some(&token), &edit.to_string());
    assert_eq!(v["results"][0]["status"], "conflict");
    assert_eq!(v["results"][0]["current"]["deleted"], true);

    // A catches up from its last revision.
    let (_, _, v) = request(&srv, "GET", "/v1/changes?since=2", Some(&token), "");
    assert_eq!(v["records"][0]["id"], entry);
    assert_eq!(v["records"][0]["deleted"], true);

    // Errors keep the JSON shape; 204 has no body.
    let (status, _, v) = request(&srv, "GET", "/v1/changes", Some("nope"), "");
    assert_eq!((status, v["error"].as_str()), (401, Some("unauthorized")));
    let (status, _, v) = request(&srv, "DELETE", "/v1/account", Some(&token), "");
    assert_eq!((status, v), (204, Value::Null));
}

#[test]
fn keep_alive_and_pipelining() {
    let srv = start(Options::default());
    let out = raw(
        &srv,
        b"GET /v1/health HTTP/1.1\r\nHost: t\r\n\r\n\
          POST /v1/account HTTP/1.1\r\nHost: t\r\nContent-Length: 0\r\n\r\n\
          GET /v1/health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n",
    );
    assert_eq!(statuses(&out), [200, 201, 200]);
}

#[test]
fn chunked_body_is_accepted() {
    let srv = start(Options::default());
    let body = r#"{"records":[]}"#;
    let out = raw(
        &srv,
        format!(
            "POST /v1/push HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\
             Transfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    // Reached the API: no token.
    assert_eq!(statuses(&out), [401], "{out}");
}

#[test]
fn expect_continue() {
    let srv = start(Options::default());
    let mut s = connect(&srv);
    s.write_all(
        b"POST /v1/account HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\n\
          Content-Length: 2\r\nConnection: close\r\n\r\n",
    )
    .unwrap();
    let mut first = [0u8; 25];
    s.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"HTTP/1.1 100 Continue\r\n\r\n");
    s.write_all(b"{}").unwrap();
    assert_eq!(statuses(&read_all(&mut s)), [201]);
}

#[test]
fn oversized_body_is_refused_without_reading_it() {
    let srv = start(Options::default());
    let started = Instant::now();
    for len in [
        (vykey_sync_proto::MAX_BODY_LEN + 1).to_string(),
        "1000000000000000".to_owned(),
    ] {
        let out = raw(
            &srv,
            format!("POST /v1/push HTTP/1.1\r\nHost: t\r\nContent-Length: {len}\r\n\r\npartial")
                .as_bytes(),
        );
        assert_eq!(statuses(&out), [413], "{out}");
        assert!(out.contains("payload_too_large"));
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn error_reply_survives_unread_client_data() {
    let srv = start(Options::default());
    let mut s = connect(&srv);
    let len = vykey_sync_proto::MAX_BODY_LEN + 1;
    s.write_all(
        format!("POST /v1/push HTTP/1.1\r\nHost: t\r\nContent-Length: {len}\r\n\r\n").as_bytes(),
    )
    .unwrap();
    // Part of the body is already on its way when the server answers.
    let _ = s.write_all(&vec![b'x'; 256 * 1024]);
    let out = read_all(&mut s);
    assert_eq!(statuses(&out), [413], "{out}");
}

#[test]
fn malformed_requests() {
    let srv = start(Options::default());
    assert_eq!(statuses(&raw(&srv, b"NONSENSE\r\n\r\n")), [400]);
    let conflicting = b"POST /v1/push HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx";
    assert_eq!(statuses(&raw(&srv, conflicting)), [400]);

    let mut huge = b"GET /v1/health HTTP/1.1\r\nX-Pad: ".to_vec();
    huge.extend(std::iter::repeat_n(b'a', 64 * 1024));
    assert_eq!(statuses(&raw(&srv, &huge)), [431]);
}

#[test]
fn slow_and_idle_clients_are_cut_off() {
    let srv = start(Options {
        header_timeout: Duration::from_millis(300),
        body_timeout: Duration::from_millis(300),
        ..Options::default()
    });

    // Sent the head, never finished the body.
    let mut s = connect(&srv);
    s.write_all(b"POST /v1/push HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc")
        .unwrap();
    assert_eq!(statuses(&read_all(&mut s)), [408]);

    // Never finished the head.
    let mut s = connect(&srv);
    s.write_all(b"GET /v1/health HTTP/1.1\r\nHo").unwrap();
    let started = Instant::now();
    read_all(&mut s);
    assert!(started.elapsed() < Duration::from_secs(5));

    // Connected, said nothing.
    let mut s = connect(&srv);
    let started = Instant::now();
    read_all(&mut s);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn connections_over_the_cap_wait_for_a_free_slot() {
    let srv = start(Options {
        max_connections: 1,
        ..Options::default()
    });
    let mut first = connect(&srv);
    first
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: t\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 12];
    first.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"HTTP/1.1 200");

    // The first connection is kept alive, so the second waits.
    let mut second = connect(&srv);
    second
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        .unwrap();
    second
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut probe = [0u8; 1];
    assert!(second.read(&mut probe).is_err(), "served too early");

    drop(first);
    second
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(statuses(&read_all(&mut second)), [200]);
}
