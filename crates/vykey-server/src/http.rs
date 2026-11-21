//! HTTP/1.1 transport on hyper: maps requests to [`crate::api`] and back.
//!
//! The API is synchronous (redb is), so each request runs on tokio's
//! blocking pool; the async side only moves bytes. Plain HTTP only: TLS and
//! HTTP/2 belong to a reverse proxy in front.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use vykey_sync_proto::{ErrorCode, INVITE_HEADER, MAX_BODY_LEN};

use crate::api::{Api, Request, Response};

/// Read buffer per connection, which bounds the request head (431 above).
const MAX_HEAD_LEN: usize = 16 * 1024;
/// How long a shutdown waits for requests in progress.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Options {
    /// Take the client address from the last `X-Forwarded-For` entry (the
    /// one the proxy appended). Only behind a proxy that sets it.
    pub trust_proxy: bool,
    /// One stderr line per request.
    pub log: bool,
    /// Open connections at most; further ones wait in the listen backlog.
    pub max_connections: usize,
    /// Time to receive a request head, counted from when the connection
    /// starts waiting for it, so it also closes idle keep-alive connections.
    pub header_timeout: Duration,
    /// Time to receive a request body.
    pub body_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            trust_proxy: false,
            log: true,
            max_connections: 512,
            header_timeout: Duration::from_secs(20),
            body_timeout: Duration::from_secs(30),
        }
    }
}

/// The runtime the server runs on.
pub fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("vykey-http")
        // Requests block on redb, which has one writer anyway.
        .max_blocking_threads(64)
        .build()
}

/// Serves until `shutdown` completes, then waits up to 10 s for requests in
/// progress.
pub async fn serve(
    listener: TcpListener,
    api: Arc<Api>,
    opts: Options,
    shutdown: impl Future<Output = ()>,
) {
    let opts = Arc::new(opts);
    let slots = Arc::new(Semaphore::new(opts.max_connections.max(1)));
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            p = slots.clone().acquire_owned() => p.expect("the semaphore is never closed"),
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    // Typically out of file descriptors: back off.
                    eprintln!("vykey-server: accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);

        let service = {
            let (api, opts) = (api.clone(), opts.clone());
            service_fn(move |req| {
                let (api, opts) = (api.clone(), opts.clone());
                async move { Ok::<_, Infallible>(handle(api, &opts, peer, req).await) }
            })
        };
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(opts.header_timeout)
            .max_buf_size(MAX_HEAD_LEN)
            .serve_connection(TokioIo::new(stream), service);
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            // Errors here are clients that hung up or sent garbage.
            let _ = conn.await;
            drop(permit);
        });
    }

    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(SHUTDOWN_GRACE) => {
            eprintln!("vykey-server: requests still running at shutdown");
        }
    }
}

/// Completes on Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    eprintln!("vykey-server: shutting down");
}

async fn handle(
    api: Arc<Api>,
    opts: &Options,
    peer: SocketAddr,
    req: hyper::Request<Incoming>,
) -> hyper::Response<Full<Bytes>> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_owned();
    let path = parts.uri.path().to_owned();

    let response = match read_body(&parts.headers, body, opts.body_timeout).await {
        Err(r) => r,
        Ok(body) => {
            let header = |name: &str| header(&parts.headers, name);
            let ip = client_ip(peer, header("X-Forwarded-For"), opts.trust_proxy);
            let authorization = header("Authorization").map(str::to_owned);
            let invite = header(INVITE_HEADER).map(str::to_owned);
            let query = parts.uri.query().unwrap_or("").to_owned();
            let (method, path) = (method.clone(), path.clone());
            tokio::task::spawn_blocking(move || {
                api.handle(&Request {
                    method: &method,
                    path: &path,
                    query: &query,
                    authorization: authorization.as_deref(),
                    invite: invite.as_deref(),
                    body: &body,
                    ip,
                })
            })
            .await
            .unwrap_or_else(|_| {
                // The task panicked.
                Response::error(ErrorCode::Internal, "internal error")
            })
        }
    };

    if opts.log {
        // No query string: nothing secret is in it today, but keep it so.
        eprintln!(
            "{method} {path} {} {}ms",
            response.status,
            started.elapsed().as_millis()
        );
    }
    to_hyper(response)
}

/// The whole body, at most [`MAX_BODY_LEN`] bytes within `timeout`.
async fn read_body(
    headers: &HeaderMap,
    body: Incoming,
    timeout: Duration,
) -> Result<Bytes, Response> {
    let too_large = || Response::error(ErrorCode::PayloadTooLarge, "body too large");
    let declared = header(headers, CONTENT_LENGTH.as_str()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > MAX_BODY_LEN as u64) {
        // Refused without reading; hyper closes the connection after the
        // response.
        return Err(too_large());
    }
    match tokio::time::timeout(timeout, Limited::new(body, MAX_BODY_LEN).collect()).await {
        Ok(Ok(collected)) => Ok(collected.to_bytes()),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => Err(too_large()),
        Ok(Err(_)) => Err(Response::error(ErrorCode::BadRequest, "unreadable body")),
        Err(_) => {
            let mut r = Response::error(ErrorCode::BadRequest, "request timeout");
            r.status = 408;
            Err(r)
        }
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn to_hyper(r: Response) -> hyper::Response<Full<Bytes>> {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut out = hyper::Response::new(Full::new(Bytes::from(r.body)));
    *out.status_mut() = status;
    let h = out.headers_mut();
    if status != StatusCode::NO_CONTENT {
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(secs) = r.retry_after {
        h.insert(RETRY_AFTER, HeaderValue::from(secs));
    }
    out
}

fn client_ip(peer: SocketAddr, forwarded: Option<&str>, trust_proxy: bool) -> IpAddr {
    let direct = peer.ip();
    if !trust_proxy {
        return direct;
    }
    forwarded
        .and_then(|f| f.rsplit(',').next())
        .and_then(|last| last.trim().parse().ok())
        .unwrap_or(direct)
}

/// A server on a random local port, for tests; stopped when dropped.
pub struct TestServer {
    pub addr: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestServer {
    pub fn start(api: Arc<Api>, opts: Options) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local address");
        listener.set_nonblocking(true).expect("non-blocking");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let rt = runtime().expect("runtime");
        let thread = std::thread::spawn(move || {
            rt.block_on(async {
                let listener = TcpListener::from_std(listener).expect("tokio listener");
                serve(listener, api, opts, async {
                    let _ = stopped.await;
                })
                .await;
            });
        });
        TestServer {
            addr,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_from_proxy_header() {
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let xff = Some("203.0.113.9, 198.51.100.2");
        assert_eq!(client_ip(peer, xff, false), peer.ip());
        assert_eq!(
            client_ip(peer, xff, true),
            "198.51.100.2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(client_ip(peer, Some("junk"), true), peer.ip());
        assert_eq!(client_ip(peer, None, true), peer.ip());
    }
}
