//! Every machine runs the same proxy, so DNS can point at any (or all) of them:
//!
//! * `:80` / `:443` — HTTP(S) ingress, routed by Host header, TLS by SNI
//!   with certificates from the replicated state (Let's Encrypt).
//! * `<app VIP>:<port>` — internal TCP load balancing (`<app>.internal`).
//! * `0.0.0.0:<public port>` — public TCP ports declared with `public = true`.
//!
//! Backends are picked with "power of two choices" (two random instances,
//! the less busy one wins); connection failures fail over to the next
//! backend before any bytes of the request are sent.

use super::Agent;
use crate::state::{AppRoute, Backend, Routes};
use crate::util::DEV_HTTP_PORT;
use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::{Body as HttpBody, Frame, Incoming};
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rand::seq::SliceRandom;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

type PBody = BoxBody<Bytes, hyper::Error>;

pub struct Proxy {
    agent: Arc<Agent>,
    inflight: Mutex<HashMap<String, Arc<AtomicUsize>>>,
    /// Passive health: instances that recently refused/timed out a connection.
    failed: Mutex<HashMap<String, std::time::Instant>>,
    certs: Arc<CertStore>,
    listeners: Mutex<HashMap<String, JoinHandle<()>>>,
}

#[derive(Default)]
pub struct CertStore {
    map: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    loaded: Mutex<HashMap<String, u64>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertStore")
    }
}

impl CertStore {
    fn has(&self, host: &str) -> bool {
        let name = host.trim_end_matches('.').to_ascii_lowercase();
        let map = self.map.read().unwrap();
        if map.contains_key(&name) {
            return true;
        }
        if let Some((_, parent)) = name.split_once('.') {
            if map.contains_key(&format!("*.{parent}")) {
                return true;
            }
        }
        false
    }
    fn refresh(&self, certs: &std::collections::BTreeMap<String, crate::state::Cert>) {
        let mut loaded = self.loaded.lock().unwrap();
        let changed = loaded.len() != certs.len()
            || certs
                .iter()
                .any(|(d, c)| loaded.get(&d.to_ascii_lowercase()) != Some(&c.issued_at));
        if !changed {
            return;
        }
        let mut map = HashMap::new();
        loaded.clear();
        for (d, c) in certs {
            let key = d.trim_end_matches('.').to_ascii_lowercase();
            // Always record issued_at so a single broken cert doesn't trigger
            // re-parsing every cert every 2 seconds until a new issuance arrives.
            loaded.insert(key.clone(), c.issued_at);
            match load_cert(&c.cert_pem, &c.key_pem) {
                Ok(ck) => {
                    map.insert(key, Arc::new(ck));
                }
                Err(e) => warn!("bad certificate for {d}: {e}"),
            }
        }
        *self.map.write().unwrap() = map;
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.trim_end_matches('.').to_ascii_lowercase();
        let map = self.map.read().unwrap();
        if let Some(c) = map.get(&name) {
            return Some(c.clone());
        }
        let (_, parent) = name.split_once('.')?;
        map.get(&format!("*.{parent}")).cloned()
    }
}

pub fn load_cert(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificate chain found in PEM");
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow!("no private key"))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)?;
    let ck = CertifiedKey::new(certs, signing);
    ck.keys_match()
        .map_err(|e| anyhow!("certificate and private key do not match: {e}"))?;
    Ok(ck)
}

pub async fn run(agent: Arc<Agent>) {
    let px = Arc::new(Proxy {
        agent: agent.clone(),
        inflight: Mutex::new(HashMap::new()),
        failed: Mutex::new(HashMap::new()),
        certs: Arc::new(CertStore::default()),
        listeners: Mutex::new(HashMap::new()),
    });
    if agent.dev {
        tokio::spawn(serve(px.clone(), format!("127.0.0.1:{DEV_HTTP_PORT}"), false));
    } else {
        tokio::spawn(serve(px.clone(), "0.0.0.0:80".into(), false));
        tokio::spawn(serve(px.clone(), "0.0.0.0:443".into(), true));
    }
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        px.certs.refresh(&agent.snapshot().certs);
        px.sync_listeners();
    }
}

async fn serve(px: Arc<Proxy>, addr: String, tls: bool) {
    let acceptor = if tls {
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(px.certs.clone());
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
    } else {
        None
    };
    let listener = loop {
        match TcpListener::bind(&addr).await {
            Ok(l) => break l,
            Err(e) => {
                warn!("proxy cannot bind {addr}: {e} (retrying)");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    info!("proxy listening on {addr}{}", if tls { " (tls)" } else { "" });
    let conn_limit = Arc::new(Semaphore::new(2048));
    loop {
        let (stream, remote) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                debug!("proxy accept error on {addr}: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(permit) = conn_limit.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        let px = px.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let svc = {
                let px = px.clone();
                service_fn(move |req| {
                    let px = px.clone();
                    async move { Ok::<_, Infallible>(px.handle(req, remote, tls).await) }
                })
            };
            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder.http1().header_read_timeout(Duration::from_secs(15));
            match acceptor {
                Some(acc) => {
                    let Ok(Ok(tls_stream)) = tokio::time::timeout(Duration::from_secs(10), acc.accept(stream)).await else {
                        return;
                    };
                    let _ = builder.serve_connection_with_upgrades(TokioIo::new(tls_stream), svc).await;
                }
                None => {
                    let _ = builder.serve_connection_with_upgrades(TokioIo::new(stream), svc).await;
                }
            }
        });
    }
}

fn text(status: StatusCode, body: impl Into<String>) -> Response<PBody> {
    let mut r = Response::new(Full::new(Bytes::from(body.into())).map_err(|e| match e {}).boxed());
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    r
}

fn html_page(status: StatusCode, title: &str, msg: &str) -> Response<PBody> {
    let body = format!(
        "<!doctype html><html><head><meta charset=utf-8><title>{title}</title>\
         <style>body{{font-family:system-ui,sans-serif;background:#0f1115;color:#e6e6e6;display:grid;place-items:center;height:100vh;margin:0}}\
         div{{max-width:32rem;padding:2rem}}h1{{font-size:1.3rem}}p{{color:#9aa0a6}}</style></head>\
         <body><div><h1>{title}</h1><p>{msg}</p><p><small>served by latrix</small></p></div></body></html>"
    );
    let mut r = Response::new(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed());
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    r
}

fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || ((v6.segments()[0] & 0xfe00) == 0xfc00),
    }
}

/// Extract an IPv4 embedded in `<app>.<ip>.sslip.io` / `<app>.<ip>.nip.io` (dashed or dotted).
fn generic_ip_matches_cluster(host: &str, suffix: &str, cluster_ips: &HashSet<String>) -> bool {
    let Some(prefix) = host.strip_suffix(suffix) else {
        return false;
    };
    let Some((_, ip_part)) = prefix.split_once('.') else {
        return false;
    };
    if ip_part.is_empty() {
        return false;
    }
    let dotted = ip_part.replace('-', ".");
    cluster_ips.contains(&dotted) || cluster_ips.contains(ip_part)
}

/// Map a Host header to an app.
pub fn resolve<'a>(routes: &'a Routes, host: &str) -> Option<&'a AppRoute> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(r) = routes
        .apps
        .values()
        .find(|r| r.hosts.iter().any(|h| h.trim_end_matches('.').eq_ignore_ascii_case(&host)))
    {
        return Some(r);
    }
    // Check explicit internal DNS map first so `<service>.<group>.internal`
    // takes precedence over a generic `<app>` with the same first label.
    if host.ends_with(".internal") {
        if let Some(vip) = routes.dns.get(&host) {
            return routes.apps.values().find(|r| &r.vip == vip);
        }
    }
    // Zero-config names: <app>.localhost, <app>.<ip>.sslip.io, <app>.<ip>.nip.io, <app>.internal
    let first = host.split('.').next()?;
    let generic = host.ends_with(".localhost")
        || host.ends_with(".sslip.io")
        || host.ends_with(".nip.io")
        || host.ends_with(".internal");
    if generic {
        if let Some(r) = routes.apps.get(first) {
            return Some(r);
        }
    }
    None
}

/// Strip `:port` from a Host header (handling bracketed IPv6 literals) and normalize.
fn normalize_host_header(raw: &str) -> String {
    let raw = raw.trim();
    let without_port = if let Some(rest) = raw.strip_prefix('[') {
        if let Some((v6, _)) = rest.split_once(']') {
            v6
        } else {
            raw
        }
    } else if let Some((h, p)) = raw.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            raw
        }
    } else {
        raw
    };
    without_port.trim_end_matches('.').to_ascii_lowercase()
}

/// Remove RFC 9110 hop-by-hop headers (and any headers nominated in Connection)
/// before proxying, preserving Upgrade/Connection: upgrade only when upgrading.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap, keep_upgrade: bool) {
    let mut nominated: Vec<HeaderName> = vec![];
    for val in headers.get_all(header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for tok in s.split(',') {
                let t = tok.trim();
                if t.is_empty() {
                    continue;
                }
                if keep_upgrade && t.eq_ignore_ascii_case("upgrade") {
                    continue;
                }
                if let Ok(name) = HeaderName::from_bytes(t.as_bytes()) {
                    nominated.push(name);
                }
            }
        }
    }
    for name in nominated {
        headers.remove(&name);
    }
    const HOP_BY_HOP: &[&str] = &[
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
    ];
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
    if keep_upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
}

struct GuardedBody {
    inner: Incoming,
    _guard: Decrement,
}

impl HttpBody for GuardedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Proxy {
    fn counter(&self, instance: &str) -> Arc<AtomicUsize> {
        self.inflight
            .lock()
            .unwrap()
            .entry(instance.to_string())
            .or_default()
            .clone()
    }

    /// Ordered list of (address, instance) to try.
    fn candidates(&self, backends: &[Backend], port: u16) -> Vec<(String, String)> {
        let mut list: Vec<(&Backend, u16)> = backends
            .iter()
            .filter_map(|b| b.ports.get(&port).map(|hp| (b, *hp)))
            .collect();
        // Power of two choices: pick two random backends and use the less
        // busy one. The rest follow by load, as fallbacks if connecting fails.
        list.shuffle(&mut rand::thread_rng());
        // Skip instances that failed recently, unless nothing else is left.
        let ok_len = {
            let mut failed = self.failed.lock().unwrap();
            failed.retain(|_, t| t.elapsed() < Duration::from_secs(15));
            let ok: Vec<(&Backend, u16)> =
                list.iter().copied().filter(|(b, _)| !failed.contains_key(&b.instance)).collect();
            let n = ok.len();
            if !ok.is_empty() {
                let bad: Vec<(&Backend, u16)> =
                    list.iter().copied().filter(|(b, _)| failed.contains_key(&b.instance)).collect();
                list = ok;
                list.extend(bad);
            }
            n
        };
        let load = |b: &Backend| self.counter(&b.instance).load(Ordering::Relaxed);
        // Only compare the first two elements when both belong to the healthy pool
        // (or when all backends are in the failed pool) so a dead backend with 0
        // inflight never displaces a healthy busy backend.
        if (ok_len >= 2 || (ok_len == 0 && list.len() >= 2))
            && load(list[1].0) < load(list[0].0)
        {
            list.swap(0, 1);
        }
        if list.len() >= 2 {
            let failed = self.failed.lock().unwrap();
            let rest = &mut list[1..];
            rest.sort_by_key(|(b, _)| (failed.contains_key(&b.instance), load(b)));
        }
        let me = self.agent.me.machine_id;
        let mut out = vec![];
        for (b, hp) in list {
            if self.agent.dev {
                out.push((format!("127.0.0.1:{hp}"), b.instance.clone()));
            } else if b.machine == me {
                // Our own instances are always published on 127.0.0.1 (the
                // mesh IP is for other machines); older containers may only
                // have the mesh IP.
                out.push((format!("127.0.0.1:{hp}"), b.instance.clone()));
                out.push((format!("{}:{hp}", b.ip), b.instance.clone()));
            } else {
                out.push((format!("{}:{hp}", b.ip), b.instance.clone()));
            }
        }
        out
    }

    async fn connect(&self, backends: &[Backend], port: u16) -> Option<(TcpStream, String)> {
        let mut tried_instances = HashSet::new();
        for (addr, inst) in self.candidates(backends, port) {
            if !tried_instances.contains(&inst) && tried_instances.len() >= 4 {
                break;
            }
            tried_instances.insert(inst.clone());
            // The mesh is low-latency: give up quickly and try the next one.
            match tokio::time::timeout(Duration::from_millis(1000), TcpStream::connect(&addr)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    self.failed.lock().unwrap().remove(&inst);
                    return Some((s, inst));
                }
                _ => {
                    debug!("backend {addr} unreachable, trying next");
                    self.failed.lock().unwrap().insert(inst, std::time::Instant::now());
                }
            }
        }
        None
    }

    async fn handle(self: &Arc<Self>, mut req: Request<Incoming>, remote: SocketAddr, tls: bool) -> Response<PBody> {
        if req.method() == Method::CONNECT {
            return text(StatusCode::METHOD_NOT_ALLOWED, "CONNECT not supported");
        }
        let path = req.uri().path().to_string();
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            return match self.agent.snapshot().acme_challenges.get(token) {
                Some(v) => text(StatusCode::OK, v.clone()),
                None => text(StatusCode::NOT_FOUND, "unknown challenge"),
            };
        }
        let raw_host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.to_string())
            .or_else(|| req.uri().authority().map(|a| a.to_string()))
            .unwrap_or_default();
        let host = normalize_host_header(&raw_host);
        let routes = self.agent.routes.read().unwrap().clone();
        let snap = self.agent.snapshot();

        // Guard generic zero-config hostnames against Host header injection & internal exposure.
        let explicit_match = routes
            .apps
            .values()
            .any(|r| r.hosts.iter().any(|h| h.trim_end_matches('.').eq_ignore_ascii_case(&host)));
        if !explicit_match {
            if host.ends_with(".localhost") && !self.agent.dev {
                return html_page(
                    StatusCode::NOT_FOUND,
                    "No app here (yet)",
                    &format!("latrix has no app configured for <b>{}</b>.", html_escape(&host)),
                );
            }
            if host.ends_with(".internal") && !is_internal_ip(remote.ip()) {
                return html_page(
                    StatusCode::NOT_FOUND,
                    "No app here (yet)",
                    &format!("latrix has no app configured for <b>{}</b>.", html_escape(&host)),
                );
            }
            if host.ends_with(".sslip.io") || host.ends_with(".nip.io") {
                let cluster_ips: HashSet<String> = snap
                    .machines
                    .values()
                    .map(|m| m.public_ip.clone())
                    .collect();
                let suffix = if host.ends_with(".sslip.io") {
                    ".sslip.io"
                } else {
                    ".nip.io"
                };
                if !generic_ip_matches_cluster(&host, suffix, &cluster_ips) {
                    return html_page(
                        StatusCode::NOT_FOUND,
                        "No app here (yet)",
                        &format!("latrix has no app configured for <b>{}</b>.", html_escape(&host)),
                    );
                }
            }
        }

        let Some(route) = resolve(&routes, &host) else {
            return html_page(
                StatusCode::NOT_FOUND,
                "No app here (yet)",
                &format!("latrix has no app configured for <b>{}</b>. Add it to <code>[http] domains</code> in latrix.toml and deploy.", html_escape(&host)),
            );
        };
        if !tls && route.force_https && self.certs.has(&host) {
            let pq = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let mut r = text(StatusCode::PERMANENT_REDIRECT, "");
            if let Ok(v) = HeaderValue::from_str(&format!("https://{host}{pq}")) {
                r.headers_mut().insert(header::LOCATION, v);
            }
            return r;
        }
        let Some(port) = route.http_port else {
            return html_page(StatusCode::NOT_FOUND, "No HTTP service", "This app does not define an [http] section.");
        };
        if route.backends.is_empty() {
            return html_page(
                StatusCode::SERVICE_UNAVAILABLE,
                "Starting up",
                &format!("<b>{}</b> has no healthy instances right now. If you just deployed, it will be up in a moment.", html_escape(&route.app)),
            );
        }
        let Some((stream, inst)) = self.connect(&route.backends, port).await else {
            return html_page(StatusCode::BAD_GATEWAY, "Bad gateway", "Could not reach any instance of this app.");
        };
        let counter = self.counter(&inst);
        counter.fetch_add(1, Ordering::Relaxed);
        let guard = Decrement(counter);

        let upgrade = req
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|s| s.split(','))
            .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
            && req.headers().contains_key(header::UPGRADE);
        let client_upgrade = if upgrade { Some(hyper::upgrade::on(&mut req)) } else { None };

        let (mut parts, body) = req.into_parts();
        let pq = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        parts.uri = pq.parse().unwrap_or_default();
        parts.version = hyper::Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers, upgrade);
        if !parts.headers.contains_key(header::HOST) {
            if let Ok(v) = HeaderValue::from_str(&host) {
                parts.headers.insert(header::HOST, v);
            }
        }
        let trust_xff = is_internal_ip(remote.ip()) || snap.cloudflare_token.is_some();
        let xff = if trust_xff {
            match parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                Some(prev) if !prev.trim().is_empty() => format!("{prev}, {}", remote.ip()),
                _ => remote.ip().to_string(),
            }
        } else {
            remote.ip().to_string()
        };
        if let Ok(v) = HeaderValue::from_str(&xff) {
            parts.headers.insert("x-forwarded-for", v);
        }
        if let Ok(v) = HeaderValue::from_str(&remote.ip().to_string()) {
            parts.headers.insert("x-real-ip", v);
        }
        parts.headers.insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if tls { "https" } else { "http" }),
        );
        if let Ok(v) = HeaderValue::from_str(&host) {
            parts.headers.insert("x-forwarded-host", v);
        }

        let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
            Ok(x) => x,
            Err(e) => return text(StatusCode::BAD_GATEWAY, format!("backend handshake failed: {e}")),
        };
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        let mut resp = match tokio::time::timeout(
            Duration::from_secs(300),
            sender.send_request(Request::from_parts(parts, body)),
        )
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return text(StatusCode::BAD_GATEWAY, format!("backend error: {e}")),
            Err(_) => return text(StatusCode::GATEWAY_TIMEOUT, "backend timed out"),
        };
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            if let Some(cu) = client_upgrade {
                let bu = hyper::upgrade::on(&mut resp);
                let ws_guard = guard;
                tokio::spawn(async move {
                    let _ws_guard = ws_guard;
                    if let Ok((c, b)) = tokio::try_join!(cu, bu) {
                        let mut c = TokioIo::new(c);
                        let mut b = TokioIo::new(b);
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut b).await;
                    }
                });
                return resp.map(|b| b.boxed());
            }
        }
        resp.map(|b| GuardedBody { inner: b, _guard: guard }.boxed())
    }

    /// Start/stop TCP listeners for internal (VIP) and public ports.
    fn sync_listeners(self: &Arc<Self>) {
        let routes = self.agent.routes.read().unwrap().clone();
        // Prune stale inflight counters for instances no longer in routes.
        {
            let active: HashSet<&str> = routes
                .apps
                .values()
                .flat_map(|r| r.backends.iter().map(|b| b.instance.as_str()))
                .collect();
            self.inflight
                .lock()
                .unwrap()
                .retain(|id, c| active.contains(id.as_str()) || c.load(Ordering::Relaxed) > 0);
        }
        let mut desired: HashMap<String, (String, String, u16)> = HashMap::new();
        for r in routes.apps.values() {
            if !self.agent.dev {
                for p in &r.ports {
                    let addr = format!("{}:{p}", r.vip);
                    desired.insert(format!("{addr}|{}|{p}", r.app), (addr, r.app.clone(), *p));
                }
            }
            for (public, cp) in &r.public_ports {
                let ip = if self.agent.dev { "127.0.0.1" } else { "0.0.0.0" };
                let addr = format!("{ip}:{public}");
                desired.insert(format!("{addr}|{}|{cp}", r.app), (addr, r.app.clone(), *cp));
            }
        }
        let mut cur = self.listeners.lock().unwrap();
        cur.retain(|k, h| {
            let keep = desired.contains_key(k) && !h.is_finished();
            if !keep {
                h.abort();
            }
            keep
        });
        for (k, (addr, app, port)) in desired {
            if cur.contains_key(&k) {
                continue;
            }
            let px = self.clone();
            cur.insert(k, tokio::spawn(async move { px.tcp_listener(addr, app, port).await }));
        }
    }

    async fn tcp_listener(self: Arc<Self>, addr: String, app: String, port: u16) {
        let listener = loop {
            match TcpListener::bind(&addr).await {
                Ok(l) => break l,
                Err(e) => {
                    debug!("cannot bind {addr} for {app}: {e} (retrying)");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        };
        debug!("tcp {addr} -> {app}:{port}");
        loop {
            let (mut client, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    debug!("tcp accept error on {addr}: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let _ = client.set_nodelay(true);
            let px = self.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let backends = px
                    .agent
                    .routes
                    .read()
                    .unwrap()
                    .apps
                    .get(&app)
                    .map(|r| r.backends.clone())
                    .unwrap_or_default();
                if let Some((mut upstream, inst)) = px.connect(&backends, port).await {
                    let counter = px.counter(&inst);
                    counter.fetch_add(1, Ordering::Relaxed);
                    let _g = Decrement(counter);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    }
}

struct Decrement(Arc<AtomicUsize>);
impl Drop for Decrement {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_resolution() {
        let mut routes = Routes::default();
        routes.apps.insert(
            "web".into(),
            AppRoute {
                app: "web".into(),
                vip: "10.78.0.2".into(),
                hosts: vec!["example.com".into()],
                ..Default::default()
            },
        );
        routes.dns.insert("frontend.shop.internal".into(), "10.78.0.2".into());
        assert_eq!(resolve(&routes, "example.com").unwrap().app, "web");
        assert_eq!(resolve(&routes, "EXAMPLE.com.").unwrap().app, "web");
        assert_eq!(resolve(&routes, "web.localhost").unwrap().app, "web");
        assert_eq!(resolve(&routes, "web.1-2-3-4.sslip.io").unwrap().app, "web");
        assert_eq!(resolve(&routes, "frontend.shop.internal").unwrap().app, "web");
        assert!(resolve(&routes, "other.com").is_none());
    }
}
