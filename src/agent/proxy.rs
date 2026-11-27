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
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rand::seq::SliceRandom;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
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
        self.map.read().unwrap().contains_key(host)
    }
    fn refresh(&self, certs: &std::collections::BTreeMap<String, crate::state::Cert>) {
        let mut loaded = self.loaded.lock().unwrap();
        let changed = loaded.len() != certs.len()
            || certs.iter().any(|(d, c)| loaded.get(d) != Some(&c.issued_at));
        if !changed {
            return;
        }
        let mut map = HashMap::new();
        loaded.clear();
        for (d, c) in certs {
            match load_cert(&c.cert_pem, &c.key_pem) {
                Ok(ck) => {
                    map.insert(d.clone(), Arc::new(ck));
                    loaded.insert(d.clone(), c.issued_at);
                }
                Err(e) => warn!("bad certificate for {d}: {e}"),
            }
        }
        *self.map.write().unwrap() = map;
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?.to_ascii_lowercase();
        let map = self.map.read().unwrap();
        if let Some(c) = map.get(&name) {
            return Some(c.clone());
        }
        let (_, parent) = name.split_once('.')?;
        map.get(&format!("*.{parent}")).cloned()
    }
}

fn load_cert(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow!("no private key"))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(CertifiedKey::new(certs, signing))
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
    loop {
        let Ok((stream, remote)) = listener.accept().await else { continue };
        let _ = stream.set_nodelay(true);
        let px = px.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let svc = {
                let px = px.clone();
                service_fn(move |req| {
                    let px = px.clone();
                    async move { Ok::<_, Infallible>(px.handle(req, remote, tls).await) }
                })
            };
            let builder = auto::Builder::new(TokioExecutor::new());
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

/// Map a Host header to an app.
pub fn resolve<'a>(routes: &'a Routes, host: &str) -> Option<&'a AppRoute> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(r) = routes.apps.values().find(|r| r.hosts.contains(&host)) {
        return Some(r);
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
        // <service>.<group>.internal
        if let Some(vip) = routes.dns.get(&host) {
            return routes.apps.values().find(|r| &r.vip == vip);
        }
    }
    None
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
        {
            let mut failed = self.failed.lock().unwrap();
            failed.retain(|_, t| t.elapsed() < Duration::from_secs(15));
            let ok: Vec<(&Backend, u16)> =
                list.iter().copied().filter(|(b, _)| !failed.contains_key(&b.instance)).collect();
            if !ok.is_empty() {
                let bad: Vec<(&Backend, u16)> =
                    list.iter().copied().filter(|(b, _)| failed.contains_key(&b.instance)).collect();
                list = ok;
                list.extend(bad);
            }
        }
        let load = |b: &Backend| self.counter(&b.instance).load(Ordering::Relaxed);
        if list.len() >= 2 {
            if load(list[1].0) < load(list[0].0) {
                list.swap(0, 1);
            }
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
        for (addr, inst) in self.candidates(backends, port).into_iter().take(4) {
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
        let path = req.uri().path().to_string();
        if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
            return match self.agent.snapshot().acme_challenges.get(token) {
                Some(v) => text(StatusCode::OK, v.clone()),
                None => text(StatusCode::NOT_FOUND, "unknown challenge"),
            };
        }
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.to_string())
            .or_else(|| req.uri().authority().map(|a| a.to_string()))
            .unwrap_or_default();
        let host = host.rsplit_once(':').map(|(h, p)| if p.chars().all(|c| c.is_ascii_digit()) { h.to_string() } else { host.clone() }).unwrap_or(host.clone());
        let routes = self.agent.routes.read().unwrap().clone();
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
                &format!("<b>{}</b> has no healthy instances right now. If you just deployed, it will be up in a moment.", route.app),
            );
        }
        let Some((stream, inst)) = self.connect(&route.backends, port).await else {
            return html_page(StatusCode::BAD_GATEWAY, "Bad gateway", "Could not reach any instance of this app.");
        };
        let counter = self.counter(&inst);
        counter.fetch_add(1, Ordering::Relaxed);
        let _guard = Decrement(counter);

        let upgrade = req
            .headers()
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false);
        let client_upgrade = if upgrade { Some(hyper::upgrade::on(&mut req)) } else { None };

        let (mut parts, body) = req.into_parts();
        let pq = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
        parts.uri = pq.parse().unwrap_or_default();
        parts.version = hyper::Version::HTTP_11;
        if !parts.headers.contains_key(header::HOST) {
            if let Ok(v) = HeaderValue::from_str(&host) {
                parts.headers.insert(header::HOST, v);
            }
        }
        let xff = match parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(prev) => format!("{prev}, {}", remote.ip()),
            None => remote.ip().to_string(),
        };
        if let Ok(v) = HeaderValue::from_str(&xff) {
            parts.headers.insert("x-forwarded-for", v);
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
        let mut resp = match sender.send_request(Request::from_parts(parts, body)).await {
            Ok(r) => r,
            Err(e) => return text(StatusCode::BAD_GATEWAY, format!("backend error: {e}")),
        };
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            if let Some(cu) = client_upgrade {
                let bu = hyper::upgrade::on(&mut resp);
                tokio::spawn(async move {
                    if let (Ok(c), Ok(b)) = (cu.await, bu.await) {
                        let mut c = TokioIo::new(c);
                        let mut b = TokioIo::new(b);
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut b).await;
                    }
                });
            }
        }
        resp.map(|b| b.boxed())
    }

    /// Start/stop TCP listeners for internal (VIP) and public ports.
    fn sync_listeners(self: &Arc<Self>) {
        let routes = self.agent.routes.read().unwrap().clone();
        let mut desired: HashMap<String, (String, String, u16)> = HashMap::new();
        for r in routes.apps.values() {
            if !self.agent.dev {
                for p in &r.ports {
                    let addr = format!("{}:{p}", r.vip);
                    desired.insert(format!("{addr}|{}", r.app), (addr, r.app.clone(), *p));
                }
            }
            for (public, cp) in &r.public_ports {
                let ip = if self.agent.dev { "127.0.0.1" } else { "0.0.0.0" };
                let addr = format!("{ip}:{public}");
                desired.insert(format!("{addr}|{}", r.app), (addr, r.app.clone(), *cp));
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
            let Ok((mut client, _)) = listener.accept().await else { continue };
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
