//! Local container runtime: makes the containers on this machine match the
//! instances the scheduler assigned to it, health-checks them, and keeps the
//! image / build caches tidy.

use super::{cmd, cmd_redacted, cmd_timeout, Agent};
use crate::config::AppConfig;
use crate::state::*;
use crate::util::{self, REGISTRY_PORT};
use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};

pub struct Runtime {
    reports: Mutex<HashMap<String, InstanceReport>>,
    /// instance -> phase ("pulling", "starting", "stopping")
    busy: Mutex<HashMap<String, String>>,
    health: Mutex<HashMap<String, Health>>,
    /// instance -> (last failed attempt, error, consecutive failures)
    failures: Mutex<HashMap<String, (Instant, String, u32)>>,
    /// container name -> (cpu %, mem MB)
    stats: Mutex<HashMap<String, (f64, f64)>>,
    build_cache_gb: Mutex<f64>,
    pub builds_running: std::sync::atomic::AtomicUsize,
    /// Shared RW lock coordinating pushes/builds (read) against registry GC (write).
    pub registry_gc_lock: tokio::sync::RwLock<()>,
    /// Dedicated HTTP client for container health checks (no redirect following).
    health_http: reqwest::Client,
    /// When a container was last moved to a new address (rebinds are spaced
    /// out so routing tables everywhere catch up in between).
    last_rebind: Mutex<Option<Instant>>,
    /// Consecutive failed reconcile passes (Docker not answering).
    pub docker_failures: std::sync::atomic::AtomicU32,
    /// app -> name of its active (running/stopping) container on this machine (for volume sync)
    pub running_apps: Mutex<HashMap<String, String>>,
    /// Recently allocated host ports (avoids TOCTOU collisions across concurrent starts).
    recent_ports: Mutex<HashMap<u16, Instant>>,
}

impl Default for Runtime {
    fn default() -> Self {
        let health_http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .no_proxy()
            .build()
            .expect("health http client");
        Self {
            reports: Default::default(),
            busy: Default::default(),
            health: Default::default(),
            failures: Default::default(),
            stats: Default::default(),
            build_cache_gb: Default::default(),
            builds_running: Default::default(),
            registry_gc_lock: tokio::sync::RwLock::new(()),
            health_http,
            last_rebind: Default::default(),
            docker_failures: Default::default(),
            running_apps: Default::default(),
            recent_ports: Default::default(),
        }
    }
}

#[derive(Default, Clone)]
struct Health {
    healthy: bool,
    fails: u32,
    healthy_since: u64,
    unhealthy_since: u64,
    unhealthy_at: Option<Instant>,
}

impl Runtime {
    pub fn reports(&self) -> Vec<InstanceReport> {
        self.reports.lock().unwrap().values().cloned().collect()
    }
    pub fn docker_ok(&self) -> bool {
        self.docker_failures.load(std::sync::atomic::Ordering::SeqCst) < 3
    }
    pub fn build_cache_gb(&self) -> f64 {
        *self.build_cache_gb.lock().unwrap()
    }
    /// Active container name for an app on this machine, if any.
    pub fn running_container(&self, app: &str) -> Option<String> {
        self.running_apps.lock().unwrap().get(app).cloned()
    }
    /// True if any instance of `app` is currently starting/stopping or has a container on this machine.
    pub fn app_has_active_work(&self, app: &str, s: &ClusterState, me: u32) -> bool {
        if self.running_apps.lock().unwrap().contains_key(app) {
            return true;
        }
        let busy = self.busy.lock().unwrap();
        s.instances_of(app)
            .any(|i| i.machine == me && busy.contains_key(&i.id))
    }
    fn set_busy(&self, id: &str, phase: &str) {
        self.busy.lock().unwrap().insert(id.into(), phase.into());
    }
    fn clear_busy(&self, id: &str) {
        self.busy.lock().unwrap().remove(id);
    }
    fn is_busy(&self, id: &str) -> bool {
        self.busy.lock().unwrap().contains_key(id)
    }
    fn alloc_host_port(&self) -> Result<u16> {
        let mut recent = self.recent_ports.lock().unwrap();
        recent.retain(|_, t| t.elapsed() < Duration::from_secs(30));
        for _ in 0..32 {
            let port = std::net::TcpListener::bind(("0.0.0.0", 0))?.local_addr()?.port();
            if let std::collections::hash_map::Entry::Vacant(e) = recent.entry(port) {
                e.insert(Instant::now());
                return Ok(port);
            }
        }
        let port = std::net::TcpListener::bind(("0.0.0.0", 0))?.local_addr()?.port();
        recent.insert(port, Instant::now());
        Ok(port)
    }
}

pub fn container_name(app: &str, id: &str) -> String {
    format!("latrix-{app}-{id}")
}

#[derive(Debug, Clone)]
pub struct Ctr {
    pub id: String,
    pub name: String,
    pub instance: String,
    pub app: String,
    pub status: String,
    pub restarts: u32,
    pub ports: BTreeMap<u16, u16>,
    /// Host addresses the ports are published on.
    pub host_ips: Vec<String>,
    pub ip: String,
    pub error: String,
}

pub async fn list_containers() -> Result<Vec<Ctr>> {
    // Retry once if a container vanishes between `docker ps` and `docker inspect`.
    for attempt in 0..2 {
        let ids = cmd_timeout(
            "docker",
            &["ps", "-aq", "--filter", "label=latrix.instance"],
            Duration::from_secs(15),
        )
        .await?;
        let ids: Vec<&str> = ids.split_whitespace().collect();
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut args = vec!["inspect"];
        args.extend(ids.iter());
        match cmd_timeout("docker", &args, Duration::from_secs(15)).await {
            Ok(out) => {
                let v: serde_json::Value = serde_json::from_str(&out)?;
                let mut res = vec![];
                for c in v.as_array().cloned().unwrap_or_default() {
                    let labels = &c["Config"]["Labels"];
                    let mut ports = BTreeMap::new();
                    let mut host_ips: Vec<String> = vec![];
                    if let Some(map) = c["NetworkSettings"]["Ports"].as_object() {
                        for (k, binds) in map {
                            let Some(cp) = k.strip_suffix("/tcp").and_then(|p| p.parse::<u16>().ok()) else { continue };
                            let first = binds.as_array().and_then(|a| a.first());
                            if let Some(hp) = first.and_then(|b| b["HostPort"].as_str()).and_then(|p| p.parse::<u16>().ok()) {
                                ports.insert(cp, hp);
                            }
                            for b in binds.as_array().cloned().unwrap_or_default() {
                                if let Some(ip) = b["HostIp"].as_str() {
                                    if !host_ips.iter().any(|x| x == ip) {
                                        host_ips.push(ip.to_string());
                                    }
                                }
                            }
                        }
                    }
                    let mut ip = c["NetworkSettings"]["IPAddress"].as_str().unwrap_or("").to_string();
                    if ip.is_empty() {
                        if let Some(nets) = c["NetworkSettings"]["Networks"].as_object() {
                            if let Some(n) = nets.values().find_map(|n| n["IPAddress"].as_str().filter(|s| !s.is_empty())) {
                                ip = n.to_string();
                            }
                        }
                    }
                    res.push(Ctr {
                        id: c["Id"].as_str().unwrap_or("").to_string(),
                        name: c["Name"].as_str().unwrap_or("").trim_start_matches('/').to_string(),
                        instance: labels["latrix.instance"].as_str().unwrap_or("").to_string(),
                        app: labels["latrix.app"].as_str().unwrap_or("").to_string(),
                        status: c["State"]["Status"].as_str().unwrap_or("").to_string(),
                        restarts: c["RestartCount"].as_u64().unwrap_or(0) as u32,
                        ports,
                        host_ips,
                        ip,
                        error: c["State"]["Error"].as_str().unwrap_or("").to_string(),
                    });
                }
                return Ok(res);
            }
            Err(e) if attempt == 0 => {
                debug!("docker inspect transient error (retrying): {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => {
                // Never return Ok(vec![]) on inspect failure — that would make
                // reconcile_once think every container vanished and force-recreate all of them.
                return Err(e.context("docker inspect failed"));
            }
        }
    }
    unreachable!()
}

pub async fn reconcile_loop(agent: Arc<Agent>) {
    let mut rx = agent.changed.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    if agent.dev {
        let _ = cmd_timeout("docker", &["network", "create", "latrix"], Duration::from_secs(15)).await;
    }
    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = rx.changed() => {},
        }
        match reconcile_once(&agent).await {
            Ok(()) => agent.rt.docker_failures.store(0, std::sync::atomic::Ordering::SeqCst),
            Err(e) => {
                let n = agent.rt.docker_failures.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if n >= 3 {
                    // Mark cached reports unhealthy so traffic stops routing here while Docker is wedged.
                    for r in agent.rt.reports.lock().unwrap().values_mut() {
                        r.healthy = false;
                    }
                }
                if n == 1 || n.is_multiple_of(20) {
                    warn!("runtime reconcile: {e:#}");
                }
            }
        }
    }
}

async fn reconcile_once(agent: &Arc<Agent>) -> Result<()> {
    let s = agent.snapshot();
    let me = agent.me.machine_id;
    let ctrs = list_containers().await?;
    let by_inst: HashMap<String, Ctr> = ctrs.iter().map(|c| (c.instance.clone(), c.clone())).collect();

    // Stop containers that should not run here.
    for c in &ctrs {
        let keep = s
            .instances
            .get(&c.instance)
            .map(|i| !i.stopping && i.machine == me)
            .unwrap_or(false);
        if !keep && !agent.rt.is_busy(&c.instance) {
            let timeout = s
                .apps
                .get(&c.app)
                .and_then(|a| s.instances.get(&c.instance).and_then(|i| a.release(i.release)))
                .map(|r| r.config.deploy.stop_timeout_secs())
                .unwrap_or(10);
            agent.rt.set_busy(&c.instance, "stopping");
            let agent = agent.clone();
            let c = c.clone();
            tokio::spawn(async move {
                info!("stopping {}", c.name);
                let t = timeout.to_string();
                let stop_limit = Duration::from_secs(timeout.saturating_add(30));
                let _ = cmd_timeout("docker", &["stop", "-t", &t, &c.id], stop_limit).await;
                let _ = cmd_timeout("docker", &["rm", "-f", &c.id], Duration::from_secs(30)).await;
                agent.rt.health.lock().unwrap().remove(&c.instance);
                agent.rt.clear_busy(&c.instance);
                agent.vols.kick();
            });
        }
    }

    // Start instances that should run here.
    let mine: Vec<Instance> = s.instances_on(me).filter(|i| !i.stopping).cloned().collect();
    let wanted = wanted_ips(agent);
    // Move containers to a new address one at a time, gated per-app so one
    // broken app doesn't block healthy apps from rebinding to the mesh IP.
    let rebind_ready = agent.rt.busy.lock().unwrap().is_empty()
        && agent.rt.last_rebind.lock().unwrap().map(|t| t.elapsed() > Duration::from_secs(15)).unwrap_or(true);
    let mut rebinds = if rebind_ready { 0 } else { 1 };
    for inst in &mine {
        if agent.rt.is_busy(&inst.id) {
            continue;
        }
        let app_healthy = {
            let health = agent.rt.health.lock().unwrap();
            mine.iter()
                .filter(|x| x.app == inst.app)
                .all(|x| health.get(&x.id).map(|h| h.healthy).unwrap_or(false))
        };
        match by_inst.get(&inst.id) {
            None => {
                // Back off after failures: 5s, 10s, 20s ... up to 2 minutes.
                if let Some((t, _, n)) = agent.rt.failures.lock().unwrap().get(&inst.id) {
                    let wait = Duration::from_secs((5u64 << (*n).min(5)).min(120));
                    if t.elapsed() < wait {
                        continue;
                    }
                }
                agent.rt.set_busy(&inst.id, "pulling");
                let agent = agent.clone();
                let inst = inst.clone();
                tokio::spawn(async move {
                    match start_instance(&agent, &inst).await {
                        Ok(()) => {
                            agent.rt.failures.lock().unwrap().remove(&inst.id);
                        }
                        Err(e) => {
                            warn!("could not start {} ({}): {e:#}", inst.id, inst.app);
                            let mut f = agent.rt.failures.lock().unwrap();
                            let n = f.get(&inst.id).map(|x| x.2.saturating_add(1)).unwrap_or(1);
                            f.insert(inst.id.clone(), (Instant::now(), format!("{e:#}"), n));
                        }
                    }
                    agent.rt.clear_busy(&inst.id);
                });
            }
            Some(c)
                if c.status == "running"
                    && !c.ports.is_empty()
                    && !wanted.iter().all(|ip| c.host_ips.contains(ip))
                    && rebinds == 0
                    && app_healthy =>
            {
                // Published on an old address (the mesh went down or came back):
                // move it to the current one, one container per pass.
                rebinds += 1;
                *agent.rt.last_rebind.lock().unwrap() = Some(Instant::now());
                let stop_t = s
                    .apps
                    .get(&inst.app)
                    .and_then(|a| a.release(inst.release))
                    .map(|r| r.config.deploy.stop_timeout_secs())
                    .unwrap_or(10);
                info!("{} is published on {} instead of {}; recreating it", c.name, c.host_ips.join(","), wanted.join(","));
                agent.rt.set_busy(&c.instance, "stopping");
                let agent = agent.clone();
                let c = c.clone();
                tokio::spawn(async move {
                    // Graceful stop first: in-flight requests finish, new ones
                    // go to the other instances.
                    let t = stop_t.to_string();
                    let _ = cmd_timeout("docker", &["stop", "-t", &t, &c.id], Duration::from_secs(stop_t.saturating_add(30))).await;
                    let _ = cmd_timeout("docker", &["rm", "-f", &c.id], Duration::from_secs(30)).await;
                    agent.rt.clear_busy(&c.instance);
                });
            }
            Some(c)
                if c.status == "running"
                    && c.ports.is_empty()
                    && s.apps
                        .get(&inst.app)
                        .and_then(|a| a.release(inst.release))
                        .map(|r| !r.config.container_ports().is_empty())
                        .unwrap_or(false) =>
            {
                // Running but its published ports are gone (e.g. the address it
                // was bound to disappeared): recreate it on the current address.
                warn!("{} lost its port bindings; recreating it", c.name);
                agent.rt.set_busy(&c.instance, "stopping");
                let agent = agent.clone();
                let c = c.clone();
                tokio::spawn(async move {
                    let _ = cmd_timeout("docker", &["stop", "-t", "10", &c.id], Duration::from_secs(40)).await;
                    let _ = cmd_timeout("docker", &["rm", "-f", &c.id], Duration::from_secs(30)).await;
                    agent.rt.clear_busy(&c.instance);
                });
            }
            Some(c) if matches!(c.status.as_str(), "exited" | "created" | "dead") => {
                // Restart policy covers crashes; this covers manual stops and odd states.
                let agent = agent.clone();
                let c = c.clone();
                agent.rt.set_busy(&c.instance, "starting");
                tokio::spawn(async move {
                    if cmd_timeout("docker", &["start", &c.id], Duration::from_secs(30)).await.is_err() {
                        let _ = cmd_timeout("docker", &["rm", "-f", &c.id], Duration::from_secs(30)).await;
                    }
                    agent.rt.clear_busy(&c.instance);
                });
            }
            _ => {}
        }
    }

    // Health checks (skip instances currently busy stopping/starting).
    let stats = agent.rt.stats.lock().unwrap().clone();
    let busy_now = agent.rt.busy.lock().unwrap().clone();
    let mut checks = vec![];
    for inst in &mine {
        if busy_now.contains_key(&inst.id) {
            continue;
        }
        let Some(c) = by_inst.get(&inst.id) else { continue };
        if c.status != "running" {
            continue;
        }
        let Some(cfg) = s.apps.get(&inst.app).and_then(|a| a.release(inst.release)).map(|r| r.config.clone()) else {
            continue;
        };
        let c = c.clone();
        let bind = agent.bind_ip();
        let id = inst.id.clone();
        let http = agent.rt.health_http.clone();
        checks.push(async move {
            let ok = check_health(&http, &cfg, &c, &bind).await;
            (id, ok)
        });
    }
    let results: HashMap<String, bool> = futures::future::join_all(checks).await.into_iter().collect();

    let mut reports = HashMap::new();
    let mut running_apps = HashMap::new();
    {
        let mut health = agent.rt.health.lock().unwrap();
        let busy = agent.rt.busy.lock().unwrap().clone();
        let failures = agent.rt.failures.lock().unwrap();
        for inst in &mine {
            let c = by_inst.get(&inst.id);
            let h = health.entry(inst.id.clone()).or_default();
            match results.get(&inst.id) {
                Some(true) => {
                    if !h.healthy {
                        h.healthy_since = util::now();
                    }
                    h.healthy = true;
                    h.fails = 0;
                    h.unhealthy_since = 0;
                    h.unhealthy_at = None;
                }
                Some(false) => {
                    h.fails = h.fails.saturating_add(1);
                    // Need 3 consecutive failures to mark a healthy instance unhealthy.
                    if h.fails >= 3 || !h.healthy {
                        if h.healthy {
                            h.unhealthy_since = util::now();
                            h.unhealthy_at = Some(Instant::now());
                        }
                        h.healthy = false;
                    }
                }
                None => {
                    // Track transition to unhealthy on crash/exit so restart_stuck can still replace it.
                    if h.healthy && !busy.contains_key(&inst.id) {
                        h.unhealthy_since = util::now();
                        h.unhealthy_at = Some(Instant::now());
                    }
                    h.healthy = false;
                }
            }
            let status = match (busy.get(&inst.id), c) {
                (Some(p), _) => p.clone(),
                (None, Some(c)) if c.status == "running" => {
                    if h.healthy { "running".into() } else { "starting".into() }
                }
                (None, Some(c)) => c.status.clone(),
                (None, None) => {
                    if failures.contains_key(&inst.id) { "failed".into() } else { "pending".into() }
                }
            };
            if let Some(c) = c {
                if matches!(c.status.as_str(), "running" | "restarting") {
                    running_apps.insert(inst.app.clone(), c.name.clone());
                }
            }
            let (cpu, mem) = c.and_then(|c| stats.get(&c.name).copied()).unwrap_or((0.0, 0.0));
            let error = failures
                .get(&inst.id)
                .map(|f| f.1.clone())
                .or_else(|| c.map(|c| c.error.clone()).filter(|e| !e.is_empty()));
            let is_busy = busy.contains_key(&inst.id);
            let unhealthy_for = h
                .unhealthy_at
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0);
            reports.insert(
                inst.id.clone(),
                InstanceReport {
                    id: inst.id.clone(),
                    status,
                    healthy: !is_busy && h.healthy && c.map(|c| c.status == "running").unwrap_or(false),
                    ports: c.map(|c| c.ports.clone()).unwrap_or_default(),
                    restarts: c.map(|c| c.restarts).unwrap_or(0),
                    cpu_pct: cpu,
                    mem_mb: mem,
                    error,
                    healthy_since: h.healthy_since,
                    unhealthy_since: h.unhealthy_since,
                    unhealthy_for,
                },
            );
        }
        // Containers being stopped / not (or no longer) assigned here are still
        // reported so the leader knows when they are really gone — AND kept in
        // `running_apps` while still running/restarting so `volumes::sync_once`
        // NEVER runs a final "idle" sync while a DB container is still flushing!
        for c in &ctrs {
            if matches!(c.status.as_str(), "running" | "restarting") && !c.app.is_empty() {
                running_apps.entry(c.app.clone()).or_insert_with(|| c.name.clone());
            }
            if reports.contains_key(&c.instance) {
                continue;
            }
            reports.insert(
                c.instance.clone(),
                InstanceReport {
                    id: c.instance.clone(),
                    status: "stopping".into(),
                    healthy: false,
                    ports: c.ports.clone(),
                    ..Default::default()
                },
            );
        }
        // Also report in-flight busy starts (e.g. pulling) even if the instance was
        // just marked stopping, so cleanup_stopping doesn't race with start_instance.
        for (id, phase) in &busy {
            reports.entry(id.clone()).or_insert_with(|| InstanceReport {
                id: id.clone(),
                status: phase.clone(),
                healthy: false,
                ..Default::default()
            });
        }
        let mine_ids: HashSet<&String> = mine.iter().map(|i| &i.id).collect();
        health.retain(|k, _| mine_ids.contains(k));
    }
    agent.rt.failures.lock().unwrap().retain(|k, _| mine.iter().any(|i| &i.id == k));
    *agent.rt.reports.lock().unwrap() = reports;
    *agent.rt.running_apps.lock().unwrap() = running_apps;
    Ok(())
}

async fn tcp_ok(addr: &str) -> bool {
    matches!(
        tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

async fn check_health(http: &reqwest::Client, cfg: &AppConfig, c: &Ctr, bind: &str) -> bool {
    // Prefer the container IP on Linux (connecting through the docker port proxy
    // always "succeeds" even when nothing listens), while also verifying the
    // host port binding exists so lost port bindings aren't hidden.
    let target = |port: u16| -> Option<String> {
        if !c.ports.contains_key(&port) {
            return None;
        }
        if !c.ip.is_empty() && cfg!(target_os = "linux") {
            Some(format!("{}:{}", c.ip, port))
        } else {
            c.ports.get(&port).map(|hp| format!("{bind}:{hp}"))
        }
    };
    if let Some(h) = &cfg.http {
        let Some(addr) = target(h.port) else { return false };
        if let Some(path) = &h.health {
            if !path.starts_with('/')
                || path.starts_with("//")
                || path.chars().any(|ch| ch.is_whitespace() || ch.is_control())
            {
                return false;
            }
            let url = format!("http://{addr}{path}");
            return match http.get(&url).send().await {
                Ok(r) => r.status().as_u16() < 400,
                Err(_) => false,
            };
        }
        return tcp_ok(&addr).await;
    }
    if let Some(p) = cfg.ports.iter().find(|p| p.protocol == "tcp") {
        if let Some(addr) = target(p.port) {
            return tcp_ok(&addr).await;
        }
        return false;
    }
    // UDP only: running counts as healthy.
    true
}

/// "10.77.0.1:7471/web:123" -> ("10.77.0.1:7471", "web:123")
fn split_registry(image: &str) -> Option<(&str, &str)> {
    let (host, rest) = image.split_once('/')?;
    if host.contains(':') || host.contains('.') || host == "localhost" {
        Some((host, rest))
    } else {
        None
    }
}

async fn image_exists(image: &str) -> bool {
    cmd_timeout("docker", &["image", "inspect", "--format", "{{.Id}}", "--", image], Duration::from_secs(15))
        .await
        .is_ok()
}

fn summarize_pull_error(err: &str) -> String {
    let msg = err.split_once(" failed: ").map(|(_, rest)| rest).unwrap_or(err).trim();
    let msg = msg.strip_prefix("Error response from daemon: ").unwrap_or(msg).trim();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("not found") || lower.contains("manifest unknown") {
        "not found".into()
    } else {
        msg.to_string()
    }
}

/// Make sure the release's image is present, pulling it from whichever
/// machine's registry has it.
pub async fn ensure_image(agent: &Arc<Agent>, rel: &Release) -> Result<()> {
    util::validate_image_ref(&rel.image)?;
    if image_exists(&rel.image).await {
        return Ok(());
    }
    if rel.sources.is_empty() {
        cmd_timeout("docker", &["pull", &rel.image], Duration::from_secs(300))
            .await
            .with_context(|| format!("pulling {}", rel.image))?;
        return Ok(());
    }
    let Some((_, repo)) = split_registry(&rel.image) else {
        cmd_timeout("docker", &["pull", &rel.image], Duration::from_secs(300)).await?;
        return Ok(());
    };
    let s = agent.snapshot();
    let alive = agent.alive_set();
    // Try alive source machines first, then other alive machines, then offline sources last.
    let mut ips: Vec<String> = vec![];
    for m in &rel.sources {
        if alive.contains(m) {
            if let Some(ip) = agent.ip_of(*m) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    for m in s.machines.values() {
        if alive.contains(&m.id) && !ips.contains(&m.overlay_ip) {
            ips.push(m.overlay_ip.clone());
        }
    }
    for m in &rel.sources {
        if let Some(ip) = agent.ip_of(*m) {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    if agent.dev {
        ips = vec!["127.0.0.1".into()];
    }
    let mut errs: Vec<String> = vec![];
    for ip in ips {
        let pull_host = if ip == agent.me.overlay_ip { "127.0.0.1" } else { ip.as_str() };
        let r = format!("{pull_host}:{REGISTRY_PORT}/{repo}");
        match cmd_timeout("docker", &["pull", "-q", &r], Duration::from_secs(180)).await {
            Ok(_) => {
                if r != rel.image {
                    cmd_timeout("docker", &["tag", &r, &rel.image], Duration::from_secs(15)).await?;
                }
                // Mirror into our own registry under the shared GC read lock so
                // registry GC never deletes in-flight layers during the push.
                if pull_host != "127.0.0.1" {
                    let own = format!("127.0.0.1:{REGISTRY_PORT}/{repo}");
                    let agent_push = agent.clone();
                    tokio::spawn(async move {
                        let _gc_read = agent_push.rt.registry_gc_lock.read().await;
                        if cmd_timeout("docker", &["tag", &r, &own], Duration::from_secs(15)).await.is_ok() {
                            let _ = cmd_timeout("docker", &["push", "-q", &own], Duration::from_secs(180)).await;
                        }
                    });
                }
                return Ok(());
            }
            Err(e) => errs.push(format!("{ip}: {}", summarize_pull_error(&e.to_string()))),
        }
    }
    bail!(
        "image {} not available from any machine ({})",
        rel.image,
        errs.join("; ")
    )
}

async fn exposed_ports(image: &str) -> Vec<u16> {
    let Ok(out) = cmd_timeout(
        "docker",
        &["image", "inspect", "--format", "{{json .Config.ExposedPorts}}", "--", image],
        Duration::from_secs(15),
    )
    .await
    else {
        return vec![];
    };
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_default();
    v.as_object()
        .map(|m| {
            m.keys()
                .filter_map(|k| k.strip_suffix("/tcp").and_then(|p| p.parse().ok()))
                .collect()
        })
        .unwrap_or_default()
}

/// Like Docker named volumes: a brand-new volume starts with the image's
/// files at that path and the same owner/permissions, so images that run as
/// a non-root user (postgres, many others) can write to it. Best effort.
async fn seed_volume(image: &str, dir: &std::path::Path, path: &str) {
    if path == "/" || path == "/__latrix_vol" || path.contains(':') || path.is_empty() {
        return;
    }
    // Copy regular files/dirs/symlinks while avoiding special device files and stripping setuid/setgid.
    let script = r#"if [ -d "$P" ]; then cp -rP --preserve=mode,ownership,timestamps "$P"/. /__latrix_vol/ 2>/dev/null || cp -a "$P"/. /__latrix_vol/ 2>/dev/null; chmod -R a-s /__latrix_vol 2>/dev/null; chown "$(stat -c %u:%g "$P")" /__latrix_vol 2>/dev/null; chmod "$(stat -c %a "$P")" /__latrix_vol 2>/dev/null; fi; true"#;
    let mount = format!("{}:/__latrix_vol", dir.display());
    let env = format!("P={path}");
    if let Err(e) = cmd_timeout(
        "docker",
        &[
            "run",
            "--rm",
            "--network=none",
            "--memory=256m",
            "--pids-limit=64",
            "--user",
            "0",
            "--entrypoint",
            "sh",
            "-e",
            &env,
            "-v",
            &mount,
            image,
            "-c",
            script,
        ],
        Duration::from_secs(60),
    )
    .await
    {
        debug!("could not seed volume {} from {image}: {e}", dir.display());
    }
}

/// Addresses app ports are published on: always 127.0.0.1, plus the mesh IP
/// while it exists.
fn wanted_ips(agent: &Agent) -> Vec<String> {
    let mut ips = vec!["127.0.0.1".to_string()];
    let b = agent.bind_ip();
    if b != "127.0.0.1" {
        ips.push(b);
    }
    ips
}

/// RAII cleanup for temporary `0600` docker `--env-file`.
struct EnvFileGuard(std::path::PathBuf);
impl Drop for EnvFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn start_instance(agent: &Arc<Agent>, inst: &Instance) -> Result<()> {
    let s = agent.snapshot();
    let app = s.apps.get(&inst.app).context("app no longer exists")?;
    let rel = app.release(inst.release).context("release no longer exists")?.clone();
    let cfg = &rel.config;
    util::validate_image_ref(&rel.image)?;
    ensure_image(agent, &rel).await?;

    // Re-check cluster state after potentially long image pull so a cancelled or
    // moved stateful instance never launches a split-brain second writer!
    let still_active = |snap: &ClusterState| {
        snap.instances
            .get(&inst.id)
            .map(|i| !i.stopping && i.machine == agent.me.machine_id)
            .unwrap_or(false)
    };
    if !still_active(&agent.snapshot()) {
        debug!("instance {} cancelled while pulling; aborting start", inst.id);
        return Ok(());
    }
    agent.rt.set_busy(&inst.id, "starting");

    let name = container_name(&inst.app, &inst.id);
    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        name.clone(),
        "--hostname".into(),
        format!("{}-{}", inst.app, inst.id),
        "--restart".into(),
        "unless-stopped".into(),
        "--label".into(),
        format!("latrix.instance={}", inst.id),
        "--label".into(),
        format!("latrix.app={}", inst.app),
        "--label".into(),
        format!("latrix.release={}", inst.release),
    ];
    let mem = cfg.scale.memory_mb();
    if mem > 0 {
        args.push("--memory".into());
        args.push(format!("{mem}m"));
    }
    if cfg.scale.cpu.is_finite() && cfg.scale.cpu > 0.0 {
        args.push("--cpus".into());
        args.push(format!("{}", cfg.scale.cpu));
    }
    if let Some(shm) = &cfg.shm_size {
        if let Ok(mb) = util::parse_size_mb(shm) {
            if mb > 0 {
                args.push("--shm-size".into());
                args.push(format!("{mb}m"));
            }
        }
    }
    if let Some(nofile) = cfg.nofile {
        if nofile > 0 {
            args.push("--ulimit".into());
            args.push(format!("nofile={nofile}:{nofile}"));
        }
    }
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    if let Some(h) = &cfg.http {
        env.insert("PORT".into(), h.port.to_string());
    }
    env.extend(cfg.env.clone());
    env.extend(app.secrets.clone());
    env.insert("LATRIX_APP".into(), inst.app.clone());
    env.insert("LATRIX_INSTANCE".into(), inst.id.clone());
    env.insert("LATRIX_RELEASE".into(), inst.release.to_string());
    env.insert(
        "LATRIX_MACHINE".into(),
        s.machines.get(&inst.machine).map(|m| m.name.clone()).unwrap_or_default(),
    );
    // Pass single-line env vars/secrets via a temporary 0600 `--env-file` so
    // secrets never appear in `/proc/<pid>/cmdline`. (Docker `--env-file` splits
    // lines on `\n`, so multiline values must still use `-e` — with `cmd_redacted`
    // ensuring argv is never logged or returned in errors.)
    let mut env_file_lines = String::new();
    let mut multiline_env: Vec<(String, String)> = vec![];
    for (k, v) in env {
        if k.contains(['=', '\0', '\r', '\n']) || v.contains('\0') {
            continue;
        }
        if v.contains(['\n', '\r']) {
            multiline_env.push((k, v));
        } else {
            env_file_lines.push_str(&k);
            env_file_lines.push('=');
            env_file_lines.push_str(&v);
            env_file_lines.push('\n');
        }
    }
    let _env_guard = if !env_file_lines.is_empty() {
        let env_path = agent
            .data
            .join(format!(".env-{}-{}", inst.id, util::random_id(6)));
        util::write_atomic_private(&env_path, env_file_lines.as_bytes())?;
        args.push("--env-file".into());
        args.push(env_path.display().to_string());
        Some(EnvFileGuard(env_path))
    } else {
        None
    };
    for (k, v) in multiline_env {
        args.push("-e".into());
        args.push(format!("{k}={v}"));
    }
    let mut ports = cfg.container_ports();
    for p in exposed_ports(&rel.image).await {
        if !ports.contains(&p) {
            ports.push(p);
        }
    }
    // Same host port on 127.0.0.1 (this machine's proxy, works whatever the
    // mesh does) and on the mesh IP (other machines), when the mesh is up.
    let ips = wanted_ips(agent);
    for p in ports {
        let hp = agent.rt.alloc_host_port()?;
        for ip in &ips {
            args.push("-p".into());
            args.push(format!("{ip}:{hp}:{p}"));
        }
    }
    // UDP (game servers, voice, ...): straight on the machine's own IP, no
    // proxy hop. The scheduler runs at most one instance per machine.
    for (public, p) in cfg.udp_ports() {
        args.push("-p".into());
        args.push(format!("0.0.0.0:{public}:{p}/udp"));
    }
    for v in &cfg.volumes {
        if v.path.contains(':') || v.path == "/" || v.path == "/__latrix_vol" {
            bail!("invalid volume mount path '{}'", v.path);
        }
        let dir = agent.data.join("volumes").join(Volume::dir_name(&inst.app, &v.name));
        let fresh = std::fs::read_dir(&dir).map(|mut d| d.next().is_none()).unwrap_or(true);
        std::fs::create_dir_all(&dir)?;
        if fresh {
            seed_volume(&rel.image, &dir, &v.path).await;
        }
        args.push("-v".into());
        args.push(format!("{}:{}", dir.display(), v.path));
    }
    if agent.dev {
        args.push("--network".into());
        args.push("latrix".into());
        args.push("--network-alias".into());
        args.push(inst.app.clone());
        if cfg.service.is_some() {
            args.push("--network-alias".into());
            args.push(cfg.service_name().into());
        }
        for alias in &cfg.aliases {
            args.push("--network-alias".into());
            args.push(alias.clone());
        }
    } else {
        args.push("--dns".into());
        args.push(agent.me.overlay_ip.clone());
        if let Some(g) = &cfg.group {
            args.push("--dns-search".into());
            args.push(format!("{g}.internal"));
        }
        args.push("--dns-search".into());
        args.push("internal".into());
    }
    args.push(rel.image.clone());
    if let Some(c) = &cfg.command {
        args.extend(c.to_args());
    }
    if !still_active(&agent.snapshot()) {
        debug!("instance {} cancelled before docker run; aborting start", inst.id);
        return Ok(());
    }
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    // A leftover container with the same name would make `run` fail.
    let _ = cmd_timeout("docker", &["rm", "-f", &name], Duration::from_secs(30)).await;
    cmd_redacted("docker", &refs, Duration::from_secs(60)).await?;
    info!("started {name} ({})", rel.image);
    Ok(())
}

/// Collect CPU / memory usage per container.
pub async fn stats_loop(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tick.tick().await;
        let Ok(out) = cmd_timeout(
            "docker",
            &["stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
            Duration::from_secs(15),
        )
        .await
        else {
            continue;
        };
        let mut map = HashMap::new();
        for line in out.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() < 3 || !parts[0].starts_with("latrix-") {
                continue;
            }
            let cpu = parts[1]
                .trim_end_matches('%')
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|v| v.is_finite() && *v >= 0.0)
                .unwrap_or(0.0);
            let used = parts[2].split('/').next().unwrap_or("").trim();
            map.insert(parts[0].to_string(), (cpu, parse_docker_size_mb(used)));
        }
        *agent.rt.stats.lock().unwrap() = map;
    }
}

pub fn parse_docker_size_mb(s: &str) -> f64 {
    let s = s.trim();
    let idx = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let n: f64 = s[..idx]
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .unwrap_or(0.0);
    let mb = match s[idx..].trim().to_ascii_lowercase().as_str() {
        "b" => n / 1048576.0,
        "kb" | "kib" => n / 1024.0,
        "mb" | "mib" => n,
        "gb" | "gib" => n * 1024.0,
        "tb" | "tib" => n * 1048576.0,
        _ => n,
    };
    if mb.is_finite() && mb >= 0.0 { mb } else { 0.0 }
}

/// Docker must trust the mesh registries (10.77.0.0/16) and this machine's
/// own registry on 127.0.0.1. Note: listing *any* insecure registries in
/// daemon.json drops Docker's built-in trust of 127.0.0.0/8, so both are
/// needed. Machines set up by older versions are fixed here.
pub async fn ensure_docker_config(agent: &Agent) {
    let path = std::path::Path::new("/etc/docker/daemon.json");
    let mut v: serde_json::Value = match std::fs::read_to_string(path) {
        Ok(t) if !t.trim().is_empty() => match serde_json::from_str(&t) {
            Ok(v) => v,
            Err(e) => {
                warn!("cannot parse {}: {e}; not changing it", path.display());
                return;
            }
        },
        _ => serde_json::json!({}),
    };
    let Some(obj) = v.as_object_mut() else { return };
    let regs = obj.entry("insecure-registries").or_insert_with(|| serde_json::json!([]));
    let Some(list) = regs.as_array_mut() else { return };
    let mut changed = false;
    for r in ["10.77.0.0/16", "127.0.0.0/8"] {
        if !list.iter().any(|x| x == r) {
            list.push(serde_json::json!(r));
            changed = true;
        }
    }
    if !changed {
        return;
    }
    if obj.get("live-restore").is_none() {
        obj.insert("live-restore".into(), serde_json::json!(true));
    }
    let backup = path.with_extension("json.latrix-backup");
    if !backup.exists() {
        let _ = std::fs::copy(path, &backup);
    }
    let bytes = serde_json::to_vec_pretty(&v).unwrap_or_default();
    if let Err(e) = util::write_atomic(path, &bytes) {
        warn!("cannot update {}: {e}", path.display());
        return;
    }
    info!("updated Docker's trusted registries; restarting Docker (containers keep running)");
    if let Err(e) = cmd("systemctl", &["restart", "docker"]).await {
        warn!("restarting Docker failed: {e}");
    }
    agent.event("info", "fixed Docker's registry settings on this machine".to_string());
}

/// Registry config with the in-memory blob descriptor cache disabled.
///
/// `registry:2`'s default config enables `storage.cache.blobdescriptor: inmemory`,
/// which is not invalidated when `registry garbage-collect` runs in a separate
/// process. Re-pushing a previously garbage-collected layer then hits the stale
/// cache ("Layer already exists") without writing the blob to disk, causing
/// subsequent pulls to fail with an unexpected EOF / 0-byte body.
const REGISTRY_CONFIG: &str = "\
version: 0.1
log:
  fields:
    service: registry
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
http:
  addr: :5000
  headers:
    X-Content-Type-Options: [nosniff]
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
";

/// Keep the local image registry running.
pub async fn registry_loop(agent: Arc<Agent>) {
    if !agent.dev {
        ensure_docker_config(&agent).await;
    }
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    let mut probe_fails: u32 = 0;
    loop {
        tick.tick().await;
        // Always on 127.0.0.1 (builds push there; works even if the mesh is
        // down), and on the mesh IP once it exists (other machines pull there).
        let mut ips = vec!["127.0.0.1".to_string()];
        let mesh_ip = agent.bind_ip();
        if mesh_ip != "127.0.0.1" && std::net::TcpListener::bind((mesh_ip.as_str(), 0)).is_ok() {
            ips.push(mesh_ip);
        }
        // Check the *live* bindings and mounted config: when one address is
        // missing after a Docker restart, Docker silently drops all of a
        // container's ports; older containers also lack our no-cache config.
        let live = cmd_timeout(
            "docker",
            &["inspect", "-f", "{{.State.Running}} {{json .NetworkSettings.Ports}} {{json .Mounts}}", "latrix-registry"],
            Duration::from_secs(15),
        )
        .await
        .unwrap_or_default();
        let up = live.starts_with("true");
        let bound: Vec<String> = ips
            .iter()
            .filter(|ip| live.contains(&format!("\"HostIp\":\"{ip}\"")))
            .cloned()
            .collect();
        let stale_mesh = !ips.iter().any(|ip| ip != "127.0.0.1") && live.contains("\"HostIp\":\"10.77.");
        let has_cfg = live.contains("/etc/docker/registry/config.yml");
        let answers = agent
            .http
            .get(format!("http://127.0.0.1:{REGISTRY_PORT}/v2/"))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if up && bound.len() == ips.len() && !stale_mesh && has_cfg {
            if answers {
                probe_fails = 0;
                continue;
            }
            // Don't kill a busy registry on a single transient probe timeout.
            probe_fails += 1;
            if probe_fails < 3 {
                continue;
            }
        }
        probe_fails = 0;
        let _ = cmd_timeout("docker", &["rm", "-f", "latrix-registry"], Duration::from_secs(30)).await;
        let dir = agent.data.join("registry");
        let _ = std::fs::create_dir_all(&dir);
        let cfg_path = agent.data.join("registry-config.yml");
        if std::fs::read_to_string(&cfg_path).ok().as_deref() != Some(REGISTRY_CONFIG) {
            if let Err(e) = std::fs::write(&cfg_path, REGISTRY_CONFIG) {
                warn!("could not write {}: {e}", cfg_path.display());
                continue;
            }
        }
        let vol = format!("{}:/var/lib/registry", dir.display());
        let cfg_vol = format!("{}:/etc/docker/registry/config.yml:ro", cfg_path.display());
        let mut args: Vec<String> = ["run", "-d", "--name", "latrix-registry", "--restart", "always"].iter().map(|s| s.to_string()).collect();
        for ip in &ips {
            args.push("-p".into());
            args.push(format!("{ip}:{REGISTRY_PORT}:5000"));
        }
        args.extend([
            "-v".to_string(),
            vol,
            "-v".to_string(),
            cfg_vol,
            "-e".into(),
            "REGISTRY_STORAGE_DELETE_ENABLED=true".into(),
            "registry:2".into(),
        ]);
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        match cmd("docker", &refs).await {
            Ok(_) => info!("started image registry on {}", ips.iter().map(|i| format!("{i}:{REGISTRY_PORT}")).collect::<Vec<_>>().join(", ")),
            Err(e) => warn!("could not start registry (retrying): {e}"),
        }
    }
}

/// Smart cache management: keep the images needed for rollbacks, drop the rest,
/// and keep the BuildKit cache within a disk-aware budget.
pub async fn gc_loop(agent: Arc<Agent>) {
    tokio::time::sleep(Duration::from_secs(120)).await;
    // Use Option<Instant> instead of `Instant::now() - Duration::from_secs(7200)`,
    // which panics on any freshly booted server with uptime < 2 hours!
    let mut last_full: Option<Instant> = None;
    let mut last_emergency: Option<Instant> = None;
    let mut last_disk_warn: Option<Instant> = None;
    let mut known: HashSet<String> = agent.snapshot().apps.keys().cloned().collect();
    loop {
        // Hourly, and soon after an app is destroyed (its images go right away).
        let apps: HashSet<String> = agent.snapshot().apps.keys().cloned().collect();
        let removed = known.iter().any(|a| !apps.contains(a));
        known = apps;
        if removed || last_full.map(|t| t.elapsed() > Duration::from_secs(3600)).unwrap_or(true) {
            last_full = Some(Instant::now());
            if let Err(e) = gc_once(&agent).await {
                warn!("cache cleanup: {e:#}");
            }
        }
        // Disk nearly full: clean harder, then shout if that wasn't enough.
        let used = disk_used_fraction(&agent);
        if used > 0.90 && last_emergency.map(|t| t.elapsed() > Duration::from_secs(1800)).unwrap_or(true) {
            last_emergency = Some(Instant::now());
            let before = used;
            emergency_cleanup(&agent).await;
            super::metrics::sample_disk(&agent).await;
            let after = disk_used_fraction(&agent);
            agent.event(
                "info",
                format!("disk was {:.0}% full: removed all build cache and unused images, now {:.0}%", before * 100.0, after * 100.0),
            );
            if after > 0.90 && last_disk_warn.map(|t| t.elapsed() > Duration::from_secs(3600)).unwrap_or(true) {
                last_disk_warn = Some(Instant::now());
                agent.event(
                    "warn",
                    format!(
                        "disk is {:.0}% full even after cleaning up; give this machine more disk, or move apps/volumes off it",
                        after * 100.0
                    ),
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

fn disk_used_fraction(agent: &Agent) -> f64 {
    let m = agent.sampler.latest();
    if m.disk_total_gb > 0.0 {
        m.disk_used_gb / m.disk_total_gb
    } else {
        0.0
    }
}

/// Everything that can be rebuilt or re-pulled goes: all build cache, all
/// images not used by a container, and all but the newest volume snapshot.
async fn emergency_cleanup(agent: &Agent) {
    let _ = cmd("docker", &["builder", "prune", "-af"]).await;
    let _ = cmd("docker", &["image", "prune", "-af"]).await;
    super::volumes::trim_snapshots(agent, 1);
    refresh_build_cache_size(agent).await;
}

pub fn build_cache_budget_gb(agent: &Agent) -> u64 {
    let m = agent.sampler.latest();
    ((m.disk_total_gb * 0.15) as u64).clamp(2, 25)
}

pub async fn prune_build_cache(agent: &Agent) {
    let budget = format!("{}gb", build_cache_budget_gb(agent));
    if cmd("docker", &["builder", "prune", "-f", "--max-used-space", &budget]).await.is_err() {
        let _ = cmd("docker", &["builder", "prune", "-f", "--keep-storage", &budget]).await;
    }
    refresh_build_cache_size(agent).await;
}

async fn refresh_build_cache_size(agent: &Agent) {
    if let Ok(out) = cmd("docker", &["system", "df", "--format", "{{.Type}}\t{{.Size}}"]).await {
        for line in out.lines() {
            if let Some(size) = line.strip_prefix("Build Cache\t") {
                *agent.rt.build_cache_gb.lock().unwrap() = parse_docker_size_mb(size) / 1024.0;
            }
        }
    }
}

const MANIFEST_ACCEPT: &str = "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json";

async fn manifest_digest(client: &reqwest::Client, base: &str, repo: &str, tag: &str) -> Result<Option<String>> {
    let resp = client
        .head(format!("{base}/v2/{repo}/manifests/{tag}"))
        .header("Accept", MANIFEST_ACCEPT)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    Ok(resp
        .headers()
        .get("Docker-Content-Digest")
        .and_then(|d| d.to_str().ok())
        .map(|s| s.to_string()))
}

async fn gc_once(agent: &Arc<Agent>) -> Result<()> {
    let s = agent.snapshot();
    // Images worth keeping: the last 3 releases of every app.
    let mut keep: HashSet<String> = HashSet::new();
    let mut keep_tags: HashMap<String, HashSet<String>> = HashMap::new();
    for a in s.apps.values() {
        let mut rels: Vec<&Release> = a.releases.iter().collect();
        rels.sort_by_key(|r| std::cmp::Reverse(r.version));
        for r in rels.iter().take(3).chain(a.current_release().iter()) {
            keep.insert(r.image.clone());
            if let Some((_, repo)) = split_registry(&r.image) {
                if let Some((name, tag)) = repo.rsplit_once(':') {
                    keep_tags.entry(name.to_string()).or_default().insert(tag.to_string());
                }
            }
        }
    }
    // Tags built within the last 15 minutes are protected even if the CLI
    // hasn't committed `/deploy` to ClusterState yet (tag format `<unix>-<rand>`).
    let now_ts = util::now();
    let is_recent_tag = |tag: &str| -> bool {
        tag.split_once('-')
            .and_then(|(ts, _)| ts.parse::<u64>().ok())
            .map(|ts| now_ts.saturating_sub(ts) < 900)
            .unwrap_or(false)
    };
    let out = cmd_timeout("docker", &["images", "--format", "{{.Repository}}:{{.Tag}}"], Duration::from_secs(30)).await?;
    let marker = format!(":{REGISTRY_PORT}/");
    for img in out.lines() {
        if !img.contains(&marker) {
            continue;
        }
        let Some((_, repo)) = split_registry(img) else { continue };
        let Some((name, tag)) = repo.rsplit_once(':') else { continue };
        let wanted = keep.contains(img)
            || keep_tags.get(name).map(|t| t.contains(tag)).unwrap_or(false)
            || is_recent_tag(tag);
        if !wanted {
            debug!("removing old image {img}");
            let _ = cmd_timeout("docker", &["rmi", img], Duration::from_secs(30)).await;
        }
    }
    let _ = cmd_timeout("docker", &["image", "prune", "-f"], Duration::from_secs(120)).await;
    prune_build_cache(agent).await;

    // Registry: delete old manifests, then garbage-collect blobs (only when idle).
    // Acquire the write lock (try_write so we don't block builds/pushes) to prevent
    // deleting untagged blobs while a build or background mirror push is in flight.
    if agent.rt.builds_running.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        let Ok(_gc_write) = agent.rt.registry_gc_lock.try_write() else {
            return Ok(());
        };
        if agent.rt.builds_running.load(std::sync::atomic::Ordering::SeqCst) != 0 {
            return Ok(());
        }
        let base = format!("http://127.0.0.1:{REGISTRY_PORT}");
        let client = &agent.http;
        let catalog: serde_json::Value = client
            .get(format!("{base}/v2/_catalog?n=1000"))
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .json()
            .await?;
        let mut deleted = 0;
        for repo in catalog["repositories"].as_array().cloned().unwrap_or_default() {
            let Some(repo) = repo.as_str() else { continue };
            let Ok(resp) = client
                .get(format!("{base}/v2/{repo}/tags/list"))
                .timeout(Duration::from_secs(5))
                .send()
                .await
            else {
                continue;
            };
            let Ok(tags_json) = resp.json::<serde_json::Value>().await else {
                continue;
            };
            let tags: Vec<String> = tags_json["tags"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            let kept = keep_tags.get(repo);

            // Resolve kept (and recently built) tags first: registry DELETE operates
            // on manifest digests, so deleting an old tag that shares a digest with
            // a kept release would delete the kept release too.
            let mut keep_digests: HashSet<String> = HashSet::new();
            let mut keep_ok = true;
            for tag in tags.iter().filter(|t| {
                kept.map(|k| k.contains(t.as_str())).unwrap_or(false) || is_recent_tag(t)
            }) {
                match manifest_digest(client, &base, repo, tag).await {
                    Ok(Some(d)) => {
                        keep_digests.insert(d);
                    }
                    _ => {
                        keep_ok = false;
                        break;
                    }
                }
            }
            if !keep_ok {
                continue;
            }

            let mut deleted_digests: HashSet<String> = HashSet::new();
            for tag in tags.iter().filter(|t| {
                !kept.map(|k| k.contains(t.as_str())).unwrap_or(false) && !is_recent_tag(t)
            }) {
                let Ok(Some(d)) = manifest_digest(client, &base, repo, tag).await else { continue };
                if keep_digests.contains(&d) || !deleted_digests.insert(d.clone()) {
                    continue;
                }
                if client
                    .delete(format!("{base}/v2/{repo}/manifests/{d}"))
                    .timeout(Duration::from_secs(5))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
                {
                    deleted += 1;
                }
            }
        }
        if deleted > 0 && agent.rt.builds_running.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            if let Err(e) = cmd_timeout(
                "docker",
                &["exec", "latrix-registry", "registry", "garbage-collect", "--delete-untagged", "/etc/docker/registry/config.yml"],
                Duration::from_secs(300),
            )
            .await
            {
                warn!("registry garbage-collect failed: {e}");
            } else {
                info!("registry cleanup: removed {deleted} old image manifest(s)");
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct LogsQuery {
    pub instance: String,
    #[serde(default)]
    pub tail: Option<u32>,
    #[serde(default)]
    pub follow: bool,
}

/// Stream a container's logs (stdout + stderr, timestamped).
pub async fn handle_logs(State(_agent): State<Arc<Agent>>, Query(q): Query<LogsQuery>) -> Response {
    if !util::safe_id(&q.instance) {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid instance id\n").into_response();
    }
    let filter = format!("label=latrix.instance={}", q.instance);
    let id = match cmd_timeout("docker", &["ps", "-aq", "--filter", &filter], Duration::from_secs(15)).await {
        Ok(o) if !o.trim().is_empty() => o.split_whitespace().next().unwrap().to_string(),
        _ => {
            return (axum::http::StatusCode::NOT_FOUND, format!("no container for instance {}\n", q.instance))
                .into_response()
        }
    };
    let tail = q.tail.unwrap_or(100).to_string();
    let mut args = vec!["logs", "--timestamps", "--tail", &tail];
    if q.follow {
        args.push("-f");
    }
    args.push(&id);
    let mut child = match tokio::process::Command::new("docker")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(256);
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let tx2 = tx.clone();
    tokio::spawn(async move {
        let mut reader = BufReader::new(out);
        let mut buf = Vec::new();
        while let Ok(n) = reader.read_until(b'\n', &mut buf).await {
            if n == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&buf).into_owned();
            buf.clear();
            if tx.send(bytes::Bytes::from(text)).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut reader = BufReader::new(err);
        let mut buf = Vec::new();
        while let Ok(n) = reader.read_until(b'\n', &mut buf).await {
            if n == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&buf).into_owned();
            buf.clear();
            if tx2.send(bytes::Bytes::from(text)).await.is_err() {
                break;
            }
        }
    });
    let stream = futures::stream::unfold((rx, child), |(mut rx, child)| async move {
        rx.recv()
            .await
            .map(|l| (Ok::<_, std::io::Error>(l), (rx, child)))
    });
    Body::from_stream(stream).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_config_disables_inmemory_cache() {
        let doc: serde_yaml::Value = serde_yaml::from_str(REGISTRY_CONFIG).expect("valid YAML");
        assert_eq!(doc["storage"]["delete"]["enabled"].as_bool(), Some(true));
        assert!(doc["storage"]["cache"].is_null());
        assert!(!REGISTRY_CONFIG.contains("inmemory"));
    }

    #[test]
    fn summarize_pull_errors() {
        assert_eq!(
            summarize_pull_error(
                "docker pull -q 10.77.0.4:7471/app:1 failed: Error response from daemon: failed to resolve reference \"10.77.0.4:7471/app:1\": 10.77.0.4:7471/app:1: not found"
            ),
            "not found"
        );
        assert_eq!(
            summarize_pull_error(
                "docker pull -q 10.77.0.1:7471/app:1 failed: short read: expected 28247960 bytes but got 0: unexpected EOF"
            ),
            "short read: expected 28247960 bytes but got 0: unexpected EOF"
        );
    }
}
