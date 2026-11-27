//! Local container runtime: makes the containers on this machine match the
//! instances the scheduler assigned to it, health-checks them, and keeps the
//! image / build caches tidy.

use super::{cmd, Agent};
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

#[derive(Default)]
pub struct Runtime {
    reports: Mutex<HashMap<String, InstanceReport>>,
    /// instance -> phase ("pulling", "starting", "stopping")
    busy: Mutex<HashMap<String, String>>,
    health: Mutex<HashMap<String, Health>>,
    /// instance -> (last failed attempt, error)
    failures: Mutex<HashMap<String, (Instant, String, u32)>>,
    /// container name -> (cpu %, mem MB)
    stats: Mutex<HashMap<String, (f64, f64)>>,
    build_cache_gb: Mutex<f64>,
    pub builds_running: std::sync::atomic::AtomicUsize,
    /// When a container was last moved to a new address (rebinds are spaced
    /// out so routing tables everywhere catch up in between).
    last_rebind: Mutex<Option<Instant>>,
    /// Consecutive failed reconcile passes (Docker not answering).
    pub docker_failures: std::sync::atomic::AtomicU32,
    /// app -> name of its running container on this machine (for volume sync)
    pub running_apps: Mutex<HashMap<String, String>>,
}

#[derive(Default, Clone)]
struct Health {
    healthy: bool,
    fails: u32,
    healthy_since: u64,
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
    /// Running container name for an app on this machine, if any.
    pub fn running_container(&self, app: &str) -> Option<String> {
        self.running_apps.lock().unwrap().get(app).cloned()
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
    let ids = cmd("docker", &["ps", "-aq", "--filter", "label=latrix.instance"]).await?;
    let ids: Vec<&str> = ids.split_whitespace().collect();
    if ids.is_empty() {
        return Ok(vec![]);
    }
    let mut args = vec!["inspect"];
    args.extend(ids.iter());
    let out = match cmd("docker", &args).await {
        Ok(o) => o,
        // A container may vanish between ps and inspect; try again next tick.
        Err(e) => {
            debug!("docker inspect: {e}");
            return Ok(vec![]);
        }
    };
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
    Ok(res)
}

pub async fn reconcile_loop(agent: Arc<Agent>) {
    let mut rx = agent.changed.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    if agent.dev {
        let _ = cmd("docker", &["network", "create", "latrix"]).await;
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
                let _ = cmd("docker", &["stop", "-t", &t, &c.id]).await;
                let _ = cmd("docker", &["rm", "-f", &c.id]).await;
                agent.rt.health.lock().unwrap().remove(&c.instance);
                agent.rt.clear_busy(&c.instance);
                agent.vols.kick();
            });
        }
    }

    // Start instances that should run here.
    let mine: Vec<Instance> = s.instances_on(me).filter(|i| !i.stopping).cloned().collect();
    let wanted = wanted_ips(agent);
    // Move containers to a new address one at a time, and only while
    // everything else here is healthy (so an app with 2+ instances never
    // has all of them down at once).
    let all_healthy = {
        let health = agent.rt.health.lock().unwrap();
        mine.iter().all(|i| health.get(&i.id).map(|h| h.healthy).unwrap_or(false))
    } && agent.rt.busy.lock().unwrap().is_empty()
        && agent.rt.last_rebind.lock().unwrap().map(|t| t.elapsed() > Duration::from_secs(15)).unwrap_or(true);
    let mut rebinds = if all_healthy { 0 } else { 1 };
    for inst in &mine {
        if agent.rt.is_busy(&inst.id) {
            continue;
        }
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
                            let n = f.get(&inst.id).map(|x| x.2 + 1).unwrap_or(1);
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
                    && rebinds == 0 =>
            {
                // Published on an old address (the mesh went down or came back):
                // move it to the current one, one container per pass.
                rebinds += 1;
                *agent.rt.last_rebind.lock().unwrap() = Some(Instant::now());
                info!("{} is published on {} instead of {}; recreating it", c.name, c.host_ips.join(","), wanted.join(","));
                agent.rt.set_busy(&c.instance, "starting");
                let agent = agent.clone();
                let c = c.clone();
                tokio::spawn(async move {
                    // Graceful stop first: in-flight requests finish, new ones
                    // go to the other instances.
                    let _ = cmd("docker", &["stop", "-t", "10", &c.id]).await;
                    let _ = cmd("docker", &["rm", "-f", &c.id]).await;
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
                agent.rt.set_busy(&c.instance, "starting");
                let agent = agent.clone();
                let c = c.clone();
                tokio::spawn(async move {
                    let _ = cmd("docker", &["rm", "-f", &c.id]).await;
                    agent.rt.clear_busy(&c.instance);
                });
            }
            Some(c) if matches!(c.status.as_str(), "exited" | "created" | "dead") => {
                // Restart policy covers crashes; this covers manual stops and odd states.
                let agent = agent.clone();
                let c = c.clone();
                agent.rt.set_busy(&c.instance, "starting");
                tokio::spawn(async move {
                    if cmd("docker", &["start", &c.id]).await.is_err() {
                        let _ = cmd("docker", &["rm", "-f", &c.id]).await;
                    }
                    agent.rt.clear_busy(&c.instance);
                });
            }
            _ => {}
        }
    }

    // Health checks.
    let stats = agent.rt.stats.lock().unwrap().clone();
    let mut checks = vec![];
    for inst in &mine {
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
        checks.push(async move {
            let ok = check_health(&cfg, &c, &bind).await;
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
                }
                Some(false) => {
                    h.fails += 1;
                    // Need 3 consecutive failures to mark a healthy instance unhealthy.
                    if h.fails >= 3 || !h.healthy {
                        h.healthy = false;
                    }
                }
                None => h.healthy = false,
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
                if c.status == "running" {
                    running_apps.insert(inst.app.clone(), c.name.clone());
                }
            }
            let (cpu, mem) = c.and_then(|c| stats.get(&c.name).copied()).unwrap_or((0.0, 0.0));
            let error = failures
                .get(&inst.id)
                .map(|f| f.1.clone())
                .or_else(|| c.map(|c| c.error.clone()).filter(|e| !e.is_empty()));
            reports.insert(
                inst.id.clone(),
                InstanceReport {
                    id: inst.id.clone(),
                    status,
                    healthy: h.healthy && c.map(|c| c.status == "running").unwrap_or(false),
                    ports: c.map(|c| c.ports.clone()).unwrap_or_default(),
                    restarts: c.map(|c| c.restarts).unwrap_or(0),
                    cpu_pct: cpu,
                    mem_mb: mem,
                    error,
                    healthy_since: h.healthy_since,
                },
            );
        }
        // Containers being stopped / not (or no longer) assigned here are still
        // reported so the leader knows when they are really gone.
        for c in &ctrs {
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

async fn check_health(cfg: &AppConfig, c: &Ctr, bind: &str) -> bool {
    // Prefer the container IP: connecting through the docker port proxy always
    // "succeeds", even when nothing listens inside the container.
    let target = |port: u16| -> Option<String> {
        if !c.ip.is_empty() && cfg!(target_os = "linux") {
            Some(format!("{}:{}", c.ip, port))
        } else {
            c.ports.get(&port).map(|hp| format!("{bind}:{hp}"))
        }
    };
    if let Some(h) = &cfg.http {
        let Some(addr) = target(h.port) else { return false };
        if let Some(path) = &h.health {
            let url = format!("http://{addr}{path}");
            let client = reqwest::Client::new();
            return match client.get(&url).timeout(Duration::from_secs(3)).send().await {
                Ok(r) => r.status().as_u16() < 400,
                Err(_) => false,
            };
        }
        return tcp_ok(&addr).await;
    }
    if let Some(p) = cfg.ports.first() {
        if let Some(addr) = target(p.port) {
            return tcp_ok(&addr).await;
        }
        return false;
    }
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
    cmd("docker", &["image", "inspect", "--format", "{{.Id}}", image]).await.is_ok()
}

/// Make sure the release's image is present, pulling it from whichever
/// machine's registry has it.
pub async fn ensure_image(agent: &Arc<Agent>, rel: &Release) -> Result<()> {
    if image_exists(&rel.image).await {
        return Ok(());
    }
    if rel.sources.is_empty() {
        cmd("docker", &["pull", &rel.image])
            .await
            .with_context(|| format!("pulling {}", rel.image))?;
        return Ok(());
    }
    let Some((_, repo)) = split_registry(&rel.image) else {
        cmd("docker", &["pull", &rel.image]).await?;
        return Ok(());
    };
    let s = agent.snapshot();
    let mut ips: Vec<String> = rel.sources.iter().filter_map(|m| agent.ip_of(*m)).collect();
    let alive = agent.alive_set();
    for m in s.machines.values() {
        if alive.contains(&m.id) && !ips.contains(&m.overlay_ip) {
            ips.push(m.overlay_ip.clone());
        }
    }
    if agent.dev {
        ips = vec!["127.0.0.1".into()];
    }
    let mut last_err = None;
    for ip in ips {
        let r = format!("{ip}:{REGISTRY_PORT}/{repo}");
        match cmd("docker", &["pull", "-q", &r]).await {
            Ok(_) => {
                if r != rel.image {
                    cmd("docker", &["tag", &r, &rel.image]).await?;
                }
                // Mirror into our own registry so this machine can serve it too.
                let own = format!("{}/{repo}", agent.registry());
                if own != r && own != rel.image {
                    tokio::spawn(async move {
                        if cmd("docker", &["tag", &r, &own]).await.is_ok() {
                            let _ = cmd("docker", &["push", "-q", &own]).await;
                        }
                    });
                }
                return Ok(());
            }
            Err(e) => last_err = Some(e),
        }
    }
    bail!(
        "image {} not available from any machine: {}",
        rel.image,
        last_err.map(|e| e.to_string()).unwrap_or_default()
    )
}

async fn exposed_ports(image: &str) -> Vec<u16> {
    let Ok(out) = cmd("docker", &["image", "inspect", "--format", "{{json .Config.ExposedPorts}}", image]).await else {
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
    let script = r#"if [ -d "$P" ]; then cp -a "$P"/. /__latrix_vol/ 2>/dev/null; chown "$(stat -c %u:%g "$P")" /__latrix_vol 2>/dev/null; chmod "$(stat -c %a "$P")" /__latrix_vol 2>/dev/null; fi; true"#;
    let mount = format!("{}:/__latrix_vol", dir.display());
    let env = format!("P={path}");
    if let Err(e) = cmd(
        "docker",
        &["run", "--rm", "--user", "0", "--entrypoint", "sh", "-e", &env, "-v", &mount, image, "-c", script],
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

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind(("0.0.0.0", 0))?.local_addr()?.port())
}

async fn start_instance(agent: &Arc<Agent>, inst: &Instance) -> Result<()> {
    let s = agent.snapshot();
    let app = s.apps.get(&inst.app).context("app no longer exists")?;
    let rel = app.release(inst.release).context("release no longer exists")?.clone();
    let cfg = &rel.config;
    ensure_image(agent, &rel).await?;
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
    if cfg.scale.cpu > 0.0 {
        args.push("--cpus".into());
        args.push(format!("{}", cfg.scale.cpu));
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
    for (k, v) in env {
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
        let hp = free_port()?;
        for ip in &ips {
            args.push("-p".into());
            args.push(format!("{ip}:{hp}:{p}"));
        }
    }
    for v in &cfg.volumes {
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
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    // A leftover container with the same name would make `run` fail.
    let _ = cmd("docker", &["rm", "-f", &name]).await;
    cmd("docker", &refs).await?;
    info!("started {name} ({})", rel.image);
    Ok(())
}

/// Collect CPU / memory usage per container.
pub async fn stats_loop(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tick.tick().await;
        let Ok(out) = cmd(
            "docker",
            &["stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
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
            let cpu = parts[1].trim_end_matches('%').trim().parse::<f64>().unwrap_or(0.0);
            let used = parts[2].split('/').next().unwrap_or("").trim();
            map.insert(parts[0].to_string(), (cpu, parse_docker_size_mb(used)));
        }
        *agent.rt.stats.lock().unwrap() = map;
    }
}

pub fn parse_docker_size_mb(s: &str) -> f64 {
    let s = s.trim();
    let idx = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
    let n: f64 = s[..idx].trim().parse().unwrap_or(0.0);
    match s[idx..].trim().to_ascii_lowercase().as_str() {
        "b" => n / 1048576.0,
        "kb" | "kib" => n / 1024.0,
        "mb" | "mib" => n,
        "gb" | "gib" => n * 1024.0,
        "tb" | "tib" => n * 1048576.0,
        _ => n,
    }
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
    let _ = std::fs::copy(path, path.with_extension("json.latrix-backup"));
    if let Err(e) = std::fs::write(path, serde_json::to_vec_pretty(&v).unwrap_or_default()) {
        warn!("cannot update {}: {e}", path.display());
        return;
    }
    info!("updated Docker's trusted registries; restarting Docker (containers keep running)");
    if let Err(e) = cmd("systemctl", &["restart", "docker"]).await {
        warn!("restarting Docker failed: {e}");
    }
    agent.event("info", "fixed Docker's registry settings on this machine".to_string());
}

/// Keep the local image registry running.
pub async fn registry_loop(agent: Arc<Agent>) {
    if !agent.dev {
        ensure_docker_config(&agent).await;
    }
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        // Always on 127.0.0.1 (builds push there; works even if the mesh is
        // down), and on the mesh IP once it exists (other machines pull there).
        let mut ips = vec!["127.0.0.1".to_string()];
        let mesh_ip = agent.bind_ip();
        if mesh_ip != "127.0.0.1" && std::net::TcpListener::bind((mesh_ip.as_str(), 0)).is_ok() {
            ips.push(mesh_ip);
        }
        // Check the *live* bindings: when one address is missing after a
        // Docker restart, Docker silently drops all of a container's ports.
        let live = cmd("docker", &["inspect", "-f", "{{.State.Running}} {{json .NetworkSettings.Ports}}", "latrix-registry"])
            .await
            .unwrap_or_default();
        let up = live.starts_with("true");
        let bound: Vec<String> = ips
            .iter()
            .filter(|ip| live.contains(&format!("\"HostIp\":\"{ip}\"")))
            .cloned()
            .collect();
        let stale_mesh = !ips.iter().any(|ip| ip != "127.0.0.1") && live.contains("\"HostIp\":\"10.77.");
        let answers = reqwest::Client::new()
            .get(format!("http://127.0.0.1:{REGISTRY_PORT}/v2/"))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .is_ok();
        if up && bound.len() == ips.len() && !stale_mesh && answers {
            continue;
        }
        let _ = cmd("docker", &["rm", "-f", "latrix-registry"]).await;
        let dir = agent.data.join("registry");
        let _ = std::fs::create_dir_all(&dir);
        let vol = format!("{}:/var/lib/registry", dir.display());
        let mut args: Vec<String> = ["run", "-d", "--name", "latrix-registry", "--restart", "always"].iter().map(|s| s.to_string()).collect();
        for ip in &ips {
            args.push("-p".into());
            args.push(format!("{ip}:{REGISTRY_PORT}:5000"));
        }
        args.extend(["-v".to_string(), vol, "-e".into(), "REGISTRY_STORAGE_DELETE_ENABLED=true".into(), "registry:2".into()]);
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
    let mut last_full = Instant::now() - Duration::from_secs(7200);
    let mut known: HashSet<String> = agent.snapshot().apps.keys().cloned().collect();
    loop {
        // Hourly, and soon after an app is destroyed (its images go right away).
        let apps: HashSet<String> = agent.snapshot().apps.keys().cloned().collect();
        let removed = known.iter().any(|a| !apps.contains(a));
        known = apps;
        if removed || last_full.elapsed() > Duration::from_secs(3600) {
            last_full = Instant::now();
            if let Err(e) = gc_once(&agent).await {
                warn!("cache cleanup: {e:#}");
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
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
    let out = cmd("docker", &["images", "--format", "{{.Repository}}:{{.Tag}}"]).await?;
    let marker = format!(":{REGISTRY_PORT}/");
    for img in out.lines() {
        if !img.contains(&marker) {
            continue;
        }
        let Some((_, repo)) = split_registry(img) else { continue };
        let Some((name, tag)) = repo.rsplit_once(':') else { continue };
        let wanted = keep.contains(img) || keep_tags.get(name).map(|t| t.contains(tag)).unwrap_or(false);
        if !wanted {
            debug!("removing old image {img}");
            let _ = cmd("docker", &["rmi", img]).await;
        }
    }
    let _ = cmd("docker", &["image", "prune", "-f"]).await;
    prune_build_cache(agent).await;

    // Registry: delete old tags, then garbage-collect blobs (only when idle).
    if agent.rt.builds_running.load(std::sync::atomic::Ordering::SeqCst) == 0 {
        let base = format!("http://{}", agent.registry());
        let client = &agent.http;
        let catalog: serde_json::Value = client
            .get(format!("{base}/v2/_catalog"))
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .json()
            .await?;
        let mut deleted = 0;
        for repo in catalog["repositories"].as_array().cloned().unwrap_or_default() {
            let Some(repo) = repo.as_str() else { continue };
            let tags: serde_json::Value = client
                .get(format!("{base}/v2/{repo}/tags/list"))
                .send()
                .await?
                .json()
                .await?;
            for tag in tags["tags"].as_array().cloned().unwrap_or_default() {
                let Some(tag) = tag.as_str() else { continue };
                if keep_tags.get(repo).map(|t| t.contains(tag)).unwrap_or(false) {
                    continue;
                }
                let head = client
                    .head(format!("{base}/v2/{repo}/manifests/{tag}"))
                    .header(
                        "Accept",
                        "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json",
                    )
                    .send()
                    .await?;
                if let Some(d) = head.headers().get("Docker-Content-Digest").and_then(|d| d.to_str().ok()) {
                    let _ = client.delete(format!("{base}/v2/{repo}/manifests/{d}")).send().await;
                    deleted += 1;
                }
            }
        }
        if deleted > 0 {
            let _ = cmd(
                "docker",
                &["exec", "latrix-registry", "registry", "garbage-collect", "--delete-untagged", "/etc/docker/registry/config.yml"],
            )
            .await;
            info!("registry cleanup: removed {deleted} old image tag(s)");
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
    let filter = format!("label=latrix.instance={}", q.instance);
    let id = match cmd("docker", &["ps", "-aq", "--filter", &filter]).await {
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
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(256);
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let tx2 = tx.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if tx.send(l + "\n").await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let mut lines = BufReader::new(err).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if tx2.send(l + "\n").await.is_err() {
                break;
            }
        }
    });
    let stream = futures::stream::unfold((rx, child), |(mut rx, child)| async move {
        rx.recv()
            .await
            .map(|l| (Ok::<_, std::io::Error>(bytes::Bytes::from(l)), (rx, child)))
    });
    Body::from_stream(stream).into_response()
}
