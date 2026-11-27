//! The latrix agent. One runs on every machine (as a systemd service).
//!
//! All agents are equal; the one with the lowest machine id that is alive acts
//! as the leader. The leader runs the scheduler, owns writes to the cluster
//! state and replicates it to everyone else. If it dies the next machine takes
//! over within seconds, with a full copy of the state.

pub mod acme;
pub mod alerts;
pub mod autopilot;
pub mod api;
pub mod builder;
pub mod cloudflare;
pub mod dns;
pub mod keys;
pub mod maintenance;
pub mod mesh;
pub mod metrics;
pub mod proxy;
pub mod rexctl;
pub mod runtime;
pub mod scheduler;
pub mod selfupdate;
pub mod store;
pub mod transfer;
pub mod volumes;

use crate::state::*;
use crate::util::{self, now};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Identity of this machine, written at join time to `<data>/node.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub machine_id: u32,
    pub overlay_ip: String,
    pub token: String,
    pub cluster: String,
}

pub struct Agent {
    pub me: NodeIdentity,
    pub data: PathBuf,
    pub dev: bool,
    pub started: Instant,
    pub state: RwLock<Arc<ClusterState>>,
    pub max_seen_version: AtomicU64,
    /// Last successful ping per machine.
    pub alive: Mutex<HashMap<u32, Instant>>,
    pub dead_since: Mutex<HashMap<u32, u64>>,
    /// Reports received (leader only).
    pub reports: Mutex<HashMap<u32, (Instant, NodeReport)>>,
    pub routes: RwLock<Arc<Routes>>,
    pub events: Mutex<VecDeque<Event>>,
    pub sched_mem: Mutex<scheduler::SchedMemory>,
    /// (leader id, since) as seen by this machine.
    pub leader_view: Mutex<Option<(u32, Instant)>>,
    pub changed: tokio::sync::watch::Sender<u64>,
    pub write_lock: tokio::sync::Mutex<()>,
    pub http: reqwest::Client,
    pub rt: runtime::Runtime,
    pub vols: volumes::VolumeState,
    pub updates: Mutex<UpdateInfo>,
    pub maintenance_done: Mutex<Option<String>>,
    pub sampler: metrics::Sampler,
    pub autopilot: autopilot::Shared,
    pub cloudflare: cloudflare::Shared,
    pub rexctl: rexctl::Shared,
    pub mesh_up: std::sync::atomic::AtomicBool,
    pub outbox: Mutex<Vec<Event>>,
    pub alert_queue: Mutex<Vec<String>>,
    pub upgrade_now: tokio::sync::Notify,
    pub acme_wake: tokio::sync::Notify,
    /// Domains waiting for a certificate: domain -> (reason, next attempt).
    pub acme_pending: Mutex<std::collections::BTreeMap<String, (String, u64)>>,
}

impl Agent {
    /// IP that containers' ports, the registry and the API bind to.
    /// The mesh IP, or 127.0.0.1 in dev mode or while the mesh address is
    /// missing (so a single machine keeps working; `latrix doctor` reports it).
    pub fn bind_ip(&self) -> String {
        if self.dev || !self.mesh_up.load(std::sync::atomic::Ordering::Relaxed) {
            "127.0.0.1".into()
        } else {
            self.me.overlay_ip.clone()
        }
    }
    /// Is the mesh address actually present on this machine?
    pub fn check_mesh(&self) -> bool {
        let up = std::net::TcpListener::bind((self.me.overlay_ip.as_str(), 0)).is_ok();
        self.mesh_up.store(up, std::sync::atomic::Ordering::Relaxed);
        up
    }
    pub fn registry(&self) -> String {
        format!("{}:{}", self.bind_ip(), util::REGISTRY_PORT)
    }
    pub fn snapshot(&self) -> Arc<ClusterState> {
        self.state.read().unwrap().clone()
    }
    pub fn event(&self, level: &str, msg: impl Into<String>) {
        let msg = msg.into();
        match level {
            "warn" => warn!("{msg}"),
            _ => info!("{msg}"),
        }
        let e = Event {
            ts: now(),
            level: level.into(),
            message: msg,
        };
        // Followers forward their events to the leader with the next report.
        if !self.is_leader() {
            let mut out = self.outbox.lock().unwrap();
            out.push(e.clone());
            if out.len() > 50 {
                out.remove(0);
            }
        }
        if e.level == "warn" && self.is_leader() {
            alerts::queue(self, &e.message);
        }
        let mut ev = self.events.lock().unwrap();
        ev.push_back(e);
        while ev.len() > 200 {
            ev.pop_front();
        }
    }
    pub fn ip_of(&self, machine: u32) -> Option<String> {
        if self.dev {
            return Some("127.0.0.1".into());
        }
        self.snapshot().machines.get(&machine).map(|m| m.overlay_ip.clone())
    }
}

pub fn default_data_dir(dev: bool) -> PathBuf {
    if dev {
        dirs::data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("latrix")
            .join("dev")
    } else {
        PathBuf::from("/var/lib/latrix")
    }
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Creates the identity + initial state of the first machine in a cluster.
#[allow(clippy::too_many_arguments)]
pub fn init_first(
    data: &Path,
    cluster: &str,
    token: &str,
    name: &str,
    public_ip: &str,
    wg_pubkey: &str,
    facts: &metrics::Facts,
    extra: (Option<String>, Option<ProviderRef>, Option<f64>),
    dev: bool,
) -> Result<()> {
    std::fs::create_dir_all(data)?;
    // Re-running `machine add` on the first machine must not wipe the cluster.
    if let Ok(existing) = load_json::<NodeIdentity>(&data.join("node.json")) {
        if existing.token == token {
            return Ok(());
        }
        anyhow::bail!(
            "this machine already belongs to cluster '{}'. To reset it, remove {} first",
            existing.cluster,
            data.display()
        );
    }
    let overlay_ip = if dev { "127.0.0.1".to_string() } else { mesh::overlay_ip(1) };
    let id = NodeIdentity {
        machine_id: 1,
        overlay_ip: overlay_ip.clone(),
        token: token.into(),
        cluster: cluster.into(),
    };
    let mut state = ClusterState {
        version: 1,
        cluster: cluster.into(),
        next_machine_id: 1,
        ..Default::default()
    };
    state.machines.insert(
        1,
        Machine {
            id: 1,
            name: name.into(),
            public_ip: public_ip.into(),
            overlay_ip,
            wg_pubkey: wg_pubkey.into(),
            os: facts.os.clone(),
            arch: facts.arch.clone(),
            cpus: facts.cpus,
            memory_mb: facts.memory_mb,
            region: extra.0,
            provider: extra.1,
            monthly_cost: extra.2,
            status: MachineStatus::Ready,
            joined_at: now(),
            maintenance: None,
            last_maintenance: now(),
            temporary: false,
        },
    );
    if dev {
        // Nothing to update on a laptop.
        state.settings.auto_updates = false;
    }
    util::write_atomic(&data.join("node.json"), &serde_json::to_vec_pretty(&id)?)?;
    util::write_atomic(&data.join("state.json"), &serde_json::to_vec_pretty(&state)?)?;
    set_private(&data.join("node.json"));
    Ok(())
}

/// Writes identity + state received from the leader when joining.
pub fn write_join(data: &Path, id: &NodeIdentity, state: &ClusterState) -> Result<()> {
    std::fs::create_dir_all(data)?;
    util::write_atomic(&data.join("node.json"), &serde_json::to_vec_pretty(id)?)?;
    util::write_atomic(&data.join("state.json"), &serde_json::to_vec_pretty(state)?)?;
    set_private(&data.join("node.json"));
    set_private(&data.join("state.json"));
    Ok(())
}

pub fn set_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

pub async fn run(data: PathBuf, dev: bool) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    std::fs::create_dir_all(&data)?;

    if dev && !data.join("node.json").exists() {
        let facts = metrics::local_facts().await;
        init_first(
            &data,
            "local",
            &util::random_token(),
            "local",
            "127.0.0.1",
            "",
            &facts,
            (None, None, None),
            true,
        )?;
    }
    let me: NodeIdentity = load_json(&data.join("node.json")).context(
        "this machine has not joined a cluster yet (run `latrix machine add` from your computer)",
    )?;
    let state: ClusterState = load_json(&data.join("state.json")).unwrap_or_default();
    info!(
        "latrix agent {} starting: machine #{} ({}) in cluster '{}', state v{}",
        util::VERSION,
        me.machine_id,
        me.overlay_ip,
        me.cluster,
        state.version
    );

    let (tx, _rx) = tokio::sync::watch::channel(state.version);
    let agent = Arc::new(Agent {
        me,
        data: data.clone(),
        dev,
        started: Instant::now(),
        max_seen_version: AtomicU64::new(state.version),
        state: RwLock::new(Arc::new(state)),
        alive: Mutex::new(HashMap::new()),
        dead_since: Mutex::new(HashMap::new()),
        reports: Mutex::new(HashMap::new()),
        routes: RwLock::new(Arc::new(Routes::default())),
        events: Mutex::new(VecDeque::new()),
        sched_mem: Mutex::new(Default::default()),
        leader_view: Mutex::new(None),
        changed: tx,
        write_lock: tokio::sync::Mutex::new(()),
        http: reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()?,
        rt: Default::default(),
        vols: Default::default(),
        updates: Mutex::new(UpdateInfo::default()),
        maintenance_done: Mutex::new(maintenance::read_done_marker(&data)),
        sampler: Default::default(),
        autopilot: Default::default(),
        cloudflare: Default::default(),
        rexctl: Default::default(),
        mesh_up: std::sync::atomic::AtomicBool::new(false),
        outbox: Mutex::new(vec![]),
        acme_pending: Mutex::new(Default::default()),
        alert_queue: Mutex::new(vec![]),
        upgrade_now: tokio::sync::Notify::new(),
        acme_wake: tokio::sync::Notify::new(),
    });

    if !dev {
        if let Err(e) = mesh::sync(&agent).await {
            warn!("mesh setup failed (will retry): {e:#}");
        }
        if !agent.check_mesh() {
            warn!("mesh address {} is missing; serving this machine's apps on 127.0.0.1 until it is back", agent.me.overlay_ip);
        }
    }

    // API: always on localhost, and on the overlay IP for other machines.
    spawn_api(agent.clone(), "127.0.0.1".into());
    if !dev {
        spawn_api(agent.clone(), agent.me.overlay_ip.clone());
    }

    tokio::spawn(metrics::run(agent.clone()));
    tokio::spawn(store::ping_loop(agent.clone()));
    tokio::spawn(store::report_loop(agent.clone()));
    tokio::spawn(store::leader_loop(agent.clone()));
    tokio::spawn(store::routes_loop(agent.clone()));
    tokio::spawn(runtime::reconcile_loop(agent.clone()));
    tokio::spawn(runtime::stats_loop(agent.clone()));
    tokio::spawn(runtime::registry_loop(agent.clone()));
    tokio::spawn(runtime::gc_loop(agent.clone()));
    tokio::spawn(proxy::run(agent.clone()));
    tokio::spawn(volumes::run(agent.clone()));
    tokio::spawn(acme::run(agent.clone()));
    tokio::spawn(alerts::run(agent.clone()));
    tokio::spawn(selfupdate::run(agent.clone()));
    tokio::spawn(rexctl::run(agent.clone()));
    tokio::spawn(keys::run(agent.clone()));
    if !dev {
        tokio::spawn(mesh::sync_loop(agent.clone()));
        tokio::spawn(dns::run(agent.clone()));
        tokio::spawn(cloudflare::run(agent.clone()));
        tokio::spawn(maintenance::run(agent.clone()));
        tokio::spawn(autopilot::run(agent.clone()));
    }

    shutdown_signal().await;
    info!("shutting down (containers keep running)");
    Ok(())
}

fn spawn_api(agent: Arc<Agent>, ip: String) {
    tokio::spawn(async move {
        let addr: SocketAddr = format!("{ip}:{}", util::API_PORT).parse().unwrap();
        loop {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    info!("API listening on {addr}");
                    let app = api::router(agent.clone());
                    if let Err(e) = axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .await
                    {
                        warn!("API server on {addr} stopped: {e}");
                    }
                }
                Err(e) => {
                    warn!("cannot bind API on {addr}: {e} (retrying)");
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Run a command and return stdout, failing with stderr on a non-zero exit.
pub async fn cmd(program: &str, args: &[&str]) -> Result<String> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .with_context(|| format!("running {program}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub async fn sh(script: &str) -> Result<String> {
    cmd("sh", &["-c", script]).await
}
