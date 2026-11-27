//! HTTP API served by every agent.
//!
//! * `/v1/local/*` — machine-local endpoints (ping, state replication, builds, logs)
//! * `/v1/m/{id}/*` — forwarded to machine `id`'s `/v1/local/*`
//! * `/v1/*` — cluster API; transparently forwarded to the leader
//! * `/` — the web dashboard
//!
//! The API only listens on 127.0.0.1 and the WireGuard overlay IP. Requests
//! from localhost (including SSH tunnels from the CLI) are trusted; anything
//! else must carry the cluster token.

use super::scheduler::{self, LiveView};
use super::store::{Ping, ReportAck};
use super::{builder, mesh, runtime, Agent, NodeIdentity};
use crate::api_types::*;
use crate::state::*;
use crate::util::{self, now, random_id, validate_name, API_PORT, VIP_PREFIX};
use anyhow::{anyhow, bail};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

type AgentState = State<Arc<Agent>>;

pub struct ApiError(pub StatusCode, pub String);

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ApiErrorBody { error: self.1 })).into_response()
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

pub fn router(agent: Arc<Agent>) -> Router {
    let local = Router::new()
        .route("/v1/local/ping", get(ping))
        .route("/v1/local/state", get(get_state).post(post_state))
        .route("/v1/local/report", post(report))
        .route("/v1/local/routes", get(routes))
        .route("/v1/local/build", post(builder::handle_build))
        .route("/v1/local/logs", get(runtime::handle_logs))
        .route("/v1/local/volume-data", get(super::transfer::get_volume).post(super::transfer::put_volume))
        .route("/v1/local/unused-volumes", get(super::volumes::handle_unused).delete(super::volumes::handle_unused))
        .route("/v1/local/image", get(super::transfer::get_image).post(super::transfer::put_image));

    let cluster = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/events", get(events))
        .route("/v1/machines/join", post(join))
        .route("/v1/machines/{name}", delete(remove_machine))
        .route("/v1/machines/{name}/action", post(machine_action))
        .route("/v1/apps/{app}", get(get_app).delete(destroy_app))
        .route("/v1/apps/{app}/build-plan", post(build_plan))
        .route("/v1/apps/{app}/deploy", post(deploy))
        .route("/v1/apps/{app}/scale", post(scale))
        .route("/v1/apps/{app}/restart", post(restart))
        .route("/v1/apps/{app}/rollback", post(rollback))
        .route("/v1/apps/{app}/secrets", post(secrets))
        .route("/v1/apps/{app}/export", get(export_app))
        .route("/v1/settings", get(get_settings).post(set_settings))
        .route("/v1/autopilot", get(get_autopilot).post(set_autopilot))
        .route("/v1/machines/provision", post(provision_machine))
        .route_layer(middleware::from_fn_with_state(agent.clone(), leader_forward));

    Router::new()
        .route("/", get(dashboard))
        .route("/v1/m/{id}/{*rest}", any(machine_forward))
        .merge(local)
        .merge(cluster)
        .layer(middleware::from_fn_with_state(agent.clone(), auth))
        .layer(axum::extract::DefaultBodyLimit::disable())
        .with_state(agent)
}

async fn auth(State(agent): AgentState, req: Request, next: Next) -> Response {
    let local = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().is_loopback())
        .unwrap_or(false);
    let token_ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v) == agent.me.token)
        .unwrap_or(false);
    if local || token_ok {
        next.run(req).await
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "missing or invalid cluster token".into()).into_response()
    }
}

/// Cluster API requests are served by the leader.
async fn leader_forward(State(agent): AgentState, req: Request, next: Next) -> Response {
    if agent.is_leader() {
        return next.run(req).await;
    }
    let Some(ip) = agent.leader_ip() else {
        return ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "no leader elected yet (machines still connecting) — try again in a few seconds".into(),
        )
        .into_response();
    };
    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();
    forward(&agent, &ip, &pq, req).await
}

async fn machine_forward(
    State(agent): AgentState,
    Path((id, rest)): Path<(u32, String)>,
    req: Request,
) -> Response {
    let Some(ip) = agent.ip_of(id) else {
        return ApiError(StatusCode::NOT_FOUND, format!("unknown machine #{id}")).into_response();
    };
    let q = req.uri().query().map(|q| format!("?{q}")).unwrap_or_default();
    let path = format!("/v1/local/{rest}{q}");
    let ip = if id == agent.me.machine_id { "127.0.0.1".to_string() } else { ip };
    forward(&agent, &ip, &path, req).await
}

/// Stream a request to another agent and stream the response back.
pub async fn forward(agent: &Agent, ip: &str, path_q: &str, req: Request) -> Response {
    let url = format!("http://{ip}:{API_PORT}{path_q}");
    let (parts, body) = req.into_parts();
    let mut rb = agent
        .http
        .request(parts.method, &url)
        .bearer_auth(&agent.me.token);
    for (k, v) in parts.headers.iter() {
        if k == header::HOST
            || k == header::AUTHORIZATION
            || k == header::CONTENT_LENGTH
            || k == header::CONNECTION
            || k == header::TRANSFER_ENCODING
        {
            continue;
        }
        rb = rb.header(k, v);
    }
    rb = rb.body(reqwest::Body::wrap_stream(body.into_data_stream()));
    match rb.send().await {
        Ok(resp) => {
            let mut b = Response::builder().status(resp.status());
            for (k, v) in resp.headers() {
                if k == header::TRANSFER_ENCODING || k == header::CONNECTION || k == header::CONTENT_LENGTH {
                    continue;
                }
                b = b.header(k, v);
            }
            b.body(Body::from_stream(resp.bytes_stream()))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => ApiError(StatusCode::BAD_GATEWAY, format!("could not reach {ip}: {e}")).into_response(),
    }
}

async fn dashboard() -> impl IntoResponse {
    let mut r = Html(include_str!("../dashboard.html")).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    r
}

// ---------------------------------------------------------------------------
// local endpoints

async fn ping(State(agent): AgentState) -> Json<Ping> {
    Json(Ping {
        machine: agent.me.machine_id,
        version: agent.snapshot().version,
        leader: agent.leader(),
        agent_version: util::VERSION.into(),
    })
}

async fn get_state(State(agent): AgentState) -> Json<ClusterState> {
    Json((*agent.snapshot()).clone())
}

async fn post_state(State(agent): AgentState, Json(s): Json<ClusterState>) -> Json<bool> {
    Json(agent.accept_state(s))
}

async fn report(State(agent): AgentState, Json(mut r): Json<NodeReport>) -> Json<ReportAck> {
    if !r.events.is_empty() {
        let name = agent.snapshot().machines.get(&r.machine).map(|m| m.name.clone()).unwrap_or_default();
        let mut ev = agent.events.lock().unwrap();
        for mut e in std::mem::take(&mut r.events) {
            e.message = format!("{name}: {}", e.message);
            ev.push_back(e);
        }
        while ev.len() > 200 {
            ev.pop_front();
        }
    }
    agent
        .reports
        .lock()
        .unwrap()
        .insert(r.machine, (Instant::now(), r));
    Json(ReportAck {
        version: agent.snapshot().version,
    })
}

async fn routes(State(agent): AgentState) -> Json<Routes> {
    Json((**agent.routes.read().unwrap()).clone())
}

// ---------------------------------------------------------------------------
// status

fn machine_name(s: &ClusterState, id: u32) -> String {
    s.machines.get(&id).map(|m| m.name.clone()).unwrap_or_else(|| format!("#{id}"))
}

fn app_view(agent: &Agent, s: &ClusterState, live: &LiveView, app: &App) -> AppView {
    let cfg = app.config().cloned();
    let rel = app.current_release();
    let (min, max) = cfg.as_ref().map(|c| c.scale.bounds()).unwrap_or((0, 0));
    let mut urls = vec![];
    let mut internal = vec![];
    if let Some(c) = &cfg {
        if let Some(h) = &c.http {
            for d in &h.domains {
                let scheme = if s.certs.contains_key(d) { "https" } else { "http" };
                urls.push(format!("{scheme}://{d}"));
            }
            if !s.settings.base_domain.is_empty() {
                let d = format!("{}.{}", app.name, s.settings.base_domain);
                let scheme = if s.certs.contains_key(&d) { "https" } else { "http" };
                urls.push(format!("{scheme}://{d}"));
            }
            if agent.dev {
                urls.push(format!("http://{}.localhost:{}", app.name, util::DEV_HTTP_PORT));
            } else if let Some(m) = s
                .machines
                .values()
                .find(|m| m.public_ip.parse::<std::net::Ipv4Addr>().is_ok())
            {
                urls.push(format!("http://{}.{}.sslip.io", app.name, m.public_ip.replace('.', "-")));
            }
        }
        let ports = c.container_ports();
        let mut names = vec![format!("{}.internal", app.name)];
        if let Some(g) = &c.group {
            names.push(format!("{}.{}.internal", c.service_name(), g));
        }
        for n in names {
            if ports.is_empty() {
                internal.push(n);
            } else {
                for p in &ports {
                    internal.push(format!("{n}:{p}"));
                }
            }
        }
        for p in c.ports.iter().filter(|p| p.public) {
            internal.push(format!("<any machine ip>:{}  (public tcp)", p.public_port.unwrap_or(p.port)));
        }
    }
    let instances = s
        .instances_of(&app.name)
        .map(|i| InstanceView {
            instance: i.clone(),
            machine_name: machine_name(s, i.machine),
            report: live.inst(i).cloned(),
        })
        .collect();
    let volumes = s
        .volumes_of(&app.name)
        .map(|v| VolumeView {
            volume: v.clone(),
            primary_name: machine_name(s, v.primary),
            replica_names: v.replicas.iter().map(|r| machine_name(s, *r)).collect(),
            report: live
                .reports
                .get(&v.primary)
                .and_then(|r| r.volumes.iter().find(|x| x.id == v.id).cloned()),
        })
        .collect();
    let mut releases: Vec<ReleaseView> = app
        .releases
        .iter()
        .rev()
        .map(|r| ReleaseView {
            version: r.version,
            image: r.image.clone(),
            status: r.status.clone(),
            created_at: r.created_at,
            description: r.description.clone(),
        })
        .collect();
    releases.truncate(10);
    AppView {
        name: app.name.clone(),
        group: cfg.as_ref().and_then(|c| c.group.clone()),
        current: app.current,
        release_status: rel.map(|r| r.status.clone()),
        image: rel.map(|r| r.image.clone()).unwrap_or_default(),
        count: app.count,
        min,
        max,
        autoscale: cfg.as_ref().map(|c| c.scale.autoscale()).unwrap_or(false),
        stateful: cfg.as_ref().map(|c| c.stateful()).unwrap_or(false),
        cpu: cfg.as_ref().map(|c| c.scale.cpu).unwrap_or(0.0),
        memory: cfg.as_ref().map(|c| c.scale.memory.clone()).unwrap_or_default(),
        urls,
        internal,
        instances,
        releases,
        volumes,
        secret_names: app.secrets.keys().cloned().collect(),
        config: cfg,
    }
}

async fn status(State(agent): AgentState) -> ApiResult<StatusView> {
    let s = agent.snapshot();
    let live = agent.live();
    let view = live.view();
    let leader = agent.leader();
    let machines = s
        .machines
        .values()
        .map(|m| {
            let r = live.reports.get(&m.id);
            MachineView {
                machine: m.clone(),
                alive: live.alive.contains(&m.id),
                leader: leader == Some(m.id),
                metrics: r.map(|r| r.metrics.clone()),
                updates: r.map(|r| r.updates.clone()),
                instances: s.instances_on(m.id).filter(|i| !i.stopping).count(),
                reserved_mb: s.reserved_mb(m.id),
                reserved_cpu: s.reserved_cpu(m.id),
                agent_version: r.map(|r| r.agent_version.clone()).unwrap_or_default(),
                build_cache_gb: r.map(|r| r.build_cache_gb).unwrap_or(0.0),
            }
        })
        .collect();
    let apps = s.apps.values().map(|a| app_view(&agent, &s, &view, a)).collect();
    let certs = s
        .certs
        .values()
        .map(|c| CertView {
            domain: c.domain.clone(),
            not_after: c.not_after,
            issued_at: c.issued_at,
            unused_since: c.unused_since,
        })
        .collect();
    let certs_pending = agent
        .acme_pending
        .lock()
        .unwrap()
        .iter()
        .map(|(d, (reason, retry_at))| PendingCert { domain: d.clone(), reason: reason.clone(), retry_at: *retry_at })
        .collect();
    let mut events: Vec<Event> = agent.events.lock().unwrap().iter().cloned().collect();
    events.reverse();
    events.truncate(50);
    let monthly_cost = s.machines.values().filter_map(|m| m.monthly_cost).sum::<f64>() + 0.0;
    Ok(Json(StatusView {
        cluster: s.cluster.clone(),
        version: s.version,
        leader,
        dev: agent.dev,
        settings: s.settings.clone(),
        machines,
        apps,
        certs,
        events,
        monthly_cost,
        autopilot: Some(agent.autopilot.status.lock().unwrap().clone()),
        certs_pending,
    }))
}

async fn events(State(agent): AgentState) -> Json<Vec<Event>> {
    Json(agent.events.lock().unwrap().iter().cloned().collect())
}

async fn get_app(State(agent): AgentState, Path(app): Path<String>) -> ApiResult<AppView> {
    let s = agent.snapshot();
    let live = agent.live();
    let a = s
        .apps
        .get(&app)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("app '{app}' not found")))?;
    Ok(Json(app_view(&agent, &s, &live.view(), a)))
}

// ---------------------------------------------------------------------------
// machines

async fn join(State(agent): AgentState, Json(req): Json<JoinRequest>) -> ApiResult<JoinResponse> {
    validate_name("machine", &req.name)?;
    if agent.dev {
        return Err(anyhow!("the local dev cluster cannot have more machines").into());
    }
    let machine = agent.mutate(|s| register_machine(s, &req)).await?;
    agent.event("info", format!("machine {} joined the cluster", machine.name));
    let state = (*agent.snapshot()).clone();
    Ok(Json(JoinResponse {
        identity: NodeIdentity {
            machine_id: machine.id,
            overlay_ip: machine.overlay_ip.clone(),
            token: agent.me.token.clone(),
            cluster: state.cluster.clone(),
        },
        machine,
        state,
    }))
}

/// Add a machine to the cluster state (idempotent for the same name + key).
pub fn register_machine(s: &mut ClusterState, req: &JoinRequest) -> anyhow::Result<Machine> {
    if let Some(existing) = s.machines.values().find(|m| m.name == req.name) {
        if existing.wg_pubkey == req.wg_pubkey {
            return Ok(existing.clone()); // re-running `machine add` is fine
        }
        bail!("a machine named '{}' already exists", req.name);
    }
    if let Some(existing) = s.machines.values().find(|m| m.public_ip == req.public_ip) {
        bail!(
            "{} is already in the cluster as '{}'",
            req.public_ip,
            existing.name
        );
    }
    let id = s.next_machine_id.max(s.machines.keys().copied().max().unwrap_or(0)) + 1;
    s.next_machine_id = id;
    let m = Machine {
        id,
        name: req.name.clone(),
        public_ip: req.public_ip.clone(),
        overlay_ip: mesh::overlay_ip(id),
        wg_pubkey: req.wg_pubkey.clone(),
        os: req.os.clone(),
        arch: req.arch.clone(),
        cpus: req.cpus,
        memory_mb: req.memory_mb,
        region: req.region.clone(),
        provider: req.provider.clone(),
        monthly_cost: req.monthly_cost,
        status: MachineStatus::Ready,
        joined_at: now(),
        maintenance: None,
        last_maintenance: now(),
        temporary: false,
    };
    s.machines.insert(id, m.clone());
    Ok(m)
}

async fn machine_action(
    State(agent): AgentState,
    Path(name): Path<String>,
    Json(req): Json<MachineAction>,
) -> ApiResult<Machine> {
    let live = agent.live();
    let m = agent
        .mutate(|s| {
            // Updating a machine nothing else can stand in for: with the
            // autopilot on, buy a temporary server first (no downtime).
            if req.action == "update" {
                if let Some(id) = s.machine_by_name(&name).map(|m| m.id) {
                    if s.surge.is_none()
                        && scheduler::surge_possible(s)
                        && !scheduler::can_absorb(s, &live.view(), id)
                        && s.machines[&id].status == MachineStatus::Ready
                    {
                        s.surge = Some(Surge { for_machine: id, requested_at: now(), temp_machine: None, phase: "buying".into() });
                        return Ok(s.machines[&id].clone());
                    }
                }
            }
            let id = s
                .machine_by_name(&name)
                .map(|m| m.id)
                .ok_or_else(|| anyhow!("machine '{name}' not found"))?;
            let m = s.machines.get_mut(&id).unwrap();
            match req.action.as_str() {
                "drain" | "update" => {
                    if matches!(m.status, MachineStatus::Draining | MachineStatus::Maintenance) {
                        bail!("{} is already {}", m.name, m.status);
                    }
                    m.status = MachineStatus::Draining;
                    m.maintenance = Some(MaintenanceTask {
                        id: random_id(8),
                        kind: if req.action == "update" { "updates".into() } else { "drain".into() },
                        started_at: now(),
                    });
                }
                "cordon" => {
                    m.status = MachineStatus::Cordoned;
                }
                "uncordon" => {
                    m.status = MachineStatus::Ready;
                    m.maintenance = None;
                }
                other => bail!("unknown action '{other}' (drain, cordon, uncordon, update)"),
            }
            Ok(m.clone())
        })
        .await?;
    agent.event("info", format!("{}: {} requested", m.name, req.action));
    Ok(Json(m))
}

#[derive(Deserialize)]
struct ForceQuery {
    #[serde(default)]
    force: bool,
    #[serde(default)]
    purge_volumes: bool,
}

async fn remove_machine(
    State(agent): AgentState,
    Path(name): Path<String>,
    Query(q): Query<ForceQuery>,
) -> ApiResult<Machine> {
    let m = agent
        .mutate(|s| {
            let m = s
                .machine_by_name(&name)
                .cloned()
                .ok_or_else(|| anyhow!("machine '{name}' not found"))?;
            if s.machines.len() == 1 {
                bail!("cannot remove the last machine of the cluster");
            }
            let busy = s.instances_on(m.id).filter(|i| !i.stopping).count();
            if busy > 0 && !q.force {
                bail!(
                    "{} still runs {busy} instance(s); drain it first (`latrix machine drain {}`) or pass --force",
                    m.name,
                    m.name
                );
            }
            let ids: Vec<String> = s.instances_on(m.id).map(|i| i.id.clone()).collect();
            for id in ids {
                s.instances.remove(&id);
            }
            for v in s.volumes.values_mut() {
                v.replicas.retain(|r| *r != m.id);
            }
            s.machines.remove(&m.id);
            Ok(m)
        })
        .await?;
    agent.event("info", format!("machine {} removed from the cluster", m.name));
    Ok(Json(m))
}

// ---------------------------------------------------------------------------
// apps

async fn build_plan(State(agent): AgentState, Path(app): Path<String>) -> ApiResult<BuildPlan> {
    validate_name("app", &app)?;
    let s = agent.snapshot();
    let live = agent.live();
    let ok = |m: &Machine| {
        live.alive.contains(&m.id)
            && matches!(m.status, MachineStatus::Ready | MachineStatus::Cordoned)
    };
    let free_disk = |id: u32| {
        live.reports
            .get(&id)
            .map(|r| r.metrics.disk_total_gb - r.metrics.disk_used_gb)
            .unwrap_or(10.0)
    };
    let a = s.apps.get(&app);
    // Cache affinity: build where we built last time, so layers are warm.
    let preferred = a
        .and_then(|a| a.last_builder)
        .and_then(|id| s.machines.get(&id))
        .filter(|m| ok(m) && free_disk(m.id) > 5.0)
        .map(|m| m.id);
    let machine = preferred
        .or_else(|| {
            s.machines
                .values()
                .filter(|m| ok(m))
                .max_by(|x, y| {
                    let score = |m: &Machine| {
                        let r = live.reports.get(&m.id);
                        let cpu = r.map(|r| r.metrics.cpu_pct).unwrap_or(50.0);
                        let cpus = r.map(|r| r.metrics.cpus).unwrap_or(m.cpus);
                        free_disk(m.id).min(50.0) / 50.0 + (1.0 - cpu / 100.0) + cpus / 8.0
                            - s.reserved_mb(m.id) as f64 / (m.memory_mb.max(1024) as f64)
                    };
                    score(x).partial_cmp(&score(y)).unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|m| m.id)
        })
        .ok_or_else(|| anyhow!("no machine is available to build on"))?;
    let mut cache_from = vec![];
    if let Some(rel) = a.and_then(|a| a.current_release()) {
        if !rel.sources.is_empty() {
            cache_from.push(rel.image.clone());
        }
    }
    Ok(Json(BuildPlan {
        machine,
        machine_name: machine_name(&s, machine),
        tag: format!("{}-{}", now(), random_id(4)),
        cache_from,
    }))
}

fn alloc_vip(s: &mut ClusterState) -> String {
    let used: std::collections::HashSet<String> = s.apps.values().map(|a| a.vip.clone()).collect();
    loop {
        s.next_vip += 1;
        let n = s.next_vip;
        let vip = format!("{VIP_PREFIX}.{}.{}", (n / 254) % 255, n % 254 + 1);
        if !used.contains(&vip) {
            return vip;
        }
    }
}

fn new_release(app: &mut App, image: String, config: crate::config::AppConfig, sources: Vec<u32>, description: String) -> u64 {
    let version = app.next_version();
    app.releases.push(Release {
        version,
        image,
        config,
        created_at: now(),
        status: ReleaseStatus::Deploying,
        sources,
        description,
    });
    app.current = version;
    // Keep the last 10 releases (always keeping the current one).
    while app.releases.len() > 10 {
        let idx = app.releases.iter().position(|r| r.version != version).unwrap();
        app.releases.remove(idx);
    }
    version
}

async fn deploy(
    State(agent): AgentState,
    Path(app): Path<String>,
    Json(req): Json<DeployRequest>,
) -> ApiResult<DeployResponse> {
    let cfg = req.config.clone();
    cfg.validate()?;
    if cfg.app != app {
        return Err(anyhow!("config is for app '{}', not '{app}'", cfg.app).into());
    }
    if req.image.trim().is_empty() {
        return Err(anyhow!("no image to deploy").into());
    }
    let live = agent.live();
    let dev = agent.dev;
    let version = agent
        .mutate(|s| {
            // Public port conflicts.
            for p in cfg.ports.iter().filter(|p| p.public) {
                let pp = p.public_port.unwrap_or(p.port);
                if [80u16, 443, API_PORT, util::REGISTRY_PORT, util::RSYNC_PORT, 22].contains(&pp) {
                    bail!("public port {pp} is reserved");
                }
                for other in s.apps.values().filter(|a| a.name != app) {
                    if let Some(oc) = other.config() {
                        if oc.ports.iter().any(|o| o.public && o.public_port.unwrap_or(o.port) == pp) {
                            bail!("public port {pp} is already used by app '{}'", other.name);
                        }
                    }
                }
            }
            if dev && cfg.ports.iter().any(|p| p.public) {
                // fine on the local cluster too
            }
            let is_new = !s.apps.contains_key(&app);
            if is_new {
                let vip = alloc_vip(s);
                s.apps.insert(
                    app.clone(),
                    App {
                        name: app.clone(),
                        vip,
                        current: 0,
                        releases: vec![],
                        secrets: BTreeMap::new(),
                        count: cfg.scale.initial(),
                        created_at: now(),
                        last_builder: None,
                    },
                );
            }
            let sources = req.builder.map(|b| vec![b]).unwrap_or_default();
            let a = s.apps.get_mut(&app).unwrap();
            if !is_new {
                let (min, max) = cfg.scale.bounds();
                a.count = if cfg.scale.autoscale() {
                    a.count.clamp(min, max)
                } else {
                    cfg.scale.initial()
                };
            }
            if req.builder.is_some() {
                a.last_builder = req.builder;
            }
            let desc = if req.description.is_empty() { "deploy".to_string() } else { req.description.clone() };
            let version = new_release(a, req.image.clone(), cfg.clone(), sources, desc);

            // Volumes: create the ones that are new; all of an app's volumes share a primary.
            let existing_primary = s.volumes_of(&app).next().map(|v| v.primary);
            let primary = match existing_primary {
                Some(p) => Some(p),
                None if !cfg.volumes.is_empty() => {
                    let view = live.view();
                    scheduler::place(s, &view, &app, &cfg, &[])
                        .or_else(|| s.machines.keys().next().copied())
                }
                None => None,
            };
            for vc in &cfg.volumes {
                let id = Volume::dir_name(&app, &vc.name);
                // A pending purge from an earlier destroy must not hit the new app's data.
                s.tombstones.remove(&id);
                let sync_secs = util::parse_duration(&vc.sync).map(|d| d.as_secs()).unwrap_or(30).max(5);
                match s.volumes.get_mut(&id) {
                    Some(v) => {
                        v.copies = vc.copies;
                        v.sync_secs = sync_secs;
                        v.path = vc.path.clone();
                    }
                    None => {
                        s.volumes.insert(
                            id.clone(),
                            Volume {
                                id,
                                app: app.clone(),
                                name: vc.name.clone(),
                                path: vc.path.clone(),
                                primary: primary.unwrap(),
                                replicas: vec![],
                                copies: vc.copies,
                                sync_secs,
                                created_at: now(),
                                moving_to: None,
                                moving_since: 0,
                                moving_version: 0,
                            },
                        );
                    }
                }
            }
            let names: Vec<String> = cfg.volumes.iter().map(|v| v.name.clone()).collect();
            s.volumes.retain(|_, v| v.app != app || names.contains(&v.name));
            Ok(version)
        })
        .await?;
    agent.event("info", format!("{app}: deploying release v{version} ({})", req.image));
    Ok(Json(DeployResponse { version }))
}

async fn destroy_app(
    State(agent): AgentState,
    Path(app): Path<String>,
    Query(q): Query<ForceQuery>,
) -> ApiResult<bool> {
    agent
        .mutate(|s| {
            if s.apps.remove(&app).is_none() {
                bail!("app '{app}' not found");
            }
            for i in s.instances.values_mut().filter(|i| i.app == app) {
                i.stopping = true;
                i.stopping_since = now();
            }
            let vols: Vec<String> = s.volumes_of(&app).map(|v| v.id.clone()).collect();
            for v in vols {
                s.volumes.remove(&v);
                if q.purge_volumes {
                    s.tombstones.insert(v, now());
                } else {
                    s.tombstones.remove(&v);
                }
            }
            s.tombstones.retain(|_, t| now().saturating_sub(*t) < 7 * 86400);
            Ok(())
        })
        .await?;
    agent.event("info", format!("{app}: destroyed"));
    Ok(Json(true))
}

async fn scale(
    State(agent): AgentState,
    Path(app): Path<String>,
    Json(req): Json<ScaleRequest>,
) -> ApiResult<AppView> {
    agent
        .mutate(|s| {
            let a = s.apps.get_mut(&app).ok_or_else(|| anyhow!("app '{app}' not found"))?;
            let rel = a.current_release().ok_or_else(|| anyhow!("app has no release"))?;
            let mut cfg = rel.config.clone();
            let image = rel.image.clone();
            let sources = rel.sources.clone();
            if let Some(c) = req.count {
                cfg.scale.count = Some(c);
                if req.min.is_none() && req.max.is_none() {
                    cfg.scale.min = None;
                    cfg.scale.max = None;
                }
            }
            if req.min.is_some() {
                cfg.scale.min = req.min;
            }
            if req.max.is_some() {
                cfg.scale.max = req.max;
            }
            let resources_changed = req.cpu.is_some() || req.memory.is_some();
            if let Some(c) = req.cpu {
                cfg.scale.cpu = c;
            }
            if let Some(m) = &req.memory {
                cfg.scale.memory = m.clone();
            }
            if cfg.stateful() && cfg.scale.bounds().1 > 1 {
                bail!("apps with volumes run a single instance (count 0 or 1)");
            }
            cfg.validate()?;
            let (min, max) = cfg.scale.bounds();
            a.count = match req.count {
                Some(c) => c.clamp(min, max),
                None => a.count.clamp(min, max),
            };
            if resources_changed {
                new_release(a, image, cfg, sources, "scale (resources)".into());
            } else {
                let cur = a.current;
                if let Some(r) = a.releases.iter_mut().find(|r| r.version == cur) {
                    r.config = cfg;
                }
            }
            Ok(())
        })
        .await?;
    agent.event("info", format!("{app}: scaled"));
    get_app(State(agent), Path(app)).await
}

async fn restart(State(agent): AgentState, Path(app): Path<String>) -> ApiResult<DeployResponse> {
    let version = agent
        .mutate(|s| {
            let a = s.apps.get_mut(&app).ok_or_else(|| anyhow!("app '{app}' not found"))?;
            let rel = a.current_release().cloned().ok_or_else(|| anyhow!("app has no release"))?;
            Ok(new_release(a, rel.image, rel.config, rel.sources, "restart".into()))
        })
        .await?;
    agent.event("info", format!("{app}: rolling restart (v{version})"));
    Ok(Json(DeployResponse { version }))
}

async fn rollback(
    State(agent): AgentState,
    Path(app): Path<String>,
    Json(req): Json<RollbackRequest>,
) -> ApiResult<DeployResponse> {
    let version = agent
        .mutate(|s| {
            let a = s.apps.get_mut(&app).ok_or_else(|| anyhow!("app '{app}' not found"))?;
            let target = match req.version {
                Some(v) => a.release(v).cloned().ok_or_else(|| anyhow!("release v{v} not found"))?,
                None => a
                    .releases
                    .iter()
                    .filter(|r| r.version < a.current && r.status != ReleaseStatus::Failed)
                    .max_by_key(|r| r.version)
                    .cloned()
                    .ok_or_else(|| anyhow!("no earlier release to roll back to"))?,
            };
            Ok(new_release(
                a,
                target.image,
                target.config,
                target.sources,
                format!("rollback to v{}", target.version),
            ))
        })
        .await?;
    agent.event("info", format!("{app}: rolling back (v{version})"));
    Ok(Json(DeployResponse { version }))
}

async fn secrets(
    State(agent): AgentState,
    Path(app): Path<String>,
    Json(req): Json<SecretsRequest>,
) -> ApiResult<DeployResponse> {
    let version = agent
        .mutate(|s| {
            let a = s.apps.get_mut(&app).ok_or_else(|| anyhow!("app '{app}' not found"))?;
            for (k, v) in &req.set {
                if k.is_empty() || k.contains('=') {
                    bail!("invalid secret name '{k}'");
                }
                a.secrets.insert(k.clone(), v.clone());
            }
            for k in &req.unset {
                a.secrets.remove(k);
            }
            let rel = a.current_release().cloned().ok_or_else(|| anyhow!("app has no release"))?;
            Ok(new_release(a, rel.image, rel.config, rel.sources, "secrets changed".into()))
        })
        .await?;
    agent.event("info", format!("{app}: secrets updated, restarting (v{version})"));
    Ok(Json(DeployResponse { version }))
}

// ---------------------------------------------------------------------------
// settings

async fn get_settings(State(agent): AgentState) -> Json<Settings> {
    Json(agent.snapshot().settings.clone())
}

async fn set_settings(
    State(agent): AgentState,
    Json(req): Json<BTreeMap<String, String>>,
) -> ApiResult<Settings> {
    let settings = agent
        .mutate(|s| {
            let mut v = serde_json::to_value(&s.settings)?;
            let obj = v.as_object_mut().unwrap();
            for (k, val) in &req {
                let cur = obj
                    .get(k)
                    .ok_or_else(|| anyhow!("unknown setting '{k}' (known: {})", obj.keys().cloned().collect::<Vec<_>>().join(", ")))?;
                let new = match cur {
                    serde_json::Value::Bool(_) => serde_json::Value::Bool(match val.as_str() {
                        "true" | "yes" | "on" | "1" => true,
                        "false" | "no" | "off" | "0" => false,
                        _ => bail!("{k} must be true or false"),
                    }),
                    serde_json::Value::Number(_) => serde_json::json!(val
                        .parse::<f64>()
                        .map_err(|_| anyhow!("{k} must be a number"))?),
                    _ => serde_json::Value::String(val.clone()),
                };
                obj.insert(k.clone(), new);
            }
            let new: Settings = serde_json::from_value(v)?;
            if !new.update_window.is_empty() && !new.update_window.contains('-') {
                bail!("update_window looks like \"02:00-05:00\" (UTC), or empty for any time");
            }
            s.settings = new.clone();
            Ok(new)
        })
        .await?;
    Ok(Json(settings))
}

// ---------------------------------------------------------------------------
// autopilot

fn autopilot_view(agent: &Agent) -> AutopilotView {
    let s = agent.snapshot();
    AutopilotView {
        enabled: s.settings.autopilot,
        budget: s.settings.monthly_budget,
        min_machines: s.settings.min_machines,
        max_machines: s.settings.max_machines,
        status: agent.autopilot.status.lock().unwrap().clone(),
    }
}

async fn get_autopilot(State(agent): AgentState) -> ApiResult<AutopilotView> {
    let mut v = autopilot_view(&agent);
    if v.status.leader_ssh_key.is_empty() {
        if let Ok((_, public)) = super::autopilot::leader_key(&agent).await {
            v.status.leader_ssh_key = public;
        }
    }
    Ok(Json(v))
}

async fn set_autopilot(State(agent): AgentState, Json(req): Json<AutopilotRequest>) -> ApiResult<AutopilotView> {
    if agent.dev && req.enabled == Some(true) {
        return Err(anyhow!("the local dev cluster can't buy servers").into());
    }
    for p in req.tokens.keys() {
        crate::cli::providers::canonical(p)?;
    }
    agent
        .mutate(|s| {
            for (p, t) in &req.tokens {
                let p = crate::cli::providers::canonical(p)?.to_string();
                s.provider_tokens.insert(p, t.clone());
            }
            for k in &req.ssh_keys {
                if !s.ssh_keys.contains(k) {
                    s.ssh_keys.push(k.clone());
                }
            }
            if let Some(b) = req.budget {
                s.settings.monthly_budget = b.max(0.0);
            }
            if let Some(m) = req.min_machines {
                s.settings.min_machines = m.max(1);
            }
            if let Some(m) = req.max_machines {
                s.settings.max_machines = m.max(1);
            }
            if s.settings.min_machines > s.settings.max_machines {
                bail!("min_machines can't be larger than max_machines");
            }
            if let Some(e) = req.enabled {
                if e && s.provider_tokens.is_empty() {
                    bail!("the autopilot needs a provider token (hetzner or digitalocean)");
                }
                s.settings.autopilot = e;
            }
            Ok(())
        })
        .await?;
    let v = autopilot_view(&agent);
    agent.event(
        "info",
        if v.enabled {
            format!("autopilot on (budget {})", if v.budget > 0.0 { format!("{:.2}/month", v.budget) } else { "unlimited".into() })
        } else {
            "autopilot off".into()
        },
    );
    Ok(Json(v))
}

async fn provision_machine(State(agent): AgentState, Json(req): Json<ProvisionRequest>) -> ApiResult<Machine> {
    validate_name("machine", &req.name)?;
    let (key, _) = super::autopilot::leader_key(&agent).await?;
    let ssh = super::autopilot::leader_ssh(&agent, &req.ssh, req.port.unwrap_or(22), &key);
    let ip = match &req.public_ip {
        Some(ip) => ip.clone(),
        None => ssh.host().to_string(),
    };
    let m = super::autopilot::provision(&agent, &ssh, &req.name, &ip, None, None, None).await?;
    agent.autopilot.status.lock().unwrap().working_on = None;
    agent.event("info", format!("machine {} joined the cluster (set up by the leader)", m.name));
    Ok(Json(m))
}

/// The app's config, image, secrets (values) and volumes, for backups.
async fn export_app(State(agent): AgentState, Path(app): Path<String>) -> ApiResult<AppExport> {
    let s = agent.snapshot();
    let a = s
        .apps
        .get(&app)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, format!("app '{app}' not found")))?;
    let rel = a.current_release().ok_or_else(|| anyhow!("app has no release"))?;
    Ok(Json(AppExport {
        config: rel.config.clone(),
        image: rel.image.clone(),
        sources: rel.sources.clone(),
        secrets: a.secrets.clone(),
        count: a.count,
        volumes: s.volumes_of(&app).cloned().collect(),
    }))
}
