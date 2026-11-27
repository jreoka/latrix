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
    let streaming = Router::new()
        .route("/v1/local/build", post(builder::handle_build))
        .route("/v1/local/volume-data", get(super::transfer::get_volume).post(super::transfer::put_volume))
        .route("/v1/local/image", get(super::transfer::get_image).post(super::transfer::put_image))
        .route("/v1/local/exec", post(super::transfer::exec_container))
        .route("/v1/m/{id}/{*rest}", any(machine_forward))
        .layer(axum::extract::DefaultBodyLimit::disable());

    let state_sync = Router::new()
        .route("/v1/local/state", get(get_state).post(post_state))
        .layer(axum::extract::DefaultBodyLimit::max(32 * 1024 * 1024));

    let local = Router::new()
        .route("/v1/local/ping", get(ping))
        .route("/v1/local/report", post(report))
        .route("/v1/local/routes", get(routes))
        .route("/v1/local/logs", get(runtime::handle_logs))
        .route("/v1/local/unused-volumes", get(super::volumes::handle_unused).delete(super::volumes::handle_unused))
        .route("/v1/local/snapshots", get(super::volumes::handle_snapshots).post(super::volumes::handle_snapshots))
        .route("/v1/local/self-update", post(super::selfupdate::handle));

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
        .route("/v1/apps/{app}/dns", post(set_app_dns))
        .route("/v1/apps/{app}/export", get(export_app))
        .route("/v1/dns", get(get_dns))
        .route("/v1/dns/cloudflare", post(setup_cloudflare))
        .route("/v1/dns/sync", post(sync_dns))
        .route("/v1/rexctl", get(get_rexctl).post(set_rexctl).delete(delete_rexctl))
        .route("/v1/rexctl/export", get(export_rexctl))
        .route("/v1/rexctl/upgrade", post(upgrade_rexctl))
        .route("/v1/rexctl/auto-upgrade", post(set_rexctl_auto_upgrade))
        .route("/v1/rexctl/config", post(update_rexctl_config))
        .route("/v1/settings", get(get_settings).post(set_settings))
        .route("/v1/autopilot", get(get_autopilot).post(set_autopilot))
        .route("/v1/providers/{provider}", delete(remove_provider))
        .route("/v1/ssh-keys", get(get_ssh_keys).post(set_ssh_keys))
        .route("/v1/upgrade-now", post(super::selfupdate::handle_now))
        .route("/v1/machines/provision", post(provision_machine))
        .route_layer(middleware::from_fn_with_state(agent.clone(), leader_forward));

    Router::new()
        .route("/", get(dashboard))
        .merge(streaming)
        .merge(state_sync)
        .merge(local)
        .merge(cluster)
        .layer(middleware::from_fn_with_state(agent.clone(), auth))
        .with_state(agent)
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim();
    let h = if let Some(rest) = h.strip_prefix('[') {
        rest.split_once(']').map(|(v, _)| v).unwrap_or(h)
    } else if let Some((name, port)) = h.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            name
        } else {
            h
        }
    } else {
        h
    };
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

fn is_loopback_origin(origin: &str) -> bool {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .unwrap_or("");
    let host = rest.split('/').next().unwrap_or("");
    !host.is_empty() && is_loopback_host(host)
}

async fn auth(State(agent): AgentState, req: Request, next: Next) -> Response {
    let local = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().is_loopback())
        .unwrap_or(false);
    let token_ok = !agent.me.token.is_empty()
        && req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|provided| util::constant_time_eq(provided.as_bytes(), agent.me.token.as_bytes()))
            .unwrap_or(false);
    if token_ok {
        return next.run(req).await;
    }
    // Without the cluster token, only allow read-only dashboard & local health
    // checks from loopback with strict Host/Origin validation (prevents local
    // privilege escalation, DNS rebinding, and cross-site CSRF).
    let path = req.uri().path();
    let readonly_dashboard = req.method() == axum::http::Method::GET
        && matches!(path, "/" | "/v1/status" | "/v1/local/ping");
    let host_ok = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(is_loopback_host)
        .unwrap_or(true);
    let origin_ok = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(is_loopback_origin)
        .unwrap_or(true);
    let fetch_site_ok = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.eq_ignore_ascii_case("cross-site"))
        .unwrap_or(true);
    if local && readonly_dashboard && host_ok && origin_ok && fetch_site_ok {
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
    if rest.is_empty()
        || rest.starts_with('/')
        || rest.contains('\\')
        || rest.contains('?')
        || rest.contains('#')
        || rest.split('/').any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return ApiError(StatusCode::BAD_REQUEST, "invalid forwarded path".into()).into_response();
    }
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
    let hops: u8 = req
        .headers()
        .get("x-latrix-hops")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if hops >= 2 {
        return ApiError(
            StatusCode::LOOP_DETECTED,
            "forwarding loop detected (leader election still converging — retry shortly)".into(),
        )
        .into_response();
    }
    let url = super::host_port_url(ip, API_PORT, path_q);
    let (parts, body) = req.into_parts();
    let mut nominated: std::collections::HashSet<String> = std::collections::HashSet::new();
    for val in parts.headers.get_all(header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for t in s.split(',') {
                let t = t.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    nominated.insert(t);
                }
            }
        }
    }
    let mut rb = agent
        .http
        .request(parts.method, &url)
        .bearer_auth(&agent.me.token)
        .header("x-latrix-hops", (hops + 1).to_string());
    for (k, v) in parts.headers.iter() {
        let name = k.as_str();
        if k == header::HOST
            || k == header::AUTHORIZATION
            || k == header::CONTENT_LENGTH
            || k == header::CONNECTION
            || k == header::TRANSFER_ENCODING
            || k == header::UPGRADE
            || k == header::TE
            || k == header::TRAILER
            || name == "keep-alive"
            || name == "proxy-authenticate"
            || name == "proxy-authorization"
            || name == "x-latrix-hops"
            || nominated.contains(name)
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
                if k == header::TRANSFER_ENCODING
                    || k == header::CONNECTION
                    || k == header::CONTENT_LENGTH
                    || k == header::TE
                    || k == header::TRAILER
                    || k.as_str() == "keep-alive"
                {
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
    Json(agent.accept_state(s).await)
}

async fn report(State(agent): AgentState, Json(mut r): Json<NodeReport>) -> ApiResult<ReportAck> {
    if !agent.is_leader() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "not leader".into(),
        ));
    }
    let snap = agent.snapshot();
    let Some(machine) = snap.machines.get(&r.machine) else {
        return Err(ApiError(
            StatusCode::NOT_FOUND,
            format!("unknown machine #{}", r.machine),
        ));
    };
    if !r.events.is_empty() {
        let name = machine.name.clone();
        let mut ev = agent.events.lock().unwrap();
        for mut e in std::mem::take(&mut r.events) {
            e.message = format!("{name}: {}", e.message);
            if e.level == "warn" {
                super::alerts::queue(&agent, &e.message);
            }
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
    Ok(Json(ReportAck {
        version: snap.version,
    }))
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
        for p in c.ports.iter().filter(|p| p.public && p.protocol == "tcp") {
            internal.push(format!("<any machine ip>:{}  (public tcp)", p.public_port.unwrap_or(p.port)));
        }
        // UDP is served only by the machines running the app, on their own IPs.
        let mut hosts: Vec<&str> = s
            .instances_of(&app.name)
            .filter(|i| !i.stopping)
            .filter_map(|i| s.machines.get(&i.machine).map(|m| m.public_ip.as_str()))
            .collect();
        hosts.sort();
        hosts.dedup();
        for (public, _) in c.udp_ports() {
            for h in &hosts {
                urls.push(format!("udp://{h}:{public}"));
            }
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
        dns_records: app.dns_records.clone(),
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
        dns: Some(super::cloudflare::summary(&agent)),
        fluxer: s.fluxer.as_ref().map(|fx| FluxerSummary {
            project: fx.project.clone(),
            domain: fx.domain.clone(),
            release: fx.release.clone(),
            auto_upgrade: fx.auto_upgrade,
            services: fx.services.clone(),
        }),
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
    validate_name("machine", &req.name)?;
    let public_ip = req.public_ip.trim();
    if public_ip.parse::<std::net::IpAddr>().is_err() {
        bail!("invalid public_ip '{}'", req.public_ip);
    }
    let wg_pubkey = req.wg_pubkey.trim();
    mesh::validate_wg_pubkey(wg_pubkey)?;
    if let Some(existing) = s.machines.values().find(|m| m.name == req.name) {
        if existing.wg_pubkey == wg_pubkey {
            return Ok(existing.clone()); // re-running `machine add` is fine
        }
        bail!("a machine named '{}' already exists", req.name);
    }
    if let Some(existing) = s.machines.values().find(|m| m.public_ip == public_ip) {
        bail!(
            "{public_ip} is already in the cluster as '{}'",
            existing.name
        );
    }
    let used_ips: std::collections::HashSet<&str> =
        s.machines.values().map(|m| m.overlay_ip.as_str()).collect();
    let mut id = s.next_machine_id.max(s.machines.keys().copied().max().unwrap_or(0));
    let (chosen_id, overlay_ip) = (0..(255 * 254))
        .find_map(|_| {
            id = id.wrapping_add(1).max(1);
            let ip = mesh::overlay_ip(id);
            if !s.machines.contains_key(&id) && !used_ips.contains(ip.as_str()) {
                Some((id, ip))
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("no free overlay IPs left in cluster"))?;
    s.next_machine_id = chosen_id;
    let m = Machine {
        id: chosen_id,
        name: req.name.clone(),
        public_ip: public_ip.to_string(),
        overlay_ip,
        wg_pubkey: wg_pubkey.to_string(),
        os: req.os.clone(),
        arch: req.arch.clone(),
        cpus: if req.cpus.is_finite() && req.cpus >= 0.0 { req.cpus } else { 0.0 },
        memory_mb: req.memory_mb,
        region: req.region.clone(),
        provider: req.provider.clone(),
        monthly_cost: req.monthly_cost.filter(|c| c.is_finite() && *c >= 0.0),
        status: MachineStatus::Ready,
        joined_at: now(),
        maintenance: None,
        last_maintenance: now(),
        temporary: false,
    };
    s.machines.insert(chosen_id, m.clone());
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
                    if m.status == MachineStatus::Maintenance {
                        bail!("{} is currently running OS maintenance; wait for it to finish before uncordoning", m.name);
                    }
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
            let primary_vols: Vec<String> = s
                .volumes
                .values()
                .filter(|v| v.primary == m.id || v.moving_to == Some(m.id))
                .map(|v| format!("{}/{}", v.app, v.name))
                .collect();
            if !primary_vols.is_empty() && !q.force {
                bail!(
                    "{} still owns volume(s) ({}); drain it first or pass --force",
                    m.name,
                    primary_vols.join(", ")
                );
            }
            let ids: Vec<String> = s.instances_on(m.id).map(|i| i.id.clone()).collect();
            for id in ids {
                s.instances.remove(&id);
            }
            for v in s.volumes.values_mut() {
                v.replicas.retain(|r| *r != m.id);
                if v.moving_to == Some(m.id) {
                    v.moving_to = None;
                }
            }
            if let Some(sg) = &s.surge {
                if sg.for_machine == m.id || sg.temp_machine == Some(m.id) {
                    s.surge = None;
                }
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

pub fn alloc_vip(s: &mut ClusterState) -> anyhow::Result<String> {
    let used: std::collections::HashSet<String> = s.apps.values().map(|a| a.vip.clone()).collect();
    for _ in 0..(255 * 254) {
        s.next_vip = s.next_vip.wrapping_add(1);
        let n = s.next_vip;
        let vip = format!("{VIP_PREFIX}.{}.{}", (n / 254) % 255, n % 254 + 1);
        if !used.contains(&vip) {
            return Ok(vip);
        }
    }
    bail!("no free internal VIP addresses left in cluster")
}

/// Validate public port, HTTP domain, and group DNS conflicts against other apps.
pub fn check_app_conflicts(
    s: &ClusterState,
    app: &str,
    cfg: &crate::config::AppConfig,
) -> anyhow::Result<()> {
    for p in cfg.ports.iter().filter(|p| p.public) {
        let pp = p.public_port.unwrap_or(p.port);
        let reserved: &[u16] = if p.protocol == "udp" {
            &[53, util::WG_PORT]
        } else {
            &[80, 443, API_PORT, util::REGISTRY_PORT, util::RSYNC_PORT, 22]
        };
        if reserved.contains(&pp) {
            bail!("public {} port {pp} is reserved", p.protocol);
        }
        for other in s.apps.values().filter(|a| a.name != app) {
            if let Some(oc) = other.config() {
                if oc.ports.iter().any(|o| {
                    o.public && o.protocol == p.protocol && o.public_port.unwrap_or(o.port) == pp
                }) {
                    bail!(
                        "public {} port {pp} is already used by app '{}'",
                        p.protocol,
                        other.name
                    );
                }
            }
        }
    }
    if let Some(h) = &cfg.http {
        for d in &h.domains {
            let dn = crate::config::normalize_dns_name(d);
            for other in s.apps.values().filter(|a| a.name != app) {
                if let Some(oh) = other.config().and_then(|c| c.http.as_ref()) {
                    if oh
                        .domains
                        .iter()
                        .any(|od| crate::config::normalize_dns_name(od) == dn)
                    {
                        bail!("domain '{dn}' is already used by app '{}'", other.name);
                    }
                }
            }
        }
    }
    if let Some(group) = &cfg.group {
        let mut names = vec![cfg.service_name().to_string()];
        names.extend(cfg.aliases.iter().cloned());
        for other in s.apps.values().filter(|a| a.name != app) {
            if let Some(oc) = other.config() {
                if oc.group.as_deref() == Some(group.as_str()) {
                    let mut onames = vec![oc.service_name().to_string()];
                    onames.extend(oc.aliases.iter().cloned());
                    for n in &names {
                        if onames.contains(n) {
                            bail!(
                                "internal name '{n}.{group}.internal' is already used by app '{}'",
                                other.name
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Ensure all configured volumes for `app` exist in `s.volumes` and remove deleted ones.
pub fn reconcile_app_volumes(
    s: &mut ClusterState,
    view: &LiveView<'_>,
    app: &str,
    cfg: &crate::config::AppConfig,
) -> anyhow::Result<()> {
    let existing_primary = s.volumes_of(app).next().map(|v| v.primary);
    let primary = match existing_primary {
        Some(p) if s.machines.contains_key(&p) => Some(p),
        _ if !cfg.volumes.is_empty() => scheduler::place(s, view, app, cfg, &[])
            .or_else(|| s.machines.keys().next().copied()),
        _ => None,
    };
    if !cfg.volumes.is_empty() && primary.is_none() {
        bail!("no machine available to place volumes for '{app}'");
    }
    for vc in &cfg.volumes {
        let id = Volume::dir_name(app, &vc.name);
        // A pending purge from an earlier destroy must not hit the new app's data.
        s.tombstones.remove(&id);
        let sync_secs = util::parse_duration(&vc.sync)
            .map(|d| d.as_secs())
            .unwrap_or(30)
            .max(5);
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
                        app: app.to_string(),
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
    Ok(())
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
    let mut cfg = req.config.clone();
    if let Some(h) = &mut cfg.http {
        for d in &mut h.domains {
            *d = crate::config::normalize_dns_name(d);
        }
    }
    cfg.validate()?;
    if cfg.app != app {
        return Err(anyhow!("config is for app '{}', not '{app}'", cfg.app).into());
    }
    util::validate_image_ref(&req.image)?;
    let live = agent.live();
    let version = agent
        .mutate(|s| {
            check_app_conflicts(s, &app, &cfg)?;
            let is_new = !s.apps.contains_key(&app);
            if is_new {
                let vip = alloc_vip(s)?;
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
                        dns_records: vec![],
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

            reconcile_app_volumes(s, &live.view(), &app, &cfg)?;
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
    let live = agent.live();
    let version = agent
        .mutate(|s| {
            let target = {
                let a = s.apps.get(&app).ok_or_else(|| anyhow!("app '{app}' not found"))?;
                match req.version {
                    Some(v) => a.release(v).cloned().ok_or_else(|| anyhow!("release v{v} not found"))?,
                    None => a
                        .releases
                        .iter()
                        .filter(|r| r.version < a.current && r.status != ReleaseStatus::Failed)
                        .max_by_key(|r| r.version)
                        .cloned()
                        .ok_or_else(|| anyhow!("no earlier release to roll back to"))?,
                }
            };
            check_app_conflicts(s, &app, &target.config)?;
            reconcile_app_volumes(s, &live.view(), &app, &target.config)?;
            let a = s.apps.get_mut(&app).unwrap();
            let (min, max) = target.config.scale.bounds();
            a.count = if target.config.stateful() {
                a.count.min(1).clamp(min.min(1), max.min(1))
            } else {
                a.count.clamp(min, max)
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
                if k.is_empty() || k.contains(['=', '\0', '\r', '\n']) {
                    bail!("invalid secret name '{k}'");
                }
                if v.contains('\0') {
                    bail!("secret '{k}' cannot contain NUL bytes");
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
    let dev = agent.dev;
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
                    // Whole numbers stay integers (counts like volume_snapshots).
                    serde_json::Value::Number(n) => match (n.is_f64(), val.parse::<u64>()) {
                        (false, Ok(i)) => serde_json::json!(i),
                        (false, Err(_)) => bail!("{k} must be a whole number"),
                        (true, _) => {
                            let f = val
                                .parse::<f64>()
                                .map_err(|_| anyhow!("{k} must be a number"))?;
                            if !f.is_finite() || f < 0.0 {
                                bail!("{k} must be a finite non-negative number");
                            }
                            serde_json::json!(f)
                        }
                    },
                    _ => serde_json::Value::String(val.clone()),
                };
                obj.insert(k.clone(), new);
            }
            let mut new: Settings = serde_json::from_value(v)?;
            if !new.update_window.is_empty() {
                scheduler::validate_window(&new.update_window)?;
            }
            if !new.base_domain.trim().is_empty() {
                new.base_domain = crate::config::validate_domain(&new.base_domain)?;
            } else {
                new.base_domain.clear();
            }
            if !new.alert_webhook.trim().is_empty() {
                super::alerts::validate_webhook_url(&new.alert_webhook)?;
            }
            if new.volume_retention_days > 36_500.0 {
                bail!("volume_retention_days must be at most 36500");
            }
            if new.min_machines == 0 || new.max_machines == 0 {
                bail!("min_machines and max_machines must be at least 1");
            }
            if new.min_machines > new.max_machines {
                bail!("min_machines can't be larger than max_machines");
            }
            if new.autopilot {
                if dev {
                    bail!("the local dev cluster can't buy servers");
                }
                if s.provider_tokens.is_empty() {
                    bail!("the autopilot needs a provider token (hetzner or digitalocean)");
                }
            }
            if new.cloudflare_ttl != 1 && !(60..=86400).contains(&new.cloudflare_ttl) {
                bail!("cloudflare_ttl must be 1 (auto) or between 60 and 86400 seconds");
            }
            if new.swappiness > 100 {
                bail!("swappiness must be between 0 and 100");
            }
            super::swap::desired_mb(&new.swap, 4096)?;
            s.settings = new.clone();
            Ok(new)
        })
        .await?;
    if req.contains_key("cloudflare_proxied")
        || req.contains_key("cloudflare_ttl")
        || req.contains_key("base_domain")
    {
        agent.cloudflare.wake.notify_one();
    }
    if req.contains_key("alert_webhook") && !settings.alert_webhook.is_empty() {
        let lines = vec!["alerts are connected: you'll hear about machines going down, failed deploys, certificate problems, full disks and crash loops".to_string()];
        if let Err(e) = super::alerts::send(&agent, &settings.alert_webhook, &lines).await {
            return Err(anyhow!("saved, but the test message failed: {e:#}").into());
        }
    }
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
    let validated_keys: Vec<String> = req
        .ssh_keys
        .iter()
        .map(|k| super::keys::validate(k))
        .collect::<anyhow::Result<_>>()?;
    if let Some(b) = req.budget {
        if !b.is_finite() || b < 0.0 {
            return Err(anyhow!("budget must be a finite non-negative number").into());
        }
    }
    agent
        .mutate(|s| {
            for (p, t) in &req.tokens {
                let p = crate::cli::providers::canonical(p)?.to_string();
                s.provider_tokens.insert(p, t.trim().to_string());
            }
            for k in &validated_keys {
                let id = super::keys::key_id(k);
                s.revoked_ssh_keys.retain(|r| super::keys::key_id(r) != id);
                if !s.ssh_keys.iter().any(|x| super::keys::key_id(x) == id) {
                    s.ssh_keys.push(k.clone());
                }
            }
            if let Some(b) = req.budget {
                s.settings.monthly_budget = b;
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
    agent.autopilot.wake.notify_one();
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

/// Drop a provider token from the cluster state (what the autopilot uses to
/// buy, resize and destroy servers). The CLI's own copy is separate.
async fn remove_provider(State(agent): AgentState, Path(provider): Path<String>) -> ApiResult<Vec<String>> {
    let name = crate::cli::providers::canonical(&provider)?.to_string();
    agent
        .mutate(|s| {
            s.provider_tokens.remove(&name);
            Ok(())
        })
        .await?;
    let remaining = agent.snapshot().provider_tokens.keys().cloned().collect::<Vec<_>>();
    agent.event("info", format!("provider token for {name} removed (left: {})", if remaining.is_empty() { "none".into() } else { remaining.join(", ") }));
    Ok(Json(remaining))
}

async fn provision_machine(State(agent): AgentState, Json(req): Json<ProvisionRequest>) -> ApiResult<Machine> {
    validate_name("machine", &req.name)?;
    util::validate_ssh_target(&req.ssh)?;
    let port = req.port.unwrap_or(22);
    if port == 0 {
        return Err(anyhow!("invalid SSH port 0").into());
    }
    let (key, _) = super::autopilot::leader_key(&agent).await?;
    let ssh = super::autopilot::leader_ssh(&agent, &req.ssh, port, &key);
    let ip = match &req.public_ip {
        Some(ip) => {
            let trimmed = ip.trim();
            if trimmed.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("invalid public_ip '{ip}'").into());
            }
            trimmed.to_string()
        }
        None => {
            let h = ssh.host().to_string();
            if h.parse::<std::net::IpAddr>().is_err() {
                return Err(anyhow!("public_ip is required when SSH host '{h}' is not an IP address").into());
            }
            h
        }
    };
    if agent
        .autopilot
        .busy
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "another server provisioning task is already in progress".into(),
        ));
    }
    struct ClearGuard(Arc<Agent>);
    impl Drop for ClearGuard {
        fn drop(&mut self) {
            self.0.autopilot.status.lock().unwrap().working_on = None;
            self.0
                .autopilot
                .busy
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }
    let _guard = ClearGuard(agent.clone());
    let m = super::autopilot::provision(&agent, &ssh, &req.name, &ip, None, None, None).await?;
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
        dns_records: a.dns_records.clone(),
    }))
}

// ---------------------------------------------------------------------------
// Cloudflare DNS

async fn get_dns(State(agent): AgentState) -> ApiResult<DnsStatusView> {
    Ok(Json(super::cloudflare::status_view(&agent)))
}

async fn setup_cloudflare(
    State(agent): AgentState,
    Json(req): Json<CloudflareSetupRequest>,
) -> ApiResult<DnsStatusView> {
    if let Some(ttl) = req.ttl {
        if ttl != 1 && !(60..=86400).contains(&ttl) {
            return Err(anyhow!("ttl must be 1 (auto) or between 60 and 86400 seconds").into());
        }
    }
    if req.remove {
        agent
            .mutate(|s| {
                s.cloudflare_token = None;
                Ok(())
            })
            .await?;
        {
            let mut rt = agent.cloudflare.status.lock().unwrap();
            *rt = Default::default();
        }
        agent.event("info", "cloudflare DNS disabled (existing DNS records in Cloudflare were left as-is)");
        return Ok(Json(super::cloudflare::status_view(&agent)));
    }

    let verified_zones = if let Some(tok) = req.token.as_deref() {
        Some(super::cloudflare::verify_token(&agent.http, tok).await?)
    } else {
        None
    };

    let zone_names: Vec<String> = verified_zones
        .as_ref()
        .map(|zs| zs.iter().map(|z| z.name.clone()).collect())
        .unwrap_or_default();

    agent
        .mutate(|s| {
            if let Some(tok) = &req.token {
                s.cloudflare_token = Some(tok.trim().to_string());
            }
            if let Some(p) = req.proxied {
                s.settings.cloudflare_proxied = p;
            }
            if let Some(t) = req.ttl {
                s.settings.cloudflare_ttl = t;
            }
            Ok(())
        })
        .await?;

    if let Some(zones) = verified_zones {
        {
            let mut rt = agent.cloudflare.status.lock().unwrap();
            rt.zones = zones;
            rt.last_error = None;
            rt.last_fingerprint.clear();
        }
        agent.event(
            "info",
            format!(
                "cloudflare DNS enabled ({} zone(s){})",
                zone_names.len(),
                if zone_names.is_empty() {
                    String::new()
                } else {
                    format!(": {}", zone_names.join(", "))
                }
            ),
        );
    }

    if agent.snapshot().cloudflare_token.is_some() {
        let _ = super::cloudflare::sync_now(&agent).await;
    }
    Ok(Json(super::cloudflare::status_view(&agent)))
}

async fn sync_dns(State(agent): AgentState) -> ApiResult<DnsSyncResult> {
    if agent.snapshot().cloudflare_token.is_none() {
        return Err(anyhow!("Cloudflare DNS is not configured yet (run `latrix dns cloudflare <token>`)").into());
    }
    let res = super::cloudflare::sync_now(&agent).await?;
    Ok(Json(res))
}

fn normalize_dns_record(mut r: crate::config::DnsRecordConfig) -> crate::config::DnsRecordConfig {
    r.name = crate::config::normalize_dns_name(&r.name);
    r.record_type = r
        .record_type
        .map(|t| t.trim().to_ascii_uppercase())
        .filter(|t| !t.is_empty());
    r.content = r.content.map(|c| c.trim().to_string()).filter(|c| !c.is_empty());
    if r.record_type.is_none() {
        if let Some(c) = &r.content {
            if c.parse::<std::net::Ipv4Addr>().is_ok() {
                r.record_type = Some("A".into());
            } else if c.parse::<std::net::Ipv6Addr>().is_ok() {
                r.record_type = Some("AAAA".into());
            }
        }
    }
    r
}

fn same_dns_slot(a: &crate::config::DnsRecordConfig, b: &crate::config::DnsRecordConfig) -> bool {
    if crate::config::normalize_dns_name(&a.name) != crate::config::normalize_dns_name(&b.name) {
        return false;
    }
    let ta = a.record_type.as_deref().map(|s| s.to_ascii_uppercase());
    let tb = b.record_type.as_deref().map(|s| s.to_ascii_uppercase());
    if ta != tb {
        return false;
    }
    // Auto-IP records (no content) and CNAMEs occupy one slot per (name, type).
    if a.content.is_none() && b.content.is_none() {
        return true;
    }
    if ta.as_deref() == Some("CNAME") {
        return true;
    }
    let ty = ta.as_deref().unwrap_or("");
    match (&a.content, &b.content) {
        (Some(ca), Some(cb)) => {
            super::cloudflare::normalize_content(ty, ca)
                == super::cloudflare::normalize_content(ty, cb)
        }
        _ => false,
    }
}

async fn set_app_dns(
    State(agent): AgentState,
    Path(app): Path<String>,
    Json(req): Json<AppDnsRequest>,
) -> ApiResult<DnsStatusView> {
    let mut to_add = vec![];
    for r in req.add {
        crate::config::validate_dns_record(&r)?;
        to_add.push(normalize_dns_record(r));
    }
    let to_remove = req.remove;
    let added_n = to_add.len();
    let removed_n = agent
        .mutate(|s| {
            let a = s
                .apps
                .get_mut(&app)
                .ok_or_else(|| anyhow!("app '{app}' not found"))?;
            for rec in &to_add {
                if let Some(pos) = a.dns_records.iter().position(|x| same_dns_slot(x, rec)) {
                    a.dns_records[pos] = rec.clone();
                } else {
                    a.dns_records.push(rec.clone());
                }
            }
            let mut removed = 0usize;
            for rm in &to_remove {
                let name = crate::config::normalize_dns_name(&rm.name);
                let ty = rm
                    .record_type
                    .as_deref()
                    .map(|t| t.trim().to_ascii_uppercase())
                    .filter(|t| !t.is_empty());
                let content = rm.content.as_deref().map(str::trim).filter(|c| !c.is_empty());
                let before = a.dns_records.len();
                a.dns_records.retain(|r| {
                    let rn = crate::config::normalize_dns_name(&r.name);
                    if rn != name {
                        return true;
                    }
                    if let Some(want_ty) = &ty {
                        let rty = r
                            .record_type
                            .as_deref()
                            .map(|t| t.to_ascii_uppercase())
                            .unwrap_or_else(|| "AUTO".into());
                        if &rty != want_ty && !(rty == "AUTO" && (want_ty == "A" || want_ty == "AAAA")) {
                            return true;
                        }
                    }
                    if let Some(want_c) = content {
                        let rty = r.record_type.as_deref().unwrap_or("");
                        let rc = r.content.as_deref().unwrap_or("");
                        if super::cloudflare::normalize_content(rty, rc)
                            != super::cloudflare::normalize_content(rty, want_c)
                        {
                            return true;
                        }
                    }
                    false
                });
                let diff = before - a.dns_records.len();
                if diff == 0 {
                    let in_cfg = a.config().map(|c| {
                        c.http
                            .iter()
                            .flat_map(|h| h.domains.iter())
                            .any(|d| crate::config::normalize_dns_name(d) == name)
                            || c.dns
                                .iter()
                                .any(|d| crate::config::normalize_dns_name(&d.name) == name)
                    }).unwrap_or(false);
                    if in_cfg {
                        bail!("'{name}' is defined in {app}'s latrix.toml — remove it there and redeploy");
                    }
                    bail!("no CLI-managed DNS record matching '{name}' on app '{app}'");
                }
                removed += diff;
            }
            Ok(removed)
        })
        .await?;

    if added_n > 0 || removed_n > 0 {
        agent.event(
            "info",
            format!("{app}: updated DNS records (+{added_n}/-{removed_n})"),
        );
        if agent.snapshot().cloudflare_token.is_some() {
            let _ = super::cloudflare::sync_now(&agent).await;
        }
    }
    Ok(Json(super::cloudflare::status_view(&agent)))
}

// ---------------------------------------------------------------------------
// ssh keys

async fn get_ssh_keys(State(agent): AgentState) -> ApiResult<SshKeysView> {
    let (_, cluster_key) = super::autopilot::leader_key(&agent).await?;
    Ok(Json(SshKeysView { keys: agent.snapshot().ssh_keys.clone(), cluster_key }))
}

async fn set_ssh_keys(State(agent): AgentState, Json(req): Json<SshKeysRequest>) -> ApiResult<SshKeysView> {
    use super::keys::{key_id, validate};
    let (_, cluster_key) = super::autopilot::leader_key(&agent).await?;
    let add: Vec<String> = req.add.iter().map(|k| validate(k)).collect::<anyhow::Result<_>>()?;
    let mut remove = Vec::with_capacity(req.remove.len());
    for k in &req.remove {
        match key_id(k) {
            Some(id) => remove.push(id),
            None => return Err(anyhow!("invalid SSH key to remove: '{k}'").into()),
        }
    }
    if remove.iter().any(|r| key_id(&cluster_key).as_ref() == Some(r)) {
        return Err(anyhow!("that is the cluster's own key; it can't be removed").into());
    }
    let keys = agent
        .mutate(move |s| {
            for k in &add {
                let id = key_id(k);
                s.revoked_ssh_keys.retain(|r| key_id(r) != id);
                if !s.ssh_keys.iter().any(|x| key_id(x) == id) {
                    s.ssh_keys.push(k.clone());
                }
            }
            for id in &remove {
                s.ssh_keys.retain(|x| key_id(x).as_ref() != Some(id));
                if !s.revoked_ssh_keys.iter().any(|r| key_id(r).as_ref() == Some(id)) {
                    s.revoked_ssh_keys.push(id.clone());
                }
            }
            Ok(s.ssh_keys.clone())
        })
        .await?;
    Ok(Json(SshKeysView { keys, cluster_key }))
}

// ---------------------------------------------------------------------------
// Fluxer (`latrix rexctl`)

async fn get_rexctl(State(agent): AgentState) -> Json<RexctlStatusView> {
    Json(super::rexctl::status_view(&agent))
}

async fn set_rexctl(State(agent): AgentState, Json(mut stack): Json<FluxerStack>) -> ApiResult<RexctlStatusView> {
    validate_name("project", &stack.project)?;
    stack.domain = crate::config::validate_domain(&stack.domain)?;
    stack.updated_at = now();
    if stack.created_at == 0 {
        stack.created_at = stack.updated_at;
    }
    let domain = stack.domain.clone();
    let release = stack.release.clone();
    let auto = stack.auto_upgrade;
    agent
        .mutate(|s| {
            s.fluxer = Some(stack);
            Ok(())
        })
        .await?;
    agent.event(
        "info",
        format!(
            "Fluxer stack registered for {domain} ({}, auto-upgrade {})",
            if release.is_empty() { "unversioned" } else { &release },
            if auto { "on" } else { "off" }
        ),
    );
    agent.rexctl.wake.notify_one();
    Ok(Json(super::rexctl::status_view(&agent)))
}

async fn delete_rexctl(State(agent): AgentState) -> ApiResult<bool> {
    agent
        .mutate(|s| {
            s.fluxer = None;
            Ok(())
        })
        .await?;
    agent.event("info", "Fluxer stack unregistered");
    Ok(Json(true))
}

async fn export_rexctl(State(agent): AgentState) -> ApiResult<FluxerStack> {
    let fx = agent
        .snapshot()
        .fluxer
        .clone()
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no Fluxer stack is managed on this cluster".into()))?;
    Ok(Json(fx))
}

async fn upgrade_rexctl(
    State(agent): AgentState,
    Json(req): Json<RexctlUpgradeRequest>,
) -> ApiResult<RexctlUpgradeResult> {
    let res = super::rexctl::upgrade_stack(&agent, req.version.as_deref(), req.force).await?;
    Ok(Json(res))
}

async fn set_rexctl_auto_upgrade(
    State(agent): AgentState,
    Json(req): Json<RexctlAutoUpgradeRequest>,
) -> ApiResult<RexctlStatusView> {
    agent
        .mutate(|s| {
            let fx = s
                .fluxer
                .as_mut()
                .ok_or_else(|| anyhow!("no Fluxer stack is managed on this cluster"))?;
            if let Some(en) = req.enabled {
                fx.auto_upgrade = en;
            }
            if let Some(h) = req.interval_hours {
                if h == 0 || h > 168 {
                    bail!("upgrade interval must be between 1 and 168 hours");
                }
                fx.upgrade_interval_hours = h;
            }
            fx.updated_at = now();
            Ok(())
        })
        .await?;
    if req.check_now {
        agent
            .rexctl
            .force_check
            .store(true, std::sync::atomic::Ordering::SeqCst);
        agent.rexctl.wake.notify_one();
    }
    Ok(Json(super::rexctl::status_view(&agent)))
}

async fn update_rexctl_config(
    State(agent): AgentState,
    Json(req): Json<RexctlConfigRequest>,
) -> ApiResult<RexctlStatusView> {
    let v = super::rexctl::apply_config(&agent, req).await?;
    Ok(Json(v))
}
