//! Leader-side auto-management and automatic upgrades for Fluxer stacks
//! deployed with `latrix rexctl`.
//!
//! When a Fluxer stack is registered in `ClusterState.fluxer` with
//! `auto_upgrade = true`, the cluster leader periodically checks
//! `https://fluxer.dev/rexctl/release.json`. When a newer release is available:
//!
//! 1. Verifies the upgrade path (`min_from`) and that the current stack is healthy.
//! 2. Takes safety snapshots of every stateful Fluxer volume.
//! 3. Fetches the release's `fluxer-compose-<version>.tar.gz` pinned image set
//!    and Caddyfile.
//! 4. Rolls out changed services in dependency tier order (never automatically
//!    bumping Postgres across major versions).
//! 5. Rolls back all updated services automatically if any service fails health
//!    checks, and raises an alert event.

use super::Agent;
use crate::api_types::*;
use crate::fluxer::{self, ServiceSpec};
use crate::state::*;
use crate::util::{self, now, API_PORT, VIP_PREFIX};
use anyhow::{anyhow, bail, Result};
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Default)]
pub struct Shared {
    pub upgrade_lock: tokio::sync::Mutex<()>,
    pub wake: tokio::sync::Notify,
    pub upgrading: Mutex<Option<String>>,
}

/// Build the public status view for `GET /v1/rexctl`.
pub fn status_view(agent: &Agent) -> RexctlStatusView {
    let s = agent.snapshot();
    let Some(fx) = &s.fluxer else {
        return RexctlStatusView {
            installed: false,
            ..Default::default()
        };
    };
    let live = agent.live();
    let mut services = vec![];
    let mut voice_endpoints = vec![];

    let svc_list: Vec<String> = if !fx.services.is_empty() {
        fx.services.clone()
    } else {
        s.apps
            .values()
            .filter_map(|a| {
                let cfg = a.config()?;
                if cfg.group.as_deref() == Some(fx.project.as_str()) {
                    Some(cfg.service_name().to_string())
                } else {
                    None
                }
            })
            .collect()
    };

    for svc in svc_list {
        let app_name = format!("{}-{svc}", fx.project);
        let Some(app) = s.apps.get(&app_name) else {
            services.push(RexctlServiceStatus {
                service: svc,
                app: app_name,
                status: "missing".into(),
                ..Default::default()
            });
            continue;
        };
        let rel = app.current_release();
        let image = rel.map(|r| r.image.clone()).unwrap_or_default();
        let mem = rel.map(|r| r.config.scale.memory.clone()).unwrap_or_default();
        let insts: Vec<&Instance> = s.instances_of(&app_name).filter(|i| !i.stopping).collect();
        let mut healthy = 0usize;
        let mut machines = vec![];
        for i in &insts {
            if let Some(m) = s.machines.get(&i.machine) {
                if !machines.contains(&m.name) {
                    machines.push(m.name.clone());
                }
                if svc == "livekit" {
                    if let Some(cfg) = rel.map(|r| &r.config) {
                        for p in cfg.ports.iter().filter(|p| p.public) {
                            let port = p.public_port.unwrap_or(p.port);
                            let ep = format!("{}://{}:{}", p.protocol, m.public_ip, port);
                            if !voice_endpoints.contains(&ep) {
                                voice_endpoints.push(ep);
                            }
                        }
                    }
                }
            }
            if live.view().healthy(i) {
                healthy += 1;
            }
        }
        let status = match rel.map(|r| &r.status) {
            Some(ReleaseStatus::Deploying) => "deploying".into(),
            Some(ReleaseStatus::Failed) => "failed".into(),
            _ if app.count == 0 => "stopped".into(),
            _ if healthy >= app.count as usize => "healthy".into(),
            _ => "degraded".into(),
        };
        services.push(RexctlServiceStatus {
            service: svc,
            app: app_name,
            image,
            status,
            healthy,
            desired: app.count,
            machines,
            memory: mem,
            release: app.current,
        });
    }

    let cert_ready = s.certs.contains_key(&fx.domain);
    let masked: BTreeMap<String, String> = fx
        .settings
        .iter()
        .map(|(k, v)| (k.clone(), fluxer::mask_value(k, v)))
        .collect();

    RexctlStatusView {
        installed: true,
        project: fx.project.clone(),
        domain: fx.domain.clone(),
        release: fx.release.clone(),
        previous_release: fx.previous_release.clone(),
        latest_available: fx.latest_available.clone(),
        auto_upgrade: fx.auto_upgrade,
        upgrade_interval_hours: fx.upgrade_interval_hours,
        upgrading: agent.rexctl.upgrading.lock().unwrap().clone(),
        last_check: fx.last_check,
        last_upgrade: fx.last_upgrade,
        last_error: fx.last_error.clone(),
        storage: fluxer::storage_summary(fx),
        bundled_voice: fx.bundled_voice,
        voice_endpoints,
        kv_mode: if fx.kv_postgres { "postgres".into() } else { "valkey".into() },
        rust_mode: if fx.rust_single { "single (fluxer-server)".into() } else { "per-service".into() },
        cert_ready,
        services,
        settings: masked,
    }
}

/// Snapshot all stateful volumes belonging to the Fluxer stack before upgrading.
async fn snapshot_fluxer_volumes(agent: &Arc<Agent>, project: &str) {
    let s = agent.snapshot();
    let prefix = format!("{project}-");
    let vols: Vec<Volume> = s
        .volumes
        .values()
        .filter(|v| v.app.starts_with(&prefix))
        .cloned()
        .collect();
    for v in vols {
        let Some(ip) = agent.ip_of(v.primary) else { continue };
        let host = if v.primary == agent.me.machine_id { "127.0.0.1" } else { ip.as_str() };
        let url = format!("http://{host}:{API_PORT}/v1/local/snapshots?volume={}&action=create", v.id);
        match agent
            .http
            .post(&url)
            .bearer_auth(&agent.me.token)
            .timeout(Duration::from_secs(60))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                info!("rexctl: pre-upgrade snapshot taken for {}", v.id);
            }
            Ok(r) => warn!("rexctl: snapshot {} returned {}", v.id, r.status()),
            Err(e) => warn!("rexctl: snapshot {} failed: {e}", v.id),
        }
    }
}

fn alloc_vip(s: &mut ClusterState) -> String {
    let used: HashSet<String> = s.apps.values().map(|a| a.vip.clone()).collect();
    loop {
        s.next_vip += 1;
        let n = s.next_vip;
        let vip = format!("{VIP_PREFIX}.{}.{}", (n / 254) % 255, n % 254 + 1);
        if !used.contains(&vip) {
            return vip;
        }
    }
}

/// Deploy (or update) one Fluxer service directly from the leader.
/// Returns `Some((app_name, prev_version, new_version))` if a new release was created.
async fn deploy_spec_on_leader(
    agent: &Arc<Agent>,
    spec: &ServiceSpec,
    description: &str,
) -> Result<Option<(String, u64, u64)>> {
    let live = agent.live();
    let app_name = spec.config.app.clone();
    agent
        .mutate(|s| {
            let is_new = !s.apps.contains_key(&app_name);
            if !is_new {
                let existing = &s.apps[&app_name];
                if let Some(rel) = existing.current_release() {
                    if rel.image == spec.image
                        && rel.config == spec.config
                        && existing.secrets == spec.secrets
                    {
                        return Ok(None);
                    }
                }
            }
            if is_new {
                let vip = alloc_vip(s);
                s.apps.insert(
                    app_name.clone(),
                    App {
                        name: app_name.clone(),
                        vip,
                        current: 0,
                        releases: vec![],
                        secrets: BTreeMap::new(),
                        count: spec.config.scale.initial(),
                        created_at: now(),
                        last_builder: None,
                        dns_records: vec![],
                    },
                );
            }
            let a = s.apps.get_mut(&app_name).unwrap();
            let prev = a.current;
            a.secrets = spec.secrets.clone();
            if !is_new {
                let (min, max) = spec.config.scale.bounds();
                a.count = if spec.config.scale.autoscale() {
                    a.count.clamp(min, max)
                } else {
                    spec.config.scale.initial()
                };
            }
            let version = a.next_version();
            a.releases.push(Release {
                version,
                image: spec.image.clone(),
                config: spec.config.clone(),
                created_at: now(),
                status: ReleaseStatus::Deploying,
                sources: vec![],
                description: description.to_string(),
            });
            a.current = version;
            while a.releases.len() > 10 {
                let idx = a.releases.iter().position(|r| r.version != version).unwrap();
                a.releases.remove(idx);
            }

            // Ensure volumes exist if a new stateful service is added.
            let existing_primary = s.volumes_of(&app_name).next().map(|v| v.primary);
            let primary = existing_primary.or_else(|| {
                if !spec.config.volumes.is_empty() {
                    let view = live.view();
                    super::scheduler::place(s, &view, &app_name, &spec.config, &[])
                        .or_else(|| s.machines.keys().next().copied())
                } else {
                    None
                }
            });
            for vc in &spec.config.volumes {
                let id = Volume::dir_name(&app_name, &vc.name);
                s.tombstones.remove(&id);
                let sync_secs = util::parse_duration(&vc.sync).map(|d| d.as_secs()).unwrap_or(30).max(5);
                s.volumes.entry(id.clone()).or_insert(Volume {
                    id,
                    app: app_name.clone(),
                    name: vc.name.clone(),
                    path: vc.path.clone(),
                    primary: primary.unwrap_or(1),
                    replicas: vec![],
                    copies: vc.copies,
                    sync_secs,
                    created_at: now(),
                    moving_to: None,
                    moving_since: 0,
                    moving_version: 0,
                });
            }
            Ok(Some((app_name.clone(), prev, version)))
        })
        .await
}

async fn wait_release_active(agent: &Arc<Agent>, app: &str, version: u64, timeout_secs: u64) -> Result<()> {
    let start = Instant::now();
    let limit = Duration::from_secs(timeout_secs + 120);
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let s = agent.snapshot();
        let Some(a) = s.apps.get(app) else {
            bail!("{app} disappeared during rollout");
        };
        match a.release(version).map(|r| &r.status) {
            Some(ReleaseStatus::Active) => return Ok(()),
            Some(ReleaseStatus::Failed) => {
                bail!("{app} v{version} failed health checks");
            }
            Some(ReleaseStatus::Superseded) => return Ok(()),
            None => bail!("{app} release v{version} disappeared"),
            _ => {}
        }
        if start.elapsed() > limit {
            bail!("{app} v{version} did not become healthy within {}s", limit.as_secs());
        }
    }
}

async fn rollback_app(agent: &Arc<Agent>, app: &str, prev_version: u64, reason: &str) {
    if prev_version == 0 {
        return;
    }
    let _ = agent
        .mutate(|s| {
            let Some(a) = s.apps.get_mut(app) else { return Ok(()) };
            let Some(target) = a.release(prev_version).cloned() else { return Ok(()) };
            let v = a.next_version();
            a.releases.push(Release {
                version: v,
                image: target.image,
                config: target.config,
                created_at: now(),
                status: ReleaseStatus::Deploying,
                sources: target.sources,
                description: reason.to_string(),
            });
            a.current = v;
            Ok(())
        })
        .await;
}

/// Check for and apply a Fluxer upgrade on the cluster leader.
pub async fn upgrade_stack(
    agent: &Arc<Agent>,
    target_version: Option<&str>,
    force: bool,
) -> Result<RexctlUpgradeResult> {
    let _guard = agent.rexctl.upgrade_lock.lock().await;
    let fx = agent
        .snapshot()
        .fluxer
        .clone()
        .ok_or_else(|| anyhow!("no Fluxer stack is managed on this cluster (`latrix rexctl deploy <backup>` first)"))?;

    let rel = fluxer::resolve_release(&agent.http, target_version).await?;

    // Record check timestamp & latest available version.
    let _ = agent
        .mutate(|s| {
            if let Some(f) = &mut s.fluxer {
                f.last_check = now();
                f.latest_available = Some(rel.version.clone());
            }
            Ok(())
        })
        .await;

    if !force && !fluxer::is_newer_fluxer(&rel.version, &fx.release) {
        return Ok(RexctlUpgradeResult {
            upgraded: false,
            from_release: fx.release.clone(),
            to_release: rel.version,
            updated_services: vec![],
            message: format!("Fluxer is already up to date ({})", fx.release),
        });
    }

    fluxer::check_upgrade_path(&fx.release, &rel)?;

    *agent.rexctl.upgrading.lock().unwrap() = Some(rel.version.clone());
    let outcome = run_upgrade_inner(agent, &fx, &rel).await;
    *agent.rexctl.upgrading.lock().unwrap() = None;

    match outcome {
        Ok(res) => Ok(res),
        Err(e) => {
            let msg = format!("{e:#}");
            let _ = agent
                .mutate(|s| {
                    if let Some(f) = &mut s.fluxer {
                        f.last_error = Some(msg.clone());
                    }
                    Ok(())
                })
                .await;
            agent.event(
                "warn",
                format!("Fluxer upgrade to {} failed: {msg}", rel.version),
            );
            Err(e)
        }
    }
}

async fn run_upgrade_inner(
    agent: &Arc<Agent>,
    fx: &FluxerStack,
    rel: &fluxer::FluxerRelease,
) -> Result<RexctlUpgradeResult> {
    agent.event(
        "info",
        format!(
            "Fluxer: upgrading {} from {} to {}",
            fx.domain,
            if fx.release.is_empty() { "unknown" } else { &fx.release },
            rel.version
        ),
    );

    let bundle = fluxer::fetch_compose_bundle(&agent.http, &rel.compose_url).await?;
    if bundle.images.is_empty() {
        bail!("release {} compose bundle contained no service images", rel.version);
    }

    // Safety snapshots before changing any containers.
    snapshot_fluxer_volumes(agent, &fx.project).await;

    // Guard against automatic Postgres major version jumps.
    let mut safe_images = bundle.images.clone();
    let pg_app = format!("{}-postgres", fx.project);
    if let (Some(cur_pg), Some(new_pg)) = (
        agent
            .snapshot()
            .apps
            .get(&pg_app)
            .and_then(|a| a.current_release())
            .map(|r| r.image.clone()),
        safe_images.get("postgres").cloned(),
    ) {
        if let (Some(m1), Some(m2)) = (fluxer::postgres_major(&cur_pg), fluxer::postgres_major(&new_pg)) {
            if m1 != m2 {
                agent.event(
                    "warn",
                    format!(
                        "Fluxer upgrade {}: keeping Postgres {m1} (refusing automatic major upgrade to Postgres {m2})",
                        rel.version
                    ),
                );
                safe_images.insert("postgres".into(), cur_pg);
            }
        }
    }

    let mut next_fx = fx.clone();
    next_fx.previous_release = if fx.release.is_empty() { None } else { Some(fx.release.clone()) };
    next_fx.release = rel.version.clone();
    if let Some(cf) = &bundle.caddyfile {
        // Keep operator-customized Caddyfile if they modified it from default; otherwise update.
        if fx.caddyfile.trim().is_empty() || fx.caddyfile == fluxer::DEFAULT_CADDYFILE {
            next_fx.caddyfile = cf.clone();
        }
    }
    next_fx.image_overrides = safe_images.clone();

    let specs = fluxer::plan_stack(&next_fx, &safe_images)?;
    next_fx.services = fluxer::service_names_from_plan(&specs);

    // Roll out in tier order: infra (1) -> rust (2) -> core (3) -> edge (4)
    let mut rolled: Vec<(String, u64, u64)> = vec![];
    for tier in 1..=4u8 {
        for spec in specs.iter().filter(|s| s.tier == tier) {
            if !fluxer::is_fluxer_app_service(&spec.service) {
                continue;
            }
            let desc = format!("fluxer upgrade to {}", rel.version);
            if let Some((app_name, prev_ver, new_ver)) = deploy_spec_on_leader(agent, spec, &desc).await? {
                rolled.push((app_name.clone(), prev_ver, new_ver));
                let timeout = spec.config.deploy.health_timeout_secs();
                if let Err(e) = wait_release_active(agent, &app_name, new_ver, timeout).await {
                    // Roll back everything upgraded in this pass in reverse order!
                    agent.event(
                        "warn",
                        format!("Fluxer upgrade {}: {e:#} — rolling back {} service(s)", rel.version, rolled.len()),
                    );
                    for (r_app, r_prev, _) in rolled.iter().rev() {
                        rollback_app(agent, r_app, *r_prev, &format!("fluxer rollback from {}", rel.version)).await;
                    }
                    bail!("{e:#} (rolled back to {})", fx.release);
                }
            }
        }
    }

    next_fx.last_upgrade = now();
    next_fx.last_error = None;
    next_fx.updated_at = now();
    let updated_services: Vec<String> = rolled.iter().map(|(a, _, _)| a.clone()).collect();
    agent
        .mutate(|s| {
            s.fluxer = Some(next_fx);
            Ok(())
        })
        .await?;

    agent.cloudflare.wake.notify_one();
    agent.event(
        "info",
        format!(
            "Fluxer upgraded to {} ({} service(s) updated)",
            rel.version,
            updated_services.len()
        ),
    );
    Ok(RexctlUpgradeResult {
        upgraded: true,
        from_release: fx.release.clone(),
        to_release: rel.version.clone(),
        updated_services,
        message: format!("Fluxer upgraded from {} to {}", fx.release, rel.version),
    })
}

/// Update `FluxerStack` settings/secrets and re-apply the stack to affected apps.
pub async fn apply_config(agent: &Arc<Agent>, req: RexctlConfigRequest) -> Result<RexctlStatusView> {
    let _guard = agent.rexctl.upgrade_lock.lock().await;
    let mut fx = agent
        .snapshot()
        .fluxer
        .clone()
        .ok_or_else(|| anyhow!("no Fluxer stack is managed on this cluster"))?;

    for (k, v) in req.set {
        let k = k.trim().to_string();
        if k.is_empty() {
            bail!("setting key cannot be empty");
        }
        if k == "domain" || k == "FLUXER_DOMAIN" {
            let d = v.trim().to_ascii_lowercase();
            if d.is_empty() || !d.contains('.') {
                bail!("invalid domain '{v}'");
            }
            fx.domain = d.clone();
            fx.settings.insert("domain".into(), d);
        } else if k == "storage.secret_key" || fluxer::is_secret_var(&k) {
            if k == "storage.secret_key" {
                fx.settings.insert(k.clone(), v.clone());
                fx.secrets.insert("FLUXER_S3_SECRET_KEY".into(), v);
            } else {
                fx.secrets.insert(k, v);
            }
        } else {
            fx.settings.insert(k, v);
        }
    }
    for k in req.unset {
        fx.settings.remove(&k);
        fx.secrets.remove(&k);
    }

    // Recompute topology flags from updated settings.
    let storage_backend = fx
        .settings
        .get("storage.backend")
        .or_else(|| fx.settings.get("FLUXER_STORAGE_BACKEND"))
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let storage_endpoint = fx
        .settings
        .get("storage.endpoint")
        .or_else(|| fx.settings.get("FLUXER_S3_ENDPOINT"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.contains("seaweedfs"));
    fx.external_object_store = storage_backend != "filesystem" && storage_endpoint.is_some();
    fx.bundled_voice = fx
        .settings
        .get("voice.bundled")
        .or_else(|| fx.settings.get("FLUXER_LIVEKIT_BUNDLED"))
        .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no" | "off"))
        .unwrap_or(true);
    fx.kv_postgres = fx
        .settings
        .get("kv.mode")
        .or_else(|| fx.settings.get("FLUXER_KV_MODE"))
        .map(|v| v.trim().eq_ignore_ascii_case("postgres"))
        .unwrap_or(false);
    fx.rust_single = fx
        .settings
        .get("rust.process")
        .or_else(|| fx.settings.get("FLUXER_RUST_PROCESS"))
        .map(|v| v.trim().eq_ignore_ascii_case("single"))
        .unwrap_or(false);
    fx.updated_at = now();

    let specs = fluxer::plan_stack(&fx, &fx.image_overrides)?;
    fx.services = fluxer::service_names_from_plan(&specs);

    for tier in 1..=4u8 {
        for spec in specs.iter().filter(|s| s.tier == tier) {
            let _ = deploy_spec_on_leader(agent, spec, "fluxer config updated").await?;
        }
    }

    agent
        .mutate(|s| {
            s.fluxer = Some(fx);
            Ok(())
        })
        .await?;
    agent.cloudflare.wake.notify_one();
    Ok(status_view(agent))
}

fn in_utc_window(window: &str, unix_secs: u64) -> bool {
    let w = window.trim();
    if w.is_empty() {
        return true;
    }
    let Some((a, b)) = w.split_once('-') else {
        return true;
    };
    let parse_hm = |s: &str| -> Option<u32> {
        let (h, m) = s.trim().split_once(':')?;
        let h: u32 = h.parse().ok()?;
        let m: u32 = m.parse().ok()?;
        (h < 24 && m < 60).then_some(h * 60 + m)
    };
    let (Some(start), Some(end)) = (parse_hm(a), parse_hm(b)) else {
        return true;
    };
    let cur = ((unix_secs % 86400) / 60) as u32;
    if start <= end {
        cur >= start && cur <= end
    } else {
        cur >= start || cur <= end
    }
}

/// Leader background loop: checks for new Fluxer releases and rolls them out automatically.
pub async fn run(agent: Arc<Agent>) {
    if agent.dev {
        return;
    }
    // Give the cluster a couple minutes after boot to stabilize.
    tokio::time::sleep(Duration::from_secs(120)).await;
    loop {
        if agent.is_leader() {
            let s = agent.snapshot();
            if let Some(fx) = &s.fluxer {
                let interval = fx.upgrade_interval_hours.max(1) * 3600;
                let due = now().saturating_sub(fx.last_check) >= interval;
                if fx.auto_upgrade && due && in_utc_window(&s.settings.update_window, now()) {
                    // Only auto-upgrade when core Fluxer apps are currently healthy.
                    let view = status_view(&agent);
                    let all_ok = !view.services.is_empty()
                        && view.services.iter().all(|svc| svc.status == "healthy");
                    if all_ok {
                        match upgrade_stack(&agent, None, false).await {
                            Ok(r) if r.upgraded => {
                                info!("automatic Fluxer upgrade complete: {}", r.message);
                            }
                            Ok(_) => {}
                            Err(e) => warn!("automatic Fluxer upgrade check: {e:#}"),
                        }
                    } else {
                        // Still refresh latest_available so `latrix rexctl status` stays current.
                        if let Ok(rel) = fluxer::resolve_release(&agent.http, None).await {
                            let _ = agent
                                .mutate(|st| {
                                    if let Some(f) = &mut st.fluxer {
                                        f.last_check = now();
                                        f.latest_available = Some(rel.version);
                                    }
                                    Ok(())
                                })
                                .await;
                        }
                    }
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(600)) => {},
            _ = agent.rexctl.wake.notified() => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_window_checks() {
        assert!(in_utc_window("", 12345));
        assert!(in_utc_window("02:00-05:00", 3 * 3600));
        assert!(!in_utc_window("02:00-05:00", 6 * 3600));
        assert!(in_utc_window("23:00-02:00", 23 * 3600 + 1800));
        assert!(in_utc_window("23:00-02:00", 3600));
        assert!(!in_utc_window("23:00-02:00", 12 * 3600));
    }
}
