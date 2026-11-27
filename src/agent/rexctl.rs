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
use crate::util::{now, API_PORT};
use anyhow::{anyhow, bail, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Default)]
pub struct Shared {
    pub upgrade_lock: tokio::sync::Mutex<()>,
    pub wake: tokio::sync::Notify,
    pub upgrading: Mutex<Option<String>>,
    pub force_check: AtomicBool,
}

struct UpgradingGuard(Arc<Agent>);

impl Drop for UpgradingGuard {
    fn drop(&mut self) {
        *self
            .0
            .rexctl
            .upgrading
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
    }
}

struct RolledApp {
    app: String,
    was_new: bool,
    prev_version: u64,
    new_version: u64,
    prev_secrets: BTreeMap<String, String>,
    prev_count: u32,
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
        upgrading: agent
            .rexctl
            .upgrading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone(),
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
async fn snapshot_fluxer_volumes(agent: &Arc<Agent>, fx: &FluxerStack) -> Result<()> {
    let s = agent.snapshot();
    let mut stack_apps: BTreeSet<String> = fx
        .services
        .iter()
        .map(|svc| format!("{}-{svc}", fx.project))
        .collect();
    for (name, app) in &s.apps {
        if app.config().and_then(|c| c.group.as_deref()) == Some(fx.project.as_str()) {
            stack_apps.insert(name.clone());
        }
    }
    let vols: Vec<Volume> = s
        .volumes
        .values()
        .filter(|v| stack_apps.contains(&v.app))
        .cloned()
        .collect();
    let mut errors = vec![];
    for v in vols {
        let Some(ip) = agent.ip_of(v.primary) else {
            errors.push(format!("{}: primary machine #{} not found", v.id, v.primary));
            continue;
        };
        let host = if v.primary == agent.me.machine_id { "127.0.0.1" } else { ip.as_str() };
        let url = super::host_port_url(
            host,
            API_PORT,
            &format!("/v1/local/snapshots?volume={}&action=take", v.id),
        );
        match agent
            .http
            .post(&url)
            .bearer_auth(&agent.me.token)
            .timeout(Duration::from_secs(120))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                info!("rexctl: pre-upgrade snapshot taken for {}", v.id);
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                let msg = format!("{}: snapshot returned {status} ({})", v.id, body.trim());
                warn!("rexctl: {msg}");
                errors.push(msg);
            }
            Err(e) => {
                let msg = format!("{}: snapshot failed: {e}", v.id);
                warn!("rexctl: {msg}");
                errors.push(msg);
            }
        }
    }
    if !errors.is_empty() {
        bail!("pre-upgrade volume snapshot failed: {}", errors.join("; "));
    }
    Ok(())
}

/// Deploy (or update) one Fluxer service directly from the leader.
/// Returns `Some(RolledApp)` if a new release was created.
async fn deploy_spec_on_leader(
    agent: &Arc<Agent>,
    spec: &ServiceSpec,
    description: &str,
) -> Result<Option<RolledApp>> {
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
            super::api::check_app_conflicts(s, &app_name, &spec.config)?;
            if is_new {
                let vip = super::api::alloc_vip(s)?;
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
            let prev_secrets = a.secrets.clone();
            let prev_count = a.count;
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

            super::api::reconcile_app_volumes(s, &live.view(), &app_name, &spec.config)?;
            Ok(Some(RolledApp {
                app: app_name.clone(),
                was_new: is_new,
                prev_version: prev,
                new_version: version,
                prev_secrets,
                prev_count,
            }))
        })
        .await
}

async fn wait_release_active(agent: &Arc<Agent>, app: &str, version: u64, timeout_secs: u64) -> Result<()> {
    let start = Instant::now();
    let limit = Duration::from_secs(timeout_secs + 120);
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !agent.is_leader() {
            bail!("lost leadership while rolling out {app} v{version}");
        }
        let s = agent.snapshot();
        let Some(a) = s.apps.get(app) else {
            bail!("{app} disappeared during rollout");
        };
        match a.release(version).map(|r| &r.status) {
            Some(ReleaseStatus::Active) => return Ok(()),
            Some(ReleaseStatus::Failed) => {
                bail!("{app} v{version} failed health checks");
            }
            Some(ReleaseStatus::Superseded) => {
                bail!("{app} v{version} was superseded by another deployment");
            }
            None => bail!("{app} release v{version} disappeared"),
            _ => {}
        }
        if start.elapsed() > limit {
            bail!("{app} v{version} did not become healthy within {}s", limit.as_secs());
        }
    }
}

async fn rollback_app(agent: &Arc<Agent>, rolled: &RolledApp, reason: &str) {
    let _ = agent
        .mutate(|s| {
            if rolled.was_new {
                s.apps.remove(&rolled.app);
                for i in s.instances.values_mut().filter(|i| i.app == rolled.app) {
                    i.stopping = true;
                    i.stopping_since = now();
                }
                let vols: Vec<String> = s.volumes_of(&rolled.app).map(|v| v.id.clone()).collect();
                for v in vols {
                    s.volumes.remove(&v);
                }
                return Ok(());
            }
            let Some(a) = s.apps.get_mut(&rolled.app) else { return Ok(()) };
            a.secrets = rolled.prev_secrets.clone();
            a.count = rolled.prev_count;
            // If the scheduler already auto-rolled back `new_version` to `prev_version`,
            // don't push a duplicate deploying release on top of it.
            let already_rolled_back = a.current == rolled.prev_version
                && a.release(rolled.new_version)
                    .map(|r| r.status == ReleaseStatus::Failed)
                    .unwrap_or(false);
            if already_rolled_back || rolled.prev_version == 0 {
                return Ok(());
            }
            let Some(target) = a.release(rolled.prev_version).cloned() else { return Ok(()) };
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

/// Remove apps belonging to `project` that are no longer present in `keep_services`.
async fn remove_obsolete_services(
    agent: &Arc<Agent>,
    project: &str,
    old_services: &[String],
    keep_services: &[String],
) -> Result<()> {
    let keep: BTreeSet<String> = keep_services.iter().map(|s| format!("{project}-{s}")).collect();
    let old_set: BTreeSet<String> = old_services.iter().map(|s| format!("{project}-{s}")).collect();
    agent
        .mutate(|s| {
            let to_remove: Vec<String> = s
                .apps
                .iter()
                .filter(|(name, app)| {
                    !keep.contains(*name)
                        && (old_set.contains(*name)
                            || app.config().and_then(|c| c.group.as_deref()) == Some(project))
                })
                .map(|(name, _)| name.clone())
                .collect();
            for app_name in to_remove {
                s.apps.remove(&app_name);
                for i in s.instances.values_mut().filter(|i| i.app == app_name) {
                    i.stopping = true;
                    i.stopping_since = now();
                }
                let vols: Vec<String> = s.volumes_of(&app_name).map(|v| v.id.clone()).collect();
                for v in vols {
                    s.volumes.remove(&v);
                }
            }
            Ok(())
        })
        .await
}

/// Check for and apply a Fluxer upgrade on the cluster leader.
/// Runs inside a detached task so client HTTP disconnect cannot cancel a mid-flight rollout.
pub async fn upgrade_stack(
    agent: &Arc<Agent>,
    target_version: Option<&str>,
    force: bool,
) -> Result<RexctlUpgradeResult> {
    let a = agent.clone();
    let target = target_version.map(String::from);
    tokio::spawn(async move { upgrade_stack_task(&a, target.as_deref(), force).await })
        .await
        .map_err(|e| anyhow!("upgrade task panicked: {e}"))?
}

async fn upgrade_stack_task(
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

    *agent
        .rexctl
        .upgrading
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(rel.version.clone());
    let _status_guard = UpgradingGuard(agent.clone());
    let outcome = run_upgrade_inner(agent, &fx, &rel, force).await;
    drop(_status_guard);

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
    force: bool,
) -> Result<RexctlUpgradeResult> {
    agent.event(
        "info",
        format!(
            "Fluxer: upgrading {} from {} to {}{}",
            fx.domain,
            if fx.release.is_empty() { "unknown" } else { &fx.release },
            rel.version,
            if rel.schema_changed { " (includes database schema migration)" } else { "" }
        ),
    );

    let bundle = fluxer::fetch_compose_bundle(&agent.http, &rel.compose_url).await?;
    if bundle.images.is_empty() {
        bail!("release {} compose bundle contained no service images", rel.version);
    }

    // Safety snapshots before changing any containers (required unless --force).
    if let Err(e) = snapshot_fluxer_volumes(agent, fx).await {
        if force {
            agent.event("warn", format!("Fluxer upgrade {}: proceeding with --force despite snapshot failure: {e:#}", rel.version));
        } else {
            return Err(e);
        }
    }

    // Guard against automatic Postgres major version jumps (fail-closed if unparseable unless --force).
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
        if cur_pg != new_pg {
            match (fluxer::postgres_major(&cur_pg), fluxer::postgres_major(&new_pg)) {
                (Some(m1), Some(m2)) if m1 != m2 => {
                    agent.event(
                        "warn",
                        format!(
                            "Fluxer upgrade {}: keeping Postgres {m1} (refusing automatic major upgrade to Postgres {m2})",
                            rel.version
                        ),
                    );
                    safe_images.insert("postgres".into(), cur_pg);
                }
                (Some(_), Some(_)) => {}
                _ if !force => {
                    agent.event(
                        "warn",
                        format!(
                            "Fluxer upgrade {}: keeping current Postgres image '{cur_pg}' because major version of '{new_pg}' could not be verified",
                            rel.version
                        ),
                    );
                    safe_images.insert("postgres".into(), cur_pg);
                }
                _ => {}
            }
        }
    }

    let mut next_fx = fx.clone();
    next_fx.previous_release = if fx.release.is_empty() { None } else { Some(fx.release.clone()) };
    next_fx.release = rel.version.clone();
    if let Some(cf) = &bundle.caddyfile {
        // Keep operator-customized Caddyfile; otherwise keep tracking upstream updates.
        if !fx.caddyfile_custom || fx.caddyfile.trim().is_empty() || fx.caddyfile == fluxer::DEFAULT_CADDYFILE {
            next_fx.caddyfile = cf.clone();
            next_fx.caddyfile_custom = false;
        }
    }
    next_fx.image_overrides = safe_images.clone();

    let specs = fluxer::plan_stack(&next_fx, &safe_images)?;
    next_fx.services = fluxer::service_names_from_plan(&specs);

    // Roll out in tier order: infra (1) -> rust (2) -> core (3) -> edge (4).
    // Any deploy or health-check failure rolls back every service updated in this pass.
    let mut rolled: Vec<RolledApp> = vec![];
    let rollout_res: Result<()> = async {
        for tier in 1..=4u8 {
            for spec in specs.iter().filter(|s| s.tier == tier) {
                if !fluxer::is_fluxer_app_service(&spec.service) {
                    continue;
                }
                let desc = format!("fluxer upgrade to {}", rel.version);
                if let Some(r) = deploy_spec_on_leader(agent, spec, &desc).await? {
                    let app_name = r.app.clone();
                    let new_ver = r.new_version;
                    rolled.push(r);
                    let timeout = spec.config.deploy.health_timeout_secs();
                    wait_release_active(agent, &app_name, new_ver, timeout).await?;
                }
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = rollout_res {
        if !rolled.is_empty() {
            agent.event(
                "warn",
                format!("Fluxer upgrade {}: {e:#} — rolling back {} service(s)", rel.version, rolled.len()),
            );
            let reason = format!("fluxer rollback from {}", rel.version);
            for r in rolled.iter().rev() {
                rollback_app(agent, r, &reason).await;
            }
            bail!("{e:#} (rolled back to {})", fx.release);
        }
        return Err(e);
    }

    let _ = remove_obsolete_services(agent, &fx.project, &fx.services, &next_fx.services).await;

    next_fx.last_upgrade = now();
    next_fx.last_error = None;
    next_fx.updated_at = now();
    let updated_services: Vec<String> = rolled.iter().map(|r| r.app.clone()).collect();
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
    let old_services = fx.services.clone();

    for (k, v) in req.set {
        let k = k.trim().to_string();
        if k.is_empty() {
            bail!("setting key cannot be empty");
        }
        if k == "domain" || k == "FLUXER_DOMAIN" {
            let d = v.trim().to_ascii_lowercase();
            crate::config::validate_domain(&d)?;
            if d != fx.domain {
                fluxer::clear_stale_domain_settings(&mut fx.settings, &fx.domain);
            }
            fx.domain = d.clone();
            fx.settings.insert("domain".into(), d);
        } else if k == "storage.secret_key" || fluxer::is_secret_entry(&k, &v) {
            if k == "storage.secret_key" {
                fx.settings.insert(k.clone(), v.clone());
                fx.secrets.insert("FLUXER_S3_SECRET_KEY".into(), v.clone());
                fx.secrets.insert("FLUXER_S3_SECRET_ACCESS_KEY".into(), v);
            } else if k == "storage.access_key" {
                fx.settings.insert(k.clone(), v.clone());
                fx.secrets.insert("FLUXER_S3_ACCESS_KEY".into(), v.clone());
                fx.secrets.insert("FLUXER_S3_ACCESS_KEY_ID".into(), v);
            } else {
                fx.secrets.insert(k, v);
            }
        } else {
            fx.settings.insert(k, v);
        }
    }
    for raw_k in req.unset {
        let k = raw_k.trim();
        if k == "domain" || k == "FLUXER_DOMAIN" {
            bail!("cannot unset required Fluxer domain (use `set domain=<new-domain>` instead)");
        }
        fx.settings.remove(k);
        fx.secrets.remove(k);
        match k {
            "storage.secret_key" | "FLUXER_S3_SECRET_KEY" | "FLUXER_S3_SECRET_ACCESS_KEY" => {
                fx.settings.remove("storage.secret_key");
                fx.secrets.remove("FLUXER_S3_SECRET_KEY");
                fx.secrets.remove("FLUXER_S3_SECRET_ACCESS_KEY");
            }
            "storage.access_key" | "FLUXER_S3_ACCESS_KEY" | "FLUXER_S3_ACCESS_KEY_ID" => {
                fx.settings.remove("storage.access_key");
                fx.secrets.remove("FLUXER_S3_ACCESS_KEY");
                fx.secrets.remove("FLUXER_S3_ACCESS_KEY_ID");
            }
            other => {
                if let Some(env_var) = fluxer::named_setting_to_var(other) {
                    fx.settings.remove(env_var);
                    fx.secrets.remove(env_var);
                }
            }
        }
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
        .filter(|s| !s.is_empty() && !fluxer::is_bundled_seaweedfs_endpoint(s));
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

    // Remove services that are no longer part of the topology BEFORE deploying new ones
    // (e.g., switching `rust.process=single` <-> per-service avoids DNS alias collisions).
    remove_obsolete_services(agent, &fx.project, &old_services, &fx.services).await?;

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
        return false;
    };
    let parse_hm = |s: &str| -> Option<u32> {
        let (h, m) = s.trim().split_once(':')?;
        let h: u32 = h.parse().ok()?;
        let m: u32 = m.parse().ok()?;
        (h < 24 && m < 60).then_some(h * 60 + m)
    };
    let (Some(start), Some(end)) = (parse_hm(a), parse_hm(b)) else {
        return false;
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
    // Give the cluster a couple minutes after boot to stabilize (wakeable for --check-now).
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(120)) => {},
        _ = agent.rexctl.wake.notified() => {},
    }
    loop {
        let forced = agent.rexctl.force_check.swap(false, Ordering::SeqCst);
        if agent.is_leader() {
            let s = agent.snapshot();
            if let Some(fx) = &s.fluxer {
                let interval = fx.upgrade_interval_hours.max(1) * 3600;
                let due = forced || now().saturating_sub(fx.last_check) >= interval;
                if due && (forced || (fx.auto_upgrade && in_utc_window(&s.settings.update_window, now()))) {
                    let view = status_view(&agent);
                    let all_ok = !view.services.is_empty()
                        && view.services.iter().all(|svc| svc.status == "healthy");
                    if fx.auto_upgrade && all_ok && (forced || in_utc_window(&s.settings.update_window, now())) {
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
