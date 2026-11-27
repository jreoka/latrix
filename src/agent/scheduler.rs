//! The scheduler: a pure function from (cluster state, live reports) to a new
//! desired cluster state. It runs on the leader every couple of seconds.
//!
//! Responsibilities:
//! * keep `count` healthy instances of each app's current release running
//! * rolling deploys with automatic rollback when the new release is unhealthy
//! * replace instances on dead machines (failover)
//! * drain machines (for maintenance) without downtime
//! * move volumes safely (final sync before switching primaries)
//! * keep the requested number of volume replicas
//! * rebalance load and spread instances across machines
//! * autoscale apps between min/max

use crate::config::AppConfig;
use crate::state::*;
use crate::util::random_id;
use std::collections::{HashMap, HashSet};

/// Machines dead for this long have their stateless instances replaced.
pub const LOST_AFTER: u64 = 30;
/// Machines dead for this long start moving instances away early.
pub const SUSPECT_AFTER: u64 = 10;
/// Volume primaries dead for this long fail over to a replica.
pub const FAILOVER_AFTER: u64 = 60;
/// Replicas dead for this long are replaced by a new replica.
pub const REPLICA_REPLACE_AFTER: u64 = 600;
/// A new leader waits this long (collecting reports) before declaring anything lost.
pub const LEADER_GRACE: u64 = 15;

pub struct LiveView<'a> {
    pub now: u64,
    pub alive: &'a HashSet<u32>,
    /// unix time a machine was first seen dead
    pub dead_since: &'a HashMap<u32, u64>,
    pub reports: &'a HashMap<u32, NodeReport>,
    pub leader_for: u64,
}

impl<'a> LiveView<'a> {
    fn grace(&self) -> bool {
        self.leader_for < LEADER_GRACE
    }
    pub fn is_alive(&self, m: u32) -> bool {
        self.grace() || self.alive.contains(&m)
    }
    pub fn dead_for(&self, m: u32) -> u64 {
        if self.grace() || self.alive.contains(&m) {
            return 0;
        }
        self.dead_since
            .get(&m)
            .map(|t| self.now.saturating_sub(*t))
            .unwrap_or(0)
    }
    pub fn inst(&self, i: &Instance) -> Option<&'a InstanceReport> {
        self.reports
            .get(&i.machine)?
            .instances
            .iter()
            .find(|r| r.id == i.id)
    }
    pub fn healthy(&self, i: &Instance) -> bool {
        self.inst(i).map(|r| r.healthy).unwrap_or(false)
    }
    /// Docker on that machine answers (unknown counts as fine).
    pub fn docker_ok(&self, m: u32) -> bool {
        self.reports.get(&m).map(|r| r.docker_ok).unwrap_or(true)
    }
    fn metrics(&self, m: u32) -> Option<&'a Metrics> {
        self.reports.get(&m).map(|r| &r.metrics)
    }
    fn vol(&self, m: u32, vol: &str) -> Option<&'a VolumeReport> {
        self.reports.get(&m)?.volumes.iter().find(|v| v.id == vol)
    }
}

/// Leader-local memory that does not need to be replicated.
#[derive(Default)]
pub struct SchedMemory {
    pub last_rebalance: u64,
    pub last_autoscale: u64,
    pub up_streak: HashMap<String, u32>,
    pub down_streak: HashMap<String, u32>,
    pub warned: HashMap<String, u64>,
    /// instance -> (restart count, when first seen at that count)
    pub restarts: HashMap<String, (u32, u64)>,
    /// Apps with UDP ports: the machines they last ran on (players know that
    /// IP, so a restart or redeploy goes back to the same machine).
    pub homes: HashMap<String, Vec<u32>>,
}

pub struct Ctx<'a, 'b> {
    pub live: &'a LiveView<'b>,
    pub events: Vec<Event>,
    pub mem: &'a mut SchedMemory,
}

impl<'a, 'b> Ctx<'a, 'b> {
    fn info(&mut self, msg: impl Into<String>) {
        self.events.push(Event {
            ts: self.live.now,
            level: "info".into(),
            message: msg.into(),
        });
    }
    fn warn(&mut self, msg: impl Into<String>) {
        self.events.push(Event {
            ts: self.live.now,
            level: "warn".into(),
            message: msg.into(),
        });
    }
    /// Warn at most once every 5 minutes per key.
    fn warn_once(&mut self, key: &str, msg: impl Into<String>) {
        let last = self.mem.warned.get(key).copied().unwrap_or(0);
        if self.live.now.saturating_sub(last) >= 300 {
            self.mem.warned.insert(key.to_string(), self.live.now);
            self.warn(msg);
        }
    }
}

pub fn reconcile(s: &mut ClusterState, live: &LiveView, mem: &mut SchedMemory) -> Vec<Event> {
    let mut cx = Ctx {
        live,
        events: vec![],
        mem,
    };
    cleanup_stopping(s, &mut cx);
    restart_stuck(s, &mut cx);
    let apps: Vec<String> = s.apps.keys().cloned().collect();
    for app in &apps {
        let stateful = s
            .apps
            .get(app)
            .and_then(|a| a.config())
            .map(|c| c.stateful())
            .unwrap_or(false);
        if stateful {
            reconcile_stateful(s, app, &mut cx);
        } else {
            reconcile_stateless(s, app, &mut cx);
        }
    }
    maintain_replicas(s, &mut cx);
    orchestrate_maintenance(s, &mut cx);
    if live.now.saturating_sub(cx.mem.last_autoscale) >= 30 {
        cx.mem.last_autoscale = live.now;
        if s.settings.autoscale {
            autoscale(s, &mut cx);
        }
    }
    if live.now.saturating_sub(cx.mem.last_rebalance) >= 45 && !live.grace() {
        cx.mem.last_rebalance = live.now;
        if s.settings.rebalance {
            rebalance(s, &mut cx);
        }
    }
    cx.events
}

/// An instance that was healthy but has failed its health checks for 2
/// minutes is replaced (the container is running but stuck). Containers that
/// keep crashing are reported.
fn restart_stuck(s: &mut ClusterState, cx: &mut Ctx) {
    let live = cx.live;
    let now = live.now;
    let mut stuck = vec![];
    let mut seen = vec![];
    for i in s.instances.values().filter(|i| !i.stopping) {
        let Some(r) = live.inst(i) else { continue };
        seen.push(i.id.clone());
        let active = s
            .apps
            .get(&i.app)
            .and_then(|a| a.release(i.release))
            .map(|r| r.status == ReleaseStatus::Active)
            .unwrap_or(false);
        if active && !r.healthy && r.unhealthy_since > 0 && now.saturating_sub(r.unhealthy_since) >= 120 {
            stuck.push((i.id.clone(), i.app.clone(), i.machine));
        }
        // crash loop: 5+ restarts within 10 minutes
        let entry = cx.mem.restarts.entry(i.id.clone()).or_insert((r.restarts, now));
        if r.restarts < entry.0 || now.saturating_sub(entry.1) > 600 {
            *entry = (r.restarts, now);
        } else if r.restarts >= entry.0 + 5 {
            let n = r.restarts - entry.0;
            *entry = (r.restarts, now);
            let app = i.app.clone();
            cx.warn_once(
                &format!("crash-{app}"),
                format!("{app}: instance {} restarted {n} times in the last few minutes (crash loop) — see `latrix logs {app}`", i.id),
            );
        }
    }
    cx.mem.restarts.retain(|k, _| seen.contains(k));
    for (id, app, m) in stuck {
        // At most one restart per app every 5 minutes.
        let key = format!("restart-{app}");
        if now.saturating_sub(cx.mem.warned.get(&key).copied().unwrap_or(0)) < 300 {
            continue;
        }
        cx.mem.warned.insert(key, now);
        stop(s, &id, now);
        cx.warn(format!(
            "{app}: instance {id} on {} failed its health checks for 2 minutes; restarting it",
            machine_name(s, m)
        ));
    }
}

fn machine_name(s: &ClusterState, m: u32) -> String {
    s.machines
        .get(&m)
        .map(|m| m.name.clone())
        .unwrap_or_else(|| format!("#{m}"))
}

fn schedulable(s: &ClusterState, live: &LiveView, m: u32) -> bool {
    s.machines
        .get(&m)
        .map(|mm| mm.status == MachineStatus::Ready)
        .unwrap_or(false)
        && live.alive.contains(&m)
        && live.docker_ok(m)
}

fn evacuating(s: &ClusterState, live: &LiveView, m: u32) -> bool {
    match s.machines.get(&m) {
        None => true,
        Some(mm) => {
            matches!(
                mm.status,
                MachineStatus::Draining | MachineStatus::Maintenance
            ) || live.dead_for(m) >= SUSPECT_AFTER
                || !live.docker_ok(m)
        }
    }
}

/// Is machine `m` in one of the app's regions (any machine when unpinned)?
pub fn region_ok(s: &ClusterState, cfg: &AppConfig, m: u32) -> bool {
    cfg.regions.is_empty() || cfg.allows_region(s.machines.get(&m).and_then(|x| x.region.as_deref()))
}

/// Apps with UDP ports are published straight on the machine's IP: one
/// instance per machine, and moving them changes the address players use.
pub fn direct(cfg: &AppConfig) -> bool {
    !cfg.udp_ports().is_empty()
}

/// Another app already publishes one of these UDP ports on `m`.
fn udp_conflict(s: &ClusterState, app: &str, cfg: &AppConfig, m: u32) -> bool {
    let mine: Vec<u16> = cfg.udp_ports().iter().map(|(p, _)| *p).collect();
    if mine.is_empty() {
        return false;
    }
    s.instances_on(m).filter(|i| i.app != app).any(|i| {
        s.apps
            .get(&i.app)
            .and_then(|a| a.release(i.release))
            .map(|r| r.config.udp_ports().iter().any(|(p, _)| mine.contains(p)))
            .unwrap_or(false)
    })
}

fn regions_text(cfg: &AppConfig) -> String {
    cfg.regions.join(", ")
}

fn stop(s: &mut ClusterState, id: &str, now: u64) {
    if let Some(i) = s.instances.get_mut(id) {
        if !i.stopping {
            i.stopping = true;
            i.stopping_since = now;
        }
    }
}

fn create(s: &mut ClusterState, app: &str, release: u64, machine: u32, now: u64) -> String {
    let id = random_id(8);
    s.instances.insert(
        id.clone(),
        Instance {
            id: id.clone(),
            app: app.to_string(),
            release,
            machine,
            created_at: now,
            stopping: false,
            stopping_since: 0,
            replaces: None,
        },
    );
    id
}

/// Delete stopping instances once their container is gone (or their machine is).
fn cleanup_stopping(s: &mut ClusterState, cx: &mut Ctx) {
    let live = cx.live;
    let mut remove = vec![];
    for i in s.instances.values().filter(|i| i.stopping) {
        let gone_machine = !s.machines.contains_key(&i.machine) || live.dead_for(i.machine) >= LOST_AFTER;
        let reported_gone = live
            .reports
            .get(&i.machine)
            .map(|r| !r.instances.iter().any(|x| x.id == i.id))
            .unwrap_or(false)
            && live.alive.contains(&i.machine);
        let too_long = live.now.saturating_sub(i.stopping_since) > 300;
        if gone_machine || reported_gone || too_long {
            remove.push(i.id.clone());
        }
    }
    for id in remove {
        s.instances.remove(&id);
    }
}

/// Score candidate machines for a new instance. Higher is better.
pub fn place(
    s: &ClusterState,
    live: &LiveView,
    app: &str,
    cfg: &AppConfig,
    exclude: &[u32],
) -> Option<u32> {
    let need_mb = cfg.scale.memory_mb() as f64;
    let mut best: Option<(f64, u32)> = None;
    for m in s.machines.values() {
        if exclude.contains(&m.id) || !schedulable(s, live, m.id) || !region_ok(s, cfg, m.id) {
            continue;
        }
        if direct(cfg) && (s.instances_of(app).any(|i| i.machine == m.id) || udp_conflict(s, app, cfg, m.id)) {
            continue;
        }
        let met = live.metrics(m.id);
        let mem_total = met
            .map(|x| x.mem_total_mb)
            .filter(|x| *x > 0)
            .unwrap_or(m.memory_mb.max(1024)) as f64;
        let cpus = met
            .map(|x| x.cpus)
            .filter(|x| *x > 0.0)
            .unwrap_or(m.cpus.max(1.0));
        let reserved = s.reserved_mb(m.id) as f64;
        let fits = reserved + need_mb <= mem_total * 0.9;
        let mem_free = 1.0 - (reserved + need_mb) / mem_total;
        let cpu_free = 1.0 - (s.reserved_cpu(m.id) + cfg.scale.cpu) / cpus;
        let actual_cpu = met.map(|x| x.cpu_pct / 100.0).unwrap_or(0.0);
        let same = s
            .instances_of(app)
            .filter(|i| i.machine == m.id && !i.stopping)
            .count() as f64;
        let mut score = mem_free + 0.5 * cpu_free + 0.5 * (1.0 - actual_cpu) - 3.0 * same;
        if !fits {
            score -= 10.0;
        }
        // Spread across regions when possible.
        if let Some(region) = &m.region {
            let same_region = s
                .instances_of(app)
                .filter(|i| !i.stopping)
                .filter(|i| s.machines.get(&i.machine).and_then(|x| x.region.as_ref()) == Some(region))
                .count() as f64;
            score -= 0.5 * same_region;
        }
        // Prefer machines that have the image or the volume locally? Small tie-breaker on id for determinism.
        score -= m.id as f64 * 1e-6;
        if best.map(|(b, _)| score > b).unwrap_or(true) {
            best = Some((score, m.id));
        }
    }
    best.map(|(_, m)| m)
}

/// Updates release status (deploying -> active, or failed + rollback).
/// Returns false if the app's current release changed (rollback).
fn track_release(s: &mut ClusterState, app: &str, cx: &mut Ctx) -> bool {
    let live = cx.live;
    let Some(a) = s.apps.get(app) else { return false };
    let Some(rel) = a.current_release() else { return false };
    if rel.status != ReleaseStatus::Deploying {
        return true;
    }
    let cfg = rel.config.clone();
    let version = rel.version;
    let target = a.count;
    let cur: Vec<&Instance> = s
        .instances_of(app)
        .filter(|i| i.release == version && !i.stopping)
        .collect();
    let healthy = cur.iter().filter(|i| live.healthy(i)).count() as u32;
    let timeout = cfg.deploy.health_timeout_secs();
    let failed = cur
        .iter()
        .any(|i| !live.healthy(i) && live.now.saturating_sub(i.created_at) > timeout)
        || (cur.is_empty() && target > 0 && live.now.saturating_sub(rel.created_at) > timeout * 3);
    if healthy >= target {
        let a = s.apps.get_mut(app).unwrap();
        for r in a.releases.iter_mut() {
            if r.version == version {
                r.status = ReleaseStatus::Active;
            } else if r.status == ReleaseStatus::Active {
                r.status = ReleaseStatus::Superseded;
            }
        }
        cx.info(format!("{app}: release v{version} is live"));
        return true;
    }
    if failed {
        let a = s.apps.get_mut(app).unwrap();
        let prev = a
            .releases
            .iter()
            .filter(|r| r.version < version && matches!(r.status, ReleaseStatus::Active | ReleaseStatus::Superseded))
            .map(|r| r.version)
            .max();
        if prev.is_some() {
            for r in a.releases.iter_mut() {
                if r.version == version {
                    r.status = ReleaseStatus::Failed;
                }
            }
        }
        match prev {
            Some(p) => {
                a.current = p;
                for r in a.releases.iter_mut() {
                    if r.version == p {
                        r.status = ReleaseStatus::Active;
                    }
                }
                cx.warn(format!(
                    "{app}: release v{version} did not become healthy within {timeout}s — rolled back to v{p}"
                ));
                return false;
            }
            None => {
                // Nothing to roll back to: keep trying (the app may just be slow, or crash-looping).
                cx.warn_once(
                    &format!("unhealthy-{app}-{version}"),
                    format!("{app}: release v{version} is not healthy after {timeout}s — check `latrix logs {app}`"),
                );
            }
        }
    }
    true
}

fn reconcile_stateless(s: &mut ClusterState, app: &str, cx: &mut Ctx) {
    let live = cx.live;
    let now = live.now;

    // Instances on machines that are gone for good are replaced.
    let lost: Vec<(String, u32)> = s
        .instances_of(app)
        .filter(|i| !i.stopping)
        .filter(|i| !s.machines.contains_key(&i.machine) || live.dead_for(i.machine) >= LOST_AFTER)
        .map(|i| (i.id.clone(), i.machine))
        .collect();
    for (id, m) in lost {
        cx.warn(format!(
            "{app}: machine {} is unreachable, replacing instance {id}",
            machine_name(s, m)
        ));
        stop(s, &id, now);
    }

    // Finish or abort replacements (rebalance / drain moves).
    let repl: Vec<(String, String, bool, u64)> = s
        .instances_of(app)
        .filter(|i| !i.stopping)
        .filter_map(|i| {
            i.replaces
                .clone()
                .map(|old| (i.id.clone(), old, live.healthy(i), i.created_at))
        })
        .collect();
    let timeout = s
        .apps
        .get(app)
        .and_then(|a| a.config())
        .map(|c| c.deploy.health_timeout_secs())
        .unwrap_or(90);
    for (id, old, healthy, created) in repl {
        let old_active = s.instances.get(&old).map(|o| !o.stopping).unwrap_or(false);
        if !old_active {
            s.instances.get_mut(&id).unwrap().replaces = None;
        } else if healthy {
            stop(s, &old, now);
            s.instances.get_mut(&id).unwrap().replaces = None;
        } else if now.saturating_sub(created) > timeout {
            stop(s, &id, now);
            cx.warn(format!("{app}: move of {old} aborted, replacement {id} never became healthy"));
        }
    }

    if !track_release(s, app, cx) {
        return;
    }

    let a = &s.apps[app];
    let Some(rel) = a.current_release() else { return };
    let cfg = rel.config.clone();
    let version = rel.version;
    let target = a.count as usize;

    let active: Vec<Instance> = s
        .instances_of(app)
        .filter(|i| !i.stopping)
        .cloned()
        .collect();
    let (cur, old): (Vec<&Instance>, Vec<&Instance>) =
        active.iter().partition(|i| i.release == version);
    // Wrong region counts like a draining machine: replaced, then stopped.
    let misplaced = |i: &Instance| evacuating(s, live, i.machine) || !region_ok(s, &cfg, i.machine);
    let base: Vec<&Instance> = cur
        .iter()
        .copied()
        .filter(|i| !misplaced(i) && i.replaces.is_none())
        .collect();
    let evac: Vec<&Instance> = cur.iter().copied().filter(|i| misplaced(i)).collect();
    let base_healthy = base.iter().filter(|i| live.healthy(i)).count();
    let base_pending = base.len() - base_healthy;
    // UDP apps hold their port on the machine: the old instance stops before
    // the new one starts in its place.
    let is_direct = direct(&cfg);
    let rolling_cfg = cfg.deploy.rolling() && !is_direct;
    let rolling = rolling_cfg && (!old.is_empty() || !evac.is_empty());
    if is_direct {
        // Remember where it runs (before stopping anything).
        let homes: Vec<u32> = active
            .iter()
            .filter(|i| region_ok(s, &cfg, i.machine) && !evacuating(s, live, i.machine))
            .map(|i| i.machine)
            .collect();
        if !homes.is_empty() {
            cx.mem.homes.insert(app.to_string(), homes);
        }
        for i in &old {
            stop(s, &i.id, now);
        }
    }

    // Scale up / replace.
    if base.len() < target {
        let need = target - base.len();
        let n = if rolling {
            let surge = (target / 4).max(1);
            surge.saturating_sub(base_pending).min(need)
        } else {
            need
        };
        let homes = cx.mem.homes.get(app).cloned().unwrap_or_default();
        let mut taken: Vec<u32> = vec![];
        for _ in 0..n {
            // UDP apps go back to the machine they ran on (same IP for
            // players); wait while the old instance there is still stopping.
            if is_direct {
                let home = homes.iter().copied().find(|h| {
                    !taken.contains(h)
                        && schedulable(s, live, *h)
                        && region_ok(s, &cfg, *h)
                        && !s.instances_of(app).any(|i| i.machine == *h && !i.stopping)
                        && !udp_conflict(s, app, &cfg, *h)
                });
                if let Some(h) = home {
                    taken.push(h);
                    if s.instances_of(app).any(|i| i.machine == h) {
                        continue; // still stopping: next pass
                    }
                    create(s, app, version, h, now);
                    continue;
                }
            }
            match place(s, live, app, &cfg, &taken) {
                Some(m) => {
                    taken.push(m);
                    create(s, app, version, m, now);
                }
                None => {
                    let why = if !cfg.regions.is_empty()
                        && !s.machines.keys().any(|m| schedulable(s, live, *m) && region_ok(s, &cfg, *m))
                    {
                        format!(
                            "{app}: no ready machine in region {} (add one with `latrix machine create --region {}`, or the autopilot buys one)",
                            regions_text(&cfg),
                            cfg.regions[0]
                        )
                    } else if is_direct {
                        format!("{app}: every machine that could run it already runs it (UDP apps run one instance per machine)")
                    } else {
                        format!("{app}: no machine available to run another instance")
                    };
                    cx.warn_once(&format!("cap-{app}-{version}"), why);
                    break;
                }
            }
        }
    } else if base.len() > target {
        // Scale down: unhealthy first, then the busiest machine, then newest.
        let mut victims: Vec<&Instance> = base.clone();
        victims.sort_by(|x, y| {
            let hx = live.healthy(x) as u8;
            let hy = live.healthy(y) as u8;
            hx.cmp(&hy)
                .then(s.reserved_mb(y.machine).cmp(&s.reserved_mb(x.machine)))
                .then(y.created_at.cmp(&x.created_at))
        });
        let ids: Vec<String> = victims
            .iter()
            .take(base.len() - target)
            .map(|i| i.id.clone())
            .collect();
        for id in ids {
            stop(s, &id, now);
        }
    }

    // Retire old releases as new instances become healthy.
    if !old.is_empty() {
        let keep_old = if rolling_cfg {
            target.saturating_sub(base_healthy)
        } else {
            0
        };
        let mut old_sorted = old.clone();
        old_sorted.sort_by_key(|i| live.healthy(i)); // unhealthy first
        let excess = old_sorted.len().saturating_sub(keep_old);
        let ids: Vec<String> = old_sorted.iter().take(excess).map(|i| i.id.clone()).collect();
        for id in ids {
            stop(s, &id, now);
        }
    }

    // Instances on draining/suspect machines go away once replacements are healthy.
    if !evac.is_empty() && base_healthy >= target {
        let ids: Vec<String> = evac.iter().map(|i| i.id.clone()).collect();
        for id in ids {
            stop(s, &id, now);
        }
    }
}

fn reconcile_stateful(s: &mut ClusterState, app: &str, cx: &mut Ctx) {
    let live = cx.live;
    let now = live.now;
    let vols: Vec<Volume> = s.volumes_of(app).cloned().collect();
    if vols.is_empty() {
        return;
    }
    let primary = vols[0].primary;
    let vol_ids: Vec<String> = vols.iter().map(|v| v.id.clone()).collect();

    // --- planned move in progress -------------------------------------------
    if let Some(target) = vols[0].moving_to {
        let since = vols[0].moving_since;
        let since_version = vols[0].moving_version;
        let remaining: Vec<String> = s
            .instances_of(app)
            .filter(|i| i.machine == primary)
            .map(|i| i.id.clone())
            .collect();
        for id in &remaining {
            stop(s, id, now);
        }
        let primary_dead = live.dead_for(primary) >= LOST_AFTER;
        let final_synced = vol_ids.iter().all(|v| {
            live.vol(primary, v)
                .map(|r| {
                    r.idle_synced_version >= since_version
                        && r.synced_version.get(&target).copied().unwrap_or(0) >= since_version
                })
                .unwrap_or(false)
        });
        let timed_out = now.saturating_sub(since) > 300;
        if remaining.is_empty() && (final_synced || primary_dead || timed_out) {
            for v in &vol_ids {
                let vol = s.volumes.get_mut(v).unwrap();
                vol.replicas.retain(|r| *r != target);
                if !vol.replicas.contains(&primary) {
                    vol.replicas.push(primary);
                }
                vol.primary = target;
                vol.moving_to = None;
            }
            if final_synced {
                cx.info(format!(
                    "{app}: volumes moved to {} (final sync complete, no data lost)",
                    machine_name(s, target)
                ));
            } else {
                cx.warn(format!(
                    "{app}: volumes moved to {} without a final sync (last periodic copy used)",
                    machine_name(s, target)
                ));
            }
        }
        return;
    }

    // --- unplanned failover ---------------------------------------------------
    if live.dead_for(primary) >= FAILOVER_AFTER || !s.machines.contains_key(&primary) {
        let best = best_replica(s, live, &vols, primary, false);
        match best {
            Some(c) => {
                for v in &vol_ids {
                    let vol = s.volumes.get_mut(v).unwrap();
                    vol.replicas.retain(|r| *r != c);
                    if s.machines.contains_key(&primary) && !vol.replicas.contains(&primary) {
                        vol.replicas.push(primary);
                    }
                    vol.primary = c;
                }
                let ids: Vec<String> = s.instances_of(app).map(|i| i.id.clone()).collect();
                for id in ids {
                    stop(s, &id, now);
                }
                cx.warn(format!(
                    "{app}: machine {} is down — failed over to replica on {}",
                    machine_name(s, primary),
                    machine_name(s, c)
                ));
            }
            None => cx.warn_once(
                &format!("failover-{app}"),
                format!("{app}: volume primary {} is down and no synced replica is available", machine_name(s, primary)),
            ),
        }
        return;
    }

    // --- planned evacuation (drain / maintenance) -----------------------------
    let primary_status = s.machines.get(&primary).map(|m| m.status);
    let cfg = s.apps.get(app).and_then(|a| a.config()).cloned();
    let wrong_region = cfg.as_ref().map(|c| !region_ok(s, c, primary)).unwrap_or(false);
    let leaving = matches!(primary_status, Some(MachineStatus::Draining) | Some(MachineStatus::Maintenance));
    if leaving || wrong_region {
        let t = best_replica(s, live, &vols, primary, true)
            .filter(|t| leaving || cfg.as_ref().map(|c| region_ok(s, c, *t)).unwrap_or(true));
        if let Some(t) = t {
            for v in &vol_ids {
                let vol = s.volumes.get_mut(v).unwrap();
                vol.moving_to = Some(t);
                vol.moving_since = now;
                vol.moving_version = s.version + 1;
            }
            let ids: Vec<String> = s.instances_of(app).map(|i| i.id.clone()).collect();
            for id in ids {
                stop(s, &id, now);
            }
            cx.info(format!(
                "{app}: moving to {} (stopping, final volume sync, then restart there)",
                machine_name(s, t)
            ));
            return;
        }
        // No replica to move to: keep running where it is.
    }

    if !track_release(s, app, cx) {
        return;
    }
    let a = &s.apps[app];
    let version = a.current;
    let target = a.count.min(1);
    let all: Vec<Instance> = s.instances_of(app).cloned().collect();
    let active: Vec<&Instance> = all.iter().filter(|i| !i.stopping).collect();

    // Wrong release or wrong machine: stop (single writer — never overlap).
    let mut stopped_any = false;
    for i in &active {
        if i.release != version || i.machine != primary || target == 0 {
            stop(s, &i.id, now);
            stopped_any = true;
        }
    }
    if stopped_any {
        return;
    }
    if all.is_empty() && target == 1 {
        let ok = s
            .machines
            .get(&primary)
            .map(|m| m.status != MachineStatus::Maintenance)
            .unwrap_or(false)
            && live.is_alive(primary);
        if ok {
            create(s, app, version, primary, now);
        }
    }
}

/// Pick the replica to promote. `planned` requires the target to be schedulable
/// and to have received at least one sync.
fn best_replica(
    s: &ClusterState,
    live: &LiveView,
    vols: &[Volume],
    primary: u32,
    planned: bool,
) -> Option<u32> {
    // Machines in the app's regions first.
    let cfg = s.apps.get(&vols[0].app).and_then(|a| a.config());
    if let Some(c) = cfg.filter(|c| !c.regions.is_empty()) {
        if let Some(r) = best_replica_where(s, live, vols, primary, planned, &|m| region_ok(s, c, m)) {
            return Some(r);
        }
    }
    best_replica_where(s, live, vols, primary, planned, &|_| true)
}

fn best_replica_where(
    s: &ClusterState,
    live: &LiveView,
    vols: &[Volume],
    primary: u32,
    planned: bool,
    ok: &dyn Fn(u32) -> bool,
) -> Option<u32> {
    let replicas = &vols[0].replicas;
    let mut best: Option<(u64, u32)> = None;
    for r in replicas {
        if !schedulable(s, live, *r) || !ok(*r) {
            continue;
        }
        // Oldest sync across all of the app's volumes for this replica.
        let synced = vols
            .iter()
            .map(|v| {
                live.vol(primary, &v.id)
                    .and_then(|x| x.synced.get(r).copied())
                    .unwrap_or(0)
            })
            .min()
            .unwrap_or(0);
        if planned && synced == 0 {
            continue;
        }
        if best.map(|(b, _)| synced > b).unwrap_or(true) {
            best = Some((synced, *r));
        }
    }
    best.map(|(_, r)| r)
}

fn maintain_replicas(s: &mut ClusterState, cx: &mut Ctx) {
    let live = cx.live;
    let ids: Vec<String> = s.volumes.keys().cloned().collect();
    // Volumes of the same app share replica machines.
    let mut chosen_for_app: HashMap<String, Vec<u32>> = HashMap::new();
    for id in ids {
        let vol = s.volumes[&id].clone();
        if vol.moving_to.is_some() {
            continue;
        }
        let cfg = s.apps.get(&vol.app).and_then(|a| a.config()).cloned();
        let allowed = |m: u32| cfg.as_ref().map(|c| region_ok(s, c, m)).unwrap_or(true);
        // Pinned to a region but stored elsewhere: keep (at least) one copy
        // in the region so the app can move there.
        let need_home = !allowed(vol.primary);
        let base_want = vol.copies.saturating_sub(1) as usize;
        let want = if need_home { base_want.max(1) } else { base_want };
        let mut replicas: Vec<u32> = vol
            .replicas
            .iter()
            .copied()
            .filter(|r| *r != vol.primary && s.machines.contains_key(r))
            .filter(|r| live.dead_for(*r) < REPLICA_REPLACE_AFTER)
            .collect();
        replicas.dedup();
        if let Some(shared) = chosen_for_app.get(&vol.app) {
            for m in shared {
                if !replicas.contains(m) && *m != vol.primary && replicas.len() < want {
                    replicas.push(*m);
                }
            }
        }
        let has_home = replicas.iter().any(|r| allowed(*r) && schedulable(s, live, *r));
        if need_home && !has_home && replicas.len() >= want {
            let free_home = s
                .machines
                .values()
                .any(|m| m.id != vol.primary && !replicas.contains(&m.id) && allowed(m.id) && schedulable(s, live, m.id));
            if free_home {
                replicas.pop(); // make room for a copy in the app's region
            }
        }
        while replicas.len() < want {
            let cand = s
                .machines
                .values()
                .filter(|m| m.id != vol.primary && !replicas.contains(&m.id))
                .filter(|m| schedulable(s, live, m.id))
                .max_by(|a, b| {
                    let fa = (allowed(a.id), free_disk(live, a.id));
                    let fb = (allowed(b.id), free_disk(live, b.id));
                    fa.partial_cmp(&fb).unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|m| m.id);
            match cand {
                Some(c) => {
                    cx.info(format!(
                        "{}: adding replica of volume '{}' on {}",
                        vol.app,
                        vol.name,
                        machine_name(s, c)
                    ));
                    replicas.push(c);
                }
                None => break,
            }
        }
        replicas.truncate(want);
        chosen_for_app.insert(vol.app.clone(), replicas.clone());
        if replicas != vol.replicas {
            s.volumes.get_mut(&id).unwrap().replicas = replicas;
        }
    }
}

fn free_disk(live: &LiveView, m: u32) -> f64 {
    live.metrics(m)
        .map(|x| x.disk_total_gb - x.disk_used_gb)
        .unwrap_or(0.0)
}

/// A machine counts as drained when nothing on it can still be moved elsewhere.
pub fn drained(s: &ClusterState, live: &LiveView, m: u32) -> bool {
    for i in s.instances_on(m) {
        if i.stopping {
            return false;
        }
        let Some(app) = s.apps.get(&i.app) else { continue };
        let Some(cfg) = app.config() else { continue };
        let movable = if cfg.stateful() {
            let vols: Vec<Volume> = s.volumes_of(&i.app).cloned().collect();
            !vols.is_empty() && best_replica(s, live, &vols, m, true).is_some()
        } else {
            s.machines.keys().any(|o| {
                *o != m
                    && schedulable(s, live, *o)
                    && region_ok(s, cfg, *o)
                    && !(direct(cfg) && s.instances_of(&i.app).any(|x| x.machine == *o && !x.stopping))
            })
        };
        if movable {
            return false;
        }
    }
    true
}

pub fn in_window(window: &str, now: u64) -> bool {
    let w = window.trim();
    if w.is_empty() {
        return true;
    }
    let parse = |t: &str| -> Option<u64> {
        let (h, m) = t.trim().split_once(':')?;
        Some(h.parse::<u64>().ok()? * 60 + m.parse::<u64>().ok()?)
    };
    let Some((a, b)) = w.split_once('-') else { return true };
    let (Some(start), Some(end)) = (parse(a), parse(b)) else { return true };
    let minute = (now % 86400) / 60;
    if start <= end {
        minute >= start && minute < end
    } else {
        minute >= start || minute < end
    }
}

fn orchestrate_maintenance(s: &mut ClusterState, cx: &mut Ctx) {
    let live = cx.live;
    let now = live.now;
    let ids: Vec<u32> = s.machines.keys().copied().collect();
    for id in &ids {
        let m = s.machines[id].clone();
        match m.status {
            MachineStatus::Draining => {
                if drained(s, live, *id) {
                    let kind = m.maintenance.as_ref().map(|t| t.kind.clone()).unwrap_or_default();
                    let mm = s.machines.get_mut(id).unwrap();
                    if kind == "updates" {
                        mm.status = MachineStatus::Maintenance;
                        let stuck = s.instances_on(*id).filter(|i| !i.stopping).count();
                        if stuck > 0 {
                            cx.warn(format!(
                                "{}: {} instance(s) cannot move anywhere and will be briefly down during updates",
                                m.name, stuck
                            ));
                        }
                        cx.info(format!("{}: drained, installing OS updates", m.name));
                    } else if kind == "remove" {
                        // The autopilot deletes it next (keeps the task as a marker).
                        mm.status = MachineStatus::Cordoned;
                        cx.info(format!("{}: drained, ready to be removed", m.name));
                    } else {
                        mm.status = MachineStatus::Cordoned;
                        mm.maintenance = None;
                        cx.info(format!("{}: drained (cordoned — run `latrix machine uncordon {}` to reuse)", m.name, m.name));
                    }
                }
            }
            MachineStatus::Maintenance => {
                let task = m.maintenance.clone();
                let done = live
                    .reports
                    .get(id)
                    .and_then(|r| r.maintenance_done.clone());
                let finished = match (&task, &done) {
                    (Some(t), Some(d)) => &t.id == d,
                    (None, _) => true,
                    _ => false,
                };
                let started = task.as_ref().map(|t| t.started_at).unwrap_or(0);
                if finished && live.alive.contains(id) {
                    let mm = s.machines.get_mut(id).unwrap();
                    mm.status = MachineStatus::Ready;
                    mm.maintenance = None;
                    mm.last_maintenance = now;
                    cx.info(format!("{}: maintenance finished, machine is back in rotation", m.name));
                } else if now.saturating_sub(started) > 7200 && live.alive.contains(id) {
                    let mm = s.machines.get_mut(id).unwrap();
                    mm.status = MachineStatus::Ready;
                    mm.maintenance = None;
                    mm.last_maintenance = now;
                    cx.warn(format!("{}: maintenance did not report completion within 2h; returning it to service", m.name));
                } else if now.saturating_sub(started) > 1800 && !live.alive.contains(id) {
                    cx.warn_once(
                        &format!("maint-{id}"),
                        format!("{}: has not come back from maintenance after 30 minutes", m.name),
                    );
                }
            }
            _ => {}
        }
    }

    // A temporary server for maintenance is in progress: drive it.
    if let Some(sg) = s.surge.clone() {
        drive_surge(s, cx, sg);
        return;
    }

    // Automatic OS updates: one machine at a time, inside the window.
    if !s.settings.auto_updates || live.grace() || !in_window(&s.settings.update_window, now) {
        return;
    }
    let busy = s
        .machines
        .values()
        .any(|m| matches!(m.status, MachineStatus::Draining | MachineStatus::Maintenance));
    if busy {
        return;
    }
    // Don't start maintenance while a deploy is rolling out.
    let deploying = s.apps.values().any(|a| {
        a.current_release()
            .map(|r| r.status == ReleaseStatus::Deploying)
            .unwrap_or(false)
    });
    if deploying {
        return;
    }
    let cand = s
        .machines
        .values()
        .filter(|m| m.status == MachineStatus::Ready && live.alive.contains(&m.id) && !m.temporary)
        .filter(|m| now.saturating_sub(m.last_maintenance) > 20 * 3600)
        .filter(|m| {
            live.reports
                .get(&m.id)
                .map(|r| r.updates.checked_at > 0 && (r.updates.pending > 0 || r.updates.reboot_required))
                .unwrap_or(false)
        })
        .min_by_key(|m| m.last_maintenance)
        .map(|m| m.id);
    if let Some(id) = cand {
        let pending = live.reports.get(&id).map(|r| r.updates.pending).unwrap_or(0);
        if !can_absorb(s, live, id) && surge_possible(s) {
            s.surge = Some(Surge { for_machine: id, requested_at: now, temp_machine: None, phase: "buying".into() });
            cx.info(format!(
                "{}: {pending} OS update(s) pending and no other machine can take its apps — buying a temporary server first",
                machine_name(s, id)
            ));
            return;
        }
        start_maintenance(s, id, now);
        cx.info(format!(
            "{}: {pending} OS update(s) pending — draining for automatic maintenance",
            machine_name(s, id)
        ));
    }
}

pub fn start_maintenance(s: &mut ClusterState, id: u32, now: u64) {
    if let Some(mm) = s.machines.get_mut(&id) {
        mm.status = MachineStatus::Draining;
        mm.maintenance = Some(MaintenanceTask { id: random_id(8), kind: "updates".into(), started_at: now });
    }
}

/// The autopilot can buy servers (on, with a provider token).
pub fn surge_possible(s: &ClusterState) -> bool {
    s.settings.autopilot && !s.provider_tokens.is_empty()
}

/// Could the other machines take everything running on `m`?
pub fn can_absorb(s: &ClusterState, live: &LiveView, m: u32) -> bool {
    let need = s.reserved_mb(m) as f64;
    if s.instances_on(m).all(|i| i.stopping) {
        return true;
    }
    let others: Vec<&Machine> = s
        .machines
        .values()
        .filter(|o| o.id != m && schedulable(s, live, o.id))
        .collect();
    if others.is_empty() {
        return false;
    }
    // Apps pinned to a region need another machine there.
    for i in s.instances_on(m).filter(|i| !i.stopping) {
        let Some(cfg) = s.apps.get(&i.app).and_then(|a| a.config()) else { continue };
        if cfg.stateful() {
            continue; // they wait for / move to their replica
        }
        let fits = others.iter().any(|o| {
            region_ok(s, cfg, o.id) && !(direct(cfg) && s.instances_of(&i.app).any(|x| x.machine == o.id && !x.stopping))
        });
        if !fits {
            return false;
        }
    }
    let free: f64 = others
        .iter()
        .map(|o| {
            let total = live.metrics(o.id).map(|x| x.mem_total_mb).filter(|x| *x > 0).unwrap_or(o.memory_mb) as f64;
            (total * 0.9 - s.reserved_mb(o.id) as f64).max(0.0)
        })
        .sum();
    need <= free
}

/// Step a "temporary server for maintenance" forward.
fn drive_surge(s: &mut ClusterState, cx: &mut Ctx, sg: Surge) {
    let live = cx.live;
    let now = live.now;
    let target = sg.for_machine;
    let mut next = sg.clone();
    match sg.phase.as_str() {
        "buying" => {
            if now.saturating_sub(sg.requested_at) > 45 * 60 {
                next.phase = "failed".into();
                cx.warn("temporary server didn't arrive in time; updating in place instead");
            }
        }
        "ready" => {
            let temp_ok = sg.temp_machine.map(|t| schedulable(s, live, t)).unwrap_or(false);
            let target_ready = s.machines.get(&target).map(|m| m.status == MachineStatus::Ready).unwrap_or(false);
            if !s.machines.contains_key(&target) {
                next.phase = "maintaining".into();
            } else if temp_ok && target_ready {
                start_maintenance(s, target, now);
                next.phase = "maintaining".into();
                cx.info(format!("{}: moving apps to the temporary server, then installing updates", machine_name(s, target)));
            } else if now.saturating_sub(sg.requested_at) > 60 * 60 {
                next.phase = "failed".into();
                cx.warn("temporary server never became ready; updating in place instead");
            }
        }
        "maintaining" => {
            let back = s
                .machines
                .get(&target)
                .map(|m| m.status == MachineStatus::Ready && m.maintenance.is_none())
                .unwrap_or(true);
            if back {
                if let Some(t) = sg.temp_machine.and_then(|t| s.machines.get_mut(&t)) {
                    t.status = MachineStatus::Draining;
                    t.maintenance = Some(MaintenanceTask { id: random_id(8), kind: "remove".into(), started_at: now });
                }
                next.phase = "returning".into();
                cx.info(format!("{} is updated; moving apps back and removing the temporary server", machine_name(s, target)));
            }
        }
        "returning" => {
            if sg.temp_machine.map(|t| !s.machines.contains_key(&t)).unwrap_or(true) {
                s.surge = None;
                cx.info("temporary server removed; maintenance complete");
                return;
            }
        }
        _ => {
            // failed: update in place (with a short interruption), remove any temp server
            if let Some(t) = sg.temp_machine.and_then(|t| s.machines.get_mut(&t)) {
                if t.maintenance.is_none() {
                    t.status = MachineStatus::Draining;
                    t.maintenance = Some(MaintenanceTask { id: random_id(8), kind: "remove".into(), started_at: now });
                }
            }
            if s.machines.get(&target).map(|m| m.status == MachineStatus::Ready).unwrap_or(false) {
                start_maintenance(s, target, now);
            }
            s.surge = None;
            return;
        }
    }
    s.surge = Some(next);
}

fn load(s: &ClusterState, live: &LiveView, m: &Machine) -> f64 {
    let met = live.metrics(m.id);
    let mem_total = met
        .map(|x| x.mem_total_mb)
        .filter(|x| *x > 0)
        .unwrap_or(m.memory_mb.max(1024)) as f64;
    let cpus = met.map(|x| x.cpus).filter(|x| *x > 0.0).unwrap_or(m.cpus.max(1.0));
    let mem = s.reserved_mb(m.id) as f64 / mem_total;
    let cpu = s.reserved_cpu(m.id) / cpus;
    let actual = met.map(|x| x.cpu_pct / 100.0).unwrap_or(0.0);
    mem.max(cpu).max(actual * 0.8)
}

fn rebalance(s: &mut ClusterState, cx: &mut Ctx) {
    let live = cx.live;
    let now = live.now;
    // Only when the cluster is calm.
    let calm = !s.instances.values().any(|i| i.stopping || i.replaces.is_some())
        && !s.machines.values().any(|m| m.status != MachineStatus::Ready && m.status != MachineStatus::Cordoned)
        && !s.apps.values().any(|a| {
            a.current_release()
                .map(|r| r.status == ReleaseStatus::Deploying)
                .unwrap_or(true)
        });
    if !calm {
        return;
    }
    let ready: Vec<Machine> = s
        .machines
        .values()
        .filter(|m| schedulable(s, live, m.id))
        .cloned()
        .collect();
    if ready.len() < 2 {
        return;
    }

    // 1) Spread: an app with two instances on one machine while another
    //    ready machine runs none of it.
    for (name, app) in s.apps.clone() {
        let Some(cfg) = app.config() else { continue };
        if cfg.stateful() || direct(cfg) {
            continue;
        }
        let insts: Vec<Instance> = s.instances_of(&name).filter(|i| !i.stopping).cloned().collect();
        let mut per: HashMap<u32, Vec<&Instance>> = HashMap::new();
        for i in &insts {
            per.entry(i.machine).or_default().push(i);
        }
        let crowded = per.iter().filter(|(_, v)| v.len() >= 2).max_by_key(|(_, v)| v.len());
        let has_empty = ready.iter().any(|m| !per.contains_key(&m.id) && region_ok(s, cfg, m.id));
        if let (Some((_, v)), true) = (crowded, has_empty) {
            let Some(victim) = v.iter().find(|i| live.healthy(i)).map(|i| (*i).clone()) else { continue };
            let exclude: Vec<u32> = per.keys().copied().collect();
            if let Some(t) = place(s, live, &name, cfg, &exclude) {
                let id = create(s, &name, victim.release, t, now);
                s.instances.get_mut(&id).unwrap().replaces = Some(victim.id.clone());
                cx.info(format!(
                    "{name}: spreading instance from {} to {}",
                    machine_name(s, victim.machine),
                    machine_name(s, t)
                ));
                return;
            }
        }
    }

    // 2) Load: move one instance from the busiest to the least busy machine.
    let mut loads: Vec<(f64, u32)> = ready.iter().map(|m| (load(s, live, m), m.id)).collect();
    loads.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let (lo, lo_id) = loads[0];
    let (hi, hi_id) = *loads.last().unwrap();
    if hi - lo < 0.25 {
        return;
    }
    let candidates: Vec<Instance> = s
        .instances_on(hi_id)
        .filter(|i| {
            s.apps
                .get(&i.app)
                .and_then(|a| a.config())
                .map(|c| !c.stateful() && !direct(c) && region_ok(s, c, lo_id))
                .unwrap_or(false)
        })
        .filter(|i| !i.stopping && i.replaces.is_none() && live.healthy(i))
        .filter(|i| {
            // don't stack two of the same app on the target
            !s.instances_of(&i.app).any(|o| o.machine == lo_id)
        })
        .cloned()
        .collect();
    // Pick the instance whose size best halves the gap.
    let gap_mb = {
        let m = &s.machines[&hi_id];
        let total = live
            .metrics(hi_id)
            .map(|x| x.mem_total_mb)
            .filter(|x| *x > 0)
            .unwrap_or(m.memory_mb.max(1024)) as f64;
        (hi - lo) / 2.0 * total
    };
    let pick = candidates.into_iter().min_by(|a, b| {
        let sa = inst_mb(s, a) as f64;
        let sb = inst_mb(s, b) as f64;
        (sa - gap_mb).abs().partial_cmp(&(sb - gap_mb).abs()).unwrap_or(std::cmp::Ordering::Equal)
    });
    if let Some(victim) = pick {
        let id = create(s, &victim.app, victim.release, lo_id, now);
        s.instances.get_mut(&id).unwrap().replaces = Some(victim.id.clone());
        cx.info(format!(
            "{}: rebalancing instance from {} ({:.0}% load) to {} ({:.0}% load)",
            victim.app,
            machine_name(s, hi_id),
            hi * 100.0,
            machine_name(s, lo_id),
            lo * 100.0
        ));
    }
}

fn inst_mb(s: &ClusterState, i: &Instance) -> u64 {
    s.apps
        .get(&i.app)
        .and_then(|a| a.release(i.release))
        .map(|r| r.config.scale.memory_mb())
        .unwrap_or(0)
}

fn autoscale(s: &mut ClusterState, cx: &mut Ctx) {
    let live = cx.live;
    let names: Vec<String> = s.apps.keys().cloned().collect();
    for name in names {
        let app = &s.apps[&name];
        let Some(cfg) = app.config() else { continue };
        if !cfg.scale.autoscale() {
            continue;
        }
        let (min, max) = cfg.scale.bounds();
        let cpu_limit = if cfg.scale.cpu > 0.0 { cfg.scale.cpu } else { 1.0 };
        let mem_limit = cfg.scale.memory_mb().max(1) as f64;
        let reports: Vec<&InstanceReport> = s
            .instances_of(&name)
            .filter(|i| !i.stopping && i.release == app.current)
            .filter_map(|i| live.inst(i))
            .filter(|r| r.healthy)
            .collect();
        if reports.is_empty() {
            continue;
        }
        let n = reports.len() as f64;
        let cpu = reports.iter().map(|r| r.cpu_pct / 100.0 / cpu_limit).sum::<f64>() / n;
        let mem = reports.iter().map(|r| r.mem_mb / mem_limit).sum::<f64>() / n;
        let util = cpu.max(mem * 0.85);
        let up = cx.mem.up_streak.entry(name.clone()).or_default();
        if util > 0.75 {
            *up += 1;
        } else {
            *up = 0;
        }
        let up_n = *up;
        let down = cx.mem.down_streak.entry(name.clone()).or_default();
        if util < 0.25 {
            *down += 1;
        } else {
            *down = 0;
        }
        let down_n = *down;
        let count = app.count;
        if up_n >= 2 && count < max {
            s.apps.get_mut(&name).unwrap().count = count + 1;
            cx.mem.up_streak.insert(name.clone(), 0);
            cx.info(format!(
                "{name}: autoscaled up to {} (utilization {:.0}%)",
                count + 1,
                util * 100.0
            ));
        } else if down_n >= 10 && count > min {
            s.apps.get_mut(&name).unwrap().count = count - 1;
            cx.mem.down_streak.insert(name.clone(), 0);
            cx.info(format!(
                "{name}: autoscaled down to {} (utilization {:.0}%)",
                count - 1,
                util * 100.0
            ));
        }
    }
}

/// Build the routing table every proxy uses.
pub fn compute_routes(s: &ClusterState, live: &LiveView) -> Routes {
    let mut routes = Routes::default();
    for (name, app) in &s.apps {
        let Some(cfg) = app.config() else { continue };
        let mut hosts: Vec<String> = cfg
            .http
            .iter()
            .flat_map(|h| h.domains.iter().cloned())
            .collect();
        if !s.settings.base_domain.is_empty() {
            hosts.push(format!("{}.{}", name, s.settings.base_domain));
        }
        let backends: Vec<Backend> = s
            .instances_of(name)
            .filter(|i| !i.stopping)
            .filter_map(|i| {
                let r = live.inst(i)?;
                // Stale "healthy" reports from a machine that stopped answering don't count.
                if !r.healthy || !live.is_alive(i.machine) {
                    return None;
                }
                let m = s.machines.get(&i.machine)?;
                Some(Backend {
                    instance: i.id.clone(),
                    machine: i.machine,
                    ip: m.overlay_ip.clone(),
                    ports: r.ports.clone(),
                })
            })
            .collect();
        // Internal ports: configured ones plus whatever the image EXPOSEs
        // (agents publish those too), so `postgres` works without config.
        let mut ports = cfg.container_ports();
        for b in &backends {
            for p in b.ports.keys() {
                if !ports.contains(p) {
                    ports.push(*p);
                }
            }
        }
        ports.sort();
        routes.dns.insert(format!("{name}.internal"), app.vip.clone());
        if let Some(g) = &cfg.group {
            routes
                .dns
                .insert(format!("{}.{}.internal", cfg.service_name(), g), app.vip.clone());
        }
        routes.apps.insert(
            name.clone(),
            AppRoute {
                app: name.clone(),
                vip: app.vip.clone(),
                hosts,
                http_port: cfg.http.as_ref().map(|h| h.port),
                force_https: cfg.http.as_ref().and_then(|h| h.force_https).unwrap_or(true),
                ports,
                public_ports: cfg
                    .ports
                    .iter()
                    .filter(|p| p.public && p.protocol == "tcp")
                    .map(|p| (p.public_port.unwrap_or(p.port), p.port))
                    .collect(),
                backends,
            },
        );
    }
    routes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, VolumeConfig};

    fn machine(id: u32) -> Machine {
        Machine {
            id,
            name: format!("m{id}"),
            public_ip: format!("1.1.1.{id}"),
            overlay_ip: format!("10.77.0.{id}"),
            wg_pubkey: String::new(),
            os: "ubuntu".into(),
            arch: "x86_64".into(),
            cpus: 4.0,
            memory_mb: 8192,
            region: None,
            provider: None,
            monthly_cost: None,
            status: MachineStatus::Ready,
            joined_at: 0,
            maintenance: None,
            last_maintenance: 0,
            temporary: false,
        }
    }

    fn app(s: &mut ClusterState, name: &str, count: u32, stateful: bool) {
        let mut cfg: AppConfig = toml::from_str(&format!("app = \"{name}\"\n[http]\nport = 80\n")).unwrap();
        cfg.scale.count = Some(count);
        if stateful {
            cfg.volumes.push(VolumeConfig {
                name: "data".into(),
                path: "/data".into(),
                copies: 2,
                sync: "30s".into(),
                pre_sync: None,
                size: None,
            });
            s.volumes.insert(
                format!("{name}__data"),
                Volume {
                    id: format!("{name}__data"),
                    app: name.into(),
                    name: "data".into(),
                    path: "/data".into(),
                    primary: 1,
                    replicas: vec![],
                    copies: 2,
                    sync_secs: 30,
                    created_at: 0,
                    moving_to: None,
                    moving_since: 0,
                    moving_version: 0,
                },
            );
        }
        s.apps.insert(
            name.into(),
            App {
                name: name.into(),
                vip: "10.78.0.1".into(),
                current: 1,
                releases: vec![Release {
                    version: 1,
                    image: "img".into(),
                    config: cfg,
                    created_at: 0,
                    status: ReleaseStatus::Deploying,
                    sources: vec![],
                    description: String::new(),
                }],
                secrets: Default::default(),
                count,
                created_at: 0,
                last_builder: None,
            },
        );
    }

    struct World {
        s: ClusterState,
        alive: HashSet<u32>,
        dead_since: HashMap<u32, u64>,
        reports: HashMap<u32, NodeReport>,
        now: u64,
        mem: SchedMemory,
    }

    impl World {
        fn new(n: u32) -> World {
            let mut s = ClusterState::default();
            for i in 1..=n {
                s.machines.insert(i, machine(i));
            }
            World {
                s,
                alive: (1..=n).collect(),
                dead_since: HashMap::new(),
                reports: HashMap::new(),
                now: 1000,
                mem: SchedMemory::default(),
            }
        }
        /// Simulate agents: every instance assigned to an alive machine runs
        /// and is healthy; stopped ones disappear.
        fn agents(&mut self) {
            self.reports.clear();
            for m in self.s.machines.keys() {
                if !self.alive.contains(m) {
                    continue;
                }
                let mut r = NodeReport {
                    machine: *m,
                    docker_ok: true,
                    ..Default::default()
                };
                r.metrics.cpus = 4.0;
                r.metrics.mem_total_mb = 8192;
                for i in self.s.instances_on(*m) {
                    if i.stopping {
                        continue;
                    }
                    r.instances.push(InstanceReport {
                        id: i.id.clone(),
                        status: "running".into(),
                        healthy: true,
                        ..Default::default()
                    });
                }
                for v in self.s.volumes.values().filter(|v| v.primary == *m) {
                    let running = self.s.instances_of(&v.app).any(|i| i.machine == *m && !i.stopping);
                    r.volumes.push(VolumeReport {
                        id: v.id.clone(),
                        synced: v.replicas.iter().map(|x| (*x, self.now)).collect(),
                        synced_version: v.replicas.iter().map(|x| (*x, self.s.version)).collect(),
                        idle_synced_at: if running { 0 } else { self.now },
                        idle_synced_version: if running { 0 } else { self.s.version },
                        ..Default::default()
                    });
                }
                self.reports.insert(*m, r);
            }
        }
        fn tick(&mut self) -> Vec<Event> {
            self.agents();
            let live = LiveView {
                now: self.now,
                alive: &self.alive,
                dead_since: &self.dead_since,
                reports: &self.reports,
                leader_for: 1000,
            };
            let ev = reconcile(&mut self.s, &live, &mut self.mem);
            self.s.version += 1; // simulate the commit
            self.now += 5;
            ev
        }
        fn run(&mut self, n: usize) {
            for _ in 0..n {
                self.tick();
            }
        }
        fn kill(&mut self, m: u32) {
            self.alive.remove(&m);
            self.dead_since.insert(m, self.now);
        }
        fn active(&self, app: &str) -> Vec<&Instance> {
            self.s.instances.values().filter(|i| i.app == app && !i.stopping).collect()
        }
    }

    #[test]
    fn spreads_instances_across_machines() {
        let mut w = World::new(3);
        app(&mut w.s, "web", 3, false);
        w.run(3);
        let machines: HashSet<u32> = w.active("web").iter().map(|i| i.machine).collect();
        assert_eq!(w.active("web").len(), 3);
        assert_eq!(machines.len(), 3, "one instance per machine");
        assert_eq!(w.s.apps["web"].releases[0].status, ReleaseStatus::Active);
    }

    #[test]
    fn replaces_instances_on_dead_machine() {
        let mut w = World::new(3);
        app(&mut w.s, "web", 2, false);
        w.run(3);
        let victim = w.active("web")[0].machine;
        w.kill(victim);
        w.run(10);
        let act = w.active("web");
        assert_eq!(act.len(), 2);
        assert!(act.iter().all(|i| i.machine != victim));
    }

    #[test]
    fn rolling_deploy_keeps_capacity() {
        let mut w = World::new(2);
        app(&mut w.s, "web", 2, false);
        w.run(3);
        let mut rel = w.s.apps["web"].releases[0].clone();
        rel.version = 2;
        rel.created_at = w.now;
        rel.status = ReleaseStatus::Deploying;
        let a = w.s.apps.get_mut("web").unwrap();
        a.releases.push(rel);
        a.current = 2;
        for _ in 0..10 {
            w.tick();
            assert!(w.active("web").len() >= 2, "never below desired count");
        }
        assert!(w.active("web").iter().all(|i| i.release == 2));
        assert_eq!(w.active("web").len(), 2);
    }

    #[test]
    fn failed_release_rolls_back() {
        let mut w = World::new(1);
        app(&mut w.s, "web", 1, false);
        w.run(2);
        let mut rel = w.s.apps["web"].releases[0].clone();
        rel.version = 2;
        rel.created_at = w.now;
        rel.status = ReleaseStatus::Deploying;
        let a = w.s.apps.get_mut("web").unwrap();
        a.releases.push(rel);
        a.current = 2;
        // v2 instances never become healthy
        for _ in 0..40 {
            w.agents();
            for r in w.reports.values_mut() {
                for ir in r.instances.iter_mut() {
                    if w.s.instances.get(&ir.id).map(|i| i.release == 2).unwrap_or(false) {
                        ir.healthy = false;
                    }
                }
            }
            let live = LiveView {
                now: w.now,
                alive: &w.alive,
                dead_since: &w.dead_since,
                reports: &w.reports,
                leader_for: 1000,
            };
            reconcile(&mut w.s, &live, &mut w.mem);
            w.now += 5;
        }
        assert_eq!(w.s.apps["web"].current, 1);
        assert_eq!(w.s.apps["web"].releases[1].status, ReleaseStatus::Failed);
    }

    #[test]
    fn drain_moves_everything_then_maintenance() {
        let mut w = World::new(2);
        app(&mut w.s, "web", 2, false);
        w.run(3);
        let m = w.s.machines.get_mut(&1).unwrap();
        m.status = MachineStatus::Draining;
        m.maintenance = Some(MaintenanceTask {
            id: "t1".into(),
            kind: "updates".into(),
            started_at: w.now,
        });
        w.run(10);
        assert_eq!(w.s.machines[&1].status, MachineStatus::Maintenance);
        assert_eq!(w.active("web").len(), 2);
        assert!(w.active("web").iter().all(|i| i.machine == 2));
        // machine reports completion
        w.agents();
        w.reports.get_mut(&1).unwrap().maintenance_done = Some("t1".into());
        let live = LiveView {
            now: w.now,
            alive: &w.alive,
            dead_since: &w.dead_since,
            reports: &w.reports,
            leader_for: 1000,
        };
        reconcile(&mut w.s, &live, &mut w.mem);
        assert_eq!(w.s.machines[&1].status, MachineStatus::Ready);
        // and the rebalancer spreads the app back out
        w.now += 100;
        w.run(20);
        let machines: HashSet<u32> = w.active("web").iter().map(|i| i.machine).collect();
        assert_eq!(machines.len(), 2, "spread back across both machines");
    }

    #[test]
    fn stateful_app_gets_replica_and_planned_move() {
        let mut w = World::new(2);
        app(&mut w.s, "db", 1, true);
        w.run(3);
        assert_eq!(w.s.volumes["db__data"].replicas, vec![2]);
        assert_eq!(w.active("db")[0].machine, 1);
        w.s.machines.get_mut(&1).unwrap().status = MachineStatus::Draining;
        w.s.machines.get_mut(&1).unwrap().maintenance = Some(MaintenanceTask {
            id: "x".into(),
            kind: "drain".into(),
            started_at: w.now,
        });
        w.run(10);
        assert_eq!(w.s.volumes["db__data"].primary, 2);
        assert_eq!(w.active("db").len(), 1);
        assert_eq!(w.active("db")[0].machine, 2);
        assert_eq!(w.s.machines[&1].status, MachineStatus::Cordoned);
    }

    fn cfg_mut<'a>(w: &'a mut World, app: &str) -> &'a mut AppConfig {
        &mut w.s.apps.get_mut(app).unwrap().releases.last_mut().unwrap().config
    }

    fn regions(w: &mut World, list: &[(u32, &str)]) {
        for (m, r) in list {
            w.s.machines.get_mut(m).unwrap().region = Some(r.to_string());
        }
    }

    fn redeploy(w: &mut World, app: &str) {
        let a = w.s.apps.get_mut(app).unwrap();
        let mut rel = a.releases.last().unwrap().clone();
        rel.version += 1;
        rel.created_at = w.now;
        rel.status = ReleaseStatus::Deploying;
        a.current = rel.version;
        a.releases.push(rel);
    }

    #[test]
    fn region_pinned_app_runs_and_moves_there() {
        let mut w = World::new(3);
        regions(&mut w, &[(1, "fsn1"), (2, "fsn1"), (3, "ash")]);
        app(&mut w.s, "web", 2, false);
        w.run(3);
        // Pin it to ash: both instances end up on the one machine there.
        cfg_mut(&mut w, "web").regions = vec!["ash".into()];
        w.run(10);
        let act = w.active("web");
        assert_eq!(act.len(), 2);
        assert!(act.iter().all(|i| i.machine == 3), "{act:?}");
        // and the rebalancer doesn't spread it out again
        w.now += 100;
        w.run(20);
        assert!(w.active("web").iter().all(|i| i.machine == 3));
    }

    #[test]
    fn region_with_no_machine_warns_and_keeps_running() {
        let mut w = World::new(1);
        regions(&mut w, &[(1, "fsn1")]);
        app(&mut w.s, "web", 1, false);
        w.run(3);
        cfg_mut(&mut w, "web").regions = vec!["ash".into()];
        let mut warned = false;
        for _ in 0..5 {
            warned |= w.tick().iter().any(|e| e.message.contains("no ready machine in region ash"));
        }
        assert!(warned);
        assert_eq!(w.active("web").len(), 1, "keeps running until there is somewhere to go");
    }

    #[test]
    fn udp_app_one_per_machine_and_back_to_the_same_machine() {
        let mut w = World::new(3);
        app(&mut w.s, "game", 1, false);
        let c = cfg_mut(&mut w, "game");
        c.http = None;
        c.ports = vec![crate::config::PortConfig { port: 7777, public: true, public_port: None, protocol: "udp".into() }];
        w.run(3);
        let home = w.active("game")[0].machine;
        // Redeploys: the old one stops first, the new one starts on the same machine.
        for _ in 0..3 {
            redeploy(&mut w, "game");
            for _ in 0..8 {
                w.tick();
                let act = w.active("game");
                assert!(act.len() <= 1, "never two at once");
                assert!(
                    !w.s.instances.values().any(|i| i.app == "game" && i.machine != home),
                    "stays on its machine"
                );
            }
            assert_eq!(w.active("game").len(), 1);
            assert_eq!(w.active("game")[0].release, w.s.apps["game"].current);
        }
        // Scaling up: one per machine, never two on one.
        w.s.apps.get_mut("game").unwrap().count = 5;
        w.run(5);
        let machines: HashSet<u32> = w.active("game").iter().map(|i| i.machine).collect();
        assert_eq!(w.active("game").len(), 3);
        assert_eq!(machines.len(), 3);
    }

    #[test]
    fn udp_ports_do_not_collide_between_apps() {
        let mut w = World::new(2);
        for name in ["a", "b"] {
            app(&mut w.s, name, 1, false);
            let c = cfg_mut(&mut w, name);
            c.http = None;
            c.ports = vec![crate::config::PortConfig { port: 7777, public: true, public_port: None, protocol: "udp".into() }];
        }
        w.run(3);
        assert_ne!(w.active("a")[0].machine, w.active("b")[0].machine);
    }

    #[test]
    fn stateful_app_moves_to_its_region() {
        let mut w = World::new(2);
        regions(&mut w, &[(1, "fsn1"), (2, "ash")]);
        app(&mut w.s, "db", 1, true);
        w.s.volumes.get_mut("db__data").unwrap().copies = 1;
        w.run(3);
        assert_eq!(w.active("db")[0].machine, 1);
        assert!(w.s.volumes["db__data"].replicas.is_empty());
        cfg_mut(&mut w, "db").regions = vec!["ash".into()];
        w.run(15);
        assert_eq!(w.s.volumes["db__data"].primary, 2, "data moved to ash");
        assert_eq!(w.active("db").len(), 1);
        assert_eq!(w.active("db")[0].machine, 2);
        w.run(3);
        assert!(w.s.volumes["db__data"].replicas.is_empty(), "back to one copy");
    }

    #[test]
    fn stateful_failover() {
        let mut w = World::new(2);
        app(&mut w.s, "db", 1, true);
        w.run(3);
        w.kill(1);
        w.run(20);
        assert_eq!(w.s.volumes["db__data"].primary, 2);
        assert_eq!(w.active("db").len(), 1);
        assert_eq!(w.active("db")[0].machine, 2);
    }

    #[test]
    fn temporary_server_for_maintenance() {
        let mut w = World::new(1);
        w.s.settings.autopilot = true;
        w.s.settings.update_window = String::new();
        w.s.provider_tokens.insert("hetzner".into(), "t".into());
        app(&mut w.s, "web", 2, false);
        app(&mut w.s, "db", 1, true);
        w.s.apps.get_mut("db").unwrap().vip = "10.78.0.2".into();
        w.run(3);
        // the single machine has updates pending
        let step = |w: &mut World, done: Option<&str>| {
            w.agents();
            let r = w.reports.get_mut(&1).unwrap();
            r.updates = UpdateInfo { pending: 3, reboot_required: true, checked_at: 1, package_manager: "apt-get".into() };
            r.maintenance_done = done.map(String::from);
            let live = LiveView { now: w.now, alive: &w.alive, dead_since: &w.dead_since, reports: &w.reports, leader_for: 1000 };
            let ev = reconcile(&mut w.s, &live, &mut w.mem);
            w.s.version += 1;
            w.now += 5;
            ev
        };
        w.now = 30 * 3600; // long after the last maintenance
        step(&mut w, None);
        let sg = w.s.surge.clone().expect("a temporary server is requested instead of draining");
        assert_eq!((sg.for_machine, sg.phase.as_str()), (1, "buying"));
        assert_eq!(w.s.machines[&1].status, MachineStatus::Ready, "nothing moves before the temp server exists");

        // the autopilot bought machine 2
        let mut m2 = machine(2);
        m2.temporary = true;
        w.s.machines.insert(2, m2);
        w.alive.insert(2);
        let sg = w.s.surge.as_mut().unwrap();
        sg.temp_machine = Some(2);
        sg.phase = "ready".into();
        for _ in 0..30 {
            step(&mut w, None);
        }
        assert_eq!(w.s.machines[&1].status, MachineStatus::Maintenance, "drained onto the temporary server");
        assert!(w.active("web").iter().all(|i| i.machine == 2));
        assert_eq!(w.active("db")[0].machine, 2, "the volume app moved with a final sync");

        // machine 1 finishes its updates
        let task = w.s.machines[&1].maintenance.clone().unwrap().id;
        for _ in 0..40 {
            step(&mut w, Some(&task));
        }
        assert_eq!(w.s.machines[&1].status, MachineStatus::Ready);
        assert_eq!(w.s.surge.as_ref().map(|s| s.phase.as_str()), Some("returning"));
        assert_eq!(w.s.machines[&2].maintenance.as_ref().map(|t| t.kind.as_str()), Some("remove"));
        assert!(w.active("web").iter().all(|i| i.machine == 1), "apps moved back");
        assert_eq!(w.active("db")[0].machine, 1, "volume app moved back");

        // the autopilot deletes the temporary server
        w.s.machines.remove(&2);
        w.alive.remove(&2);
        step(&mut w, Some(&task));
        assert!(w.s.surge.is_none());
        assert_eq!(w.active("web").len(), 2);
    }

    #[test]
    fn stuck_instance_is_replaced() {
        let mut w = World::new(2);
        app(&mut w.s, "web", 2, false);
        w.run(3);
        let victim = w.active("web")[0].id.clone();
        let since = w.now;
        let mut events = vec![];
        for _ in 0..30 {
            w.agents();
            for r in w.reports.values_mut() {
                for ir in r.instances.iter_mut().filter(|ir| ir.id == victim) {
                    ir.healthy = false;
                    ir.unhealthy_since = since;
                }
            }
            let live = LiveView { now: w.now, alive: &w.alive, dead_since: &w.dead_since, reports: &w.reports, leader_for: 1000 };
            events.extend(reconcile(&mut w.s, &live, &mut w.mem));
            w.s.version += 1;
            w.now += 5;
        }
        assert!(!w.active("web").iter().any(|i| i.id == victim), "stuck instance replaced");
        assert_eq!(w.active("web").len(), 2);
        assert!(events.iter().any(|e| e.message.contains("failed its health checks")));
    }

    #[test]
    fn broken_docker_is_evacuated() {
        let mut w = World::new(2);
        app(&mut w.s, "web", 2, false);
        w.run(3);
        for _ in 0..6 {
            w.agents();
            w.reports.get_mut(&1).unwrap().docker_ok = false;
            let live = LiveView {
                now: w.now,
                alive: &w.alive,
                dead_since: &w.dead_since,
                reports: &w.reports,
                leader_for: 1000,
            };
            reconcile(&mut w.s, &live, &mut w.mem);
            w.s.version += 1;
            w.now += 5;
        }
        assert!(w.active("web").iter().all(|i| i.machine == 2));
        assert_eq!(w.active("web").len(), 2);
    }

    #[test]
    fn window() {
        // 03:00 UTC
        assert!(in_window("02:00-05:00", 3 * 3600));
        assert!(!in_window("02:00-05:00", 6 * 3600));
        assert!(in_window("23:00-01:00", 30 * 60));
        assert!(in_window("", 12345));
    }

    #[test]
    fn routes_only_healthy() {
        let mut w = World::new(2);
        app(&mut w.s, "web", 2, false);
        w.run(3);
        w.agents();
        w.reports.get_mut(&1).unwrap().instances.iter_mut().for_each(|r| r.healthy = false);
        let live = LiveView {
            now: w.now,
            alive: &w.alive,
            dead_since: &w.dead_since,
            reports: &w.reports,
            leader_for: 1000,
        };
        let r = compute_routes(&w.s, &live);
        assert_eq!(r.apps["web"].backends.len(), 1);
        assert_eq!(r.dns["web.internal"], "10.78.0.1");
    }
}
