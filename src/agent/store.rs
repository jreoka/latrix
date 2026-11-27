//! State storage, replication and leader election.

use super::scheduler::{self, LiveView};
use super::Agent;
use crate::state::*;
use crate::util::{self, now, API_PORT};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// A machine counts as alive if it answered a ping this recently.
const ALIVE_WINDOW: Duration = Duration::from_secs(8);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ping {
    pub machine: u32,
    pub version: u64,
    pub leader: Option<u32>,
    pub agent_version: String,
}

pub struct LiveOwned {
    pub now: u64,
    pub alive: HashSet<u32>,
    pub dead_since: HashMap<u32, u64>,
    pub reports: HashMap<u32, NodeReport>,
    pub leader_for: u64,
}

impl LiveOwned {
    pub fn view(&self) -> LiveView<'_> {
        LiveView {
            now: self.now,
            alive: &self.alive,
            dead_since: &self.dead_since,
            reports: &self.reports,
            leader_for: self.leader_for,
        }
    }
}

impl Agent {
    pub fn alive_set(&self) -> HashSet<u32> {
        let mut set: HashSet<u32> = self
            .alive
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, t)| t.elapsed() < ALIVE_WINDOW)
            .map(|(m, _)| *m)
            .collect();
        set.insert(self.me.machine_id);
        set
    }

    /// The leader is the alive machine with the lowest id.
    pub fn leader(&self) -> Option<u32> {
        let s = self.snapshot();
        let alive = self.alive_set();
        let leader = s.machines.keys().copied().filter(|m| alive.contains(m)).min();
        let lowest_configured = s.machines.keys().copied().min();
        // Right after start, give the mesh a moment before claiming leadership
        // of a multi-machine cluster when lower-id peers haven't answered yet.
        if leader == Some(self.me.machine_id)
            && s.machines.len() > 1
            && self.started.elapsed() < Duration::from_secs(20)
            && (alive.len() == 1 || lowest_configured != Some(self.me.machine_id))
        {
            return None;
        }
        leader
    }

    pub fn is_leader(&self) -> bool {
        self.leader() == Some(self.me.machine_id)
    }

    /// Seconds this machine has been leader (0 if it is not).
    pub fn leader_for(&self) -> u64 {
        match *self.leader_view.lock().unwrap() {
            Some((id, since)) if id == self.me.machine_id => since.elapsed().as_secs(),
            _ => 0,
        }
    }

    pub fn leader_ip(&self) -> Option<String> {
        let l = self.leader()?;
        self.ip_of(l)
    }

    fn persist(&self, s: &ClusterState) {
        match serde_json::to_vec(s) {
            Ok(bytes) => {
                let path = self.data.join("state.json");
                if let Err(e) = util::write_atomic_private(&path, &bytes) {
                    warn!("could not persist state: {e}");
                }
            }
            Err(e) => warn!("could not serialize state: {e}"),
        }
    }

    fn install(&self, s: ClusterState) -> Arc<ClusterState> {
        self.persist(&s);
        let v = s.version;
        let arc = Arc::new(s);
        *self.state.write().unwrap() = arc.clone();
        self.max_seen_version.fetch_max(v, Ordering::SeqCst);
        let _ = self.changed.send(v);
        arc
    }

    /// Accept a replicated state if it is newer than ours (serialized under `write_lock`).
    pub async fn accept_state(&self, s: ClusterState) -> bool {
        if s.cluster != self.me.cluster {
            warn!("ignoring state for another cluster '{}'", s.cluster);
            return false;
        }
        let _guard = self.write_lock.lock().await;
        let cur = self.snapshot().version;
        if s.version <= cur {
            return false;
        }
        debug!("accepting state v{} (had v{cur})", s.version);
        self.install(s);
        true
    }

    /// Apply a change to the cluster state (leader only) and replicate it.
    pub async fn mutate<T>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut ClusterState) -> Result<T>,
    ) -> Result<T> {
        if !self.is_leader() {
            bail!("this machine is not the leader");
        }
        let _guard = self.write_lock.lock().await;
        if !self.is_leader() {
            bail!("this machine lost leadership before committing");
        }
        let mut s = (*self.snapshot()).clone();
        let out = f(&mut s)?;
        self.commit(s);
        Ok(out)
    }

    /// Bump the version, persist and broadcast. Caller holds `write_lock`.
    fn commit(self: &Arc<Self>, mut s: ClusterState) {
        s.version = s.version.max(self.max_seen_version.load(Ordering::SeqCst)) + 1;
        let arc = self.install(s);
        self.broadcast(arc);
    }

    pub fn broadcast(self: &Arc<Self>, s: Arc<ClusterState>) {
        for m in s.machines.values() {
            if m.id == self.me.machine_id || self.dev {
                continue;
            }
            let agent = self.clone();
            let s = s.clone();
            let url = super::host_port_url(&m.overlay_ip, API_PORT, "/v1/local/state");
            tokio::spawn(async move {
                let res = agent
                    .http
                    .post(&url)
                    .bearer_auth(&agent.me.token)
                    .timeout(Duration::from_secs(5))
                    .json(&*s)
                    .send()
                    .await;
                match res {
                    Ok(r) if !r.status().is_success() => {
                        debug!("state push to {url} rejected: {}", r.status());
                    }
                    Err(e) => debug!("state push to {url} failed: {e}"),
                    _ => {}
                }
            });
        }
    }

    pub fn live(&self) -> LiveOwned {
        let alive = self.alive_set();
        let dead_since = self.dead_since.lock().unwrap().clone();
        let mut reports: HashMap<u32, NodeReport> = self
            .reports
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, (t, _))| t.elapsed() < Duration::from_secs(30))
            .map(|(k, (_, r))| (*k, r.clone()))
            .collect();
        // The leader's own report is always fresh.
        reports.insert(self.me.machine_id, self.build_report());
        LiveOwned {
            now: now(),
            alive,
            dead_since,
            reports,
            leader_for: self.leader_for(),
        }
    }

    pub fn build_report(&self) -> NodeReport {
        NodeReport {
            machine: self.me.machine_id,
            state_version: self.snapshot().version,
            agent_version: util::VERSION.into(),
            metrics: self.sampler.latest(),
            instances: self.rt.reports(),
            volumes: self.vols.reports(),
            updates: self.updates.lock().unwrap().clone(),
            maintenance_done: self.maintenance_done.lock().unwrap().clone(),
            build_cache_gb: self.rt.build_cache_gb(),
            docker_ok: self.rt.docker_ok(),
            events: vec![],
            replica_volumes: self.vols.replica_volumes(&self.data, &self.snapshot(), self.me.machine_id),
        }
    }

    /// GET a JSON document from another machine's agent.
    pub async fn peer_get<T: for<'de> Deserialize<'de>>(&self, ip: &str, path: &str) -> Result<T> {
        let url = super::host_port_url(ip, API_PORT, path);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.me.token)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("{url}: {}", resp.status()));
        }
        Ok(resp.json().await?)
    }

    async fn pull_state_from(&self, ip: &str) {
        match self.peer_get::<ClusterState>(ip, "/v1/local/state").await {
            Ok(s) => {
                self.accept_state(s).await;
            }
            Err(e) => debug!("state pull from {ip} failed: {e}"),
        }
    }
}

/// Ping every other machine; track liveness, discover newer state, elect leader.
pub async fn ping_loop(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let s = agent.snapshot();
        let mut futs = vec![];
        for m in s.machines.values() {
            if m.id == agent.me.machine_id {
                continue;
            }
            let agent = agent.clone();
            let (id, ip) = (m.id, m.overlay_ip.clone());
            futs.push(async move {
                let r = tokio::time::timeout(
                    Duration::from_millis(1800),
                    agent.peer_get::<Ping>(&ip, "/v1/local/ping"),
                )
                .await;
                (id, ip, r)
            });
        }
        let mut newest: Option<(u64, String)> = None;
        for (id, ip, r) in futures::future::join_all(futs).await {
            if let Ok(Ok(p)) = r {
                agent.alive.lock().unwrap().insert(id, Instant::now());
                agent.max_seen_version.fetch_max(p.version, Ordering::SeqCst);
                if p.version > s.version && newest.as_ref().map(|(v, _)| p.version > *v).unwrap_or(true) {
                    newest = Some((p.version, ip));
                }
            }
        }
        // Prune removed machines from liveness map.
        agent.alive.lock().unwrap().retain(|id, _| s.machines.contains_key(id));
        if let Some((_, ip)) = newest {
            if !agent.pull_in_flight.swap(true, Ordering::AcqRel) {
                let agent_pull = agent.clone();
                tokio::spawn(async move {
                    agent_pull.pull_state_from(&ip).await;
                    agent_pull.pull_in_flight.store(false, Ordering::Release);
                });
            }
        }

        // Track who is leader and since when.
        let leader = agent.leader();
        let mut lv = agent.leader_view.lock().unwrap();
        let changed = match (*lv, leader) {
            (Some((a, _)), Some(b)) => a != b,
            (None, Some(_)) => true,
            (Some(_), None) => true,
            (None, None) => false,
        };
        if changed {
            *lv = leader.map(|l| (l, Instant::now()));
            drop(lv);
            if let Some(l) = leader {
                let name = s.machines.get(&l).map(|m| m.name.clone()).unwrap_or_default();
                if l == agent.me.machine_id {
                    info!("this machine is now the leader");
                    agent.event("info", format!("{name} is now the cluster leader"));
                } else {
                    info!("leader is now #{l} ({name})");
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ReportAck {
    pub version: u64,
}

/// Send this machine's report to the leader every few seconds.
pub async fn report_loop(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(Duration::from_secs(3));
    loop {
        tick.tick().await;
        let Some(leader) = agent.leader() else { continue };
        if leader == agent.me.machine_id {
            continue; // the leader reads its own report directly
        }
        let Some(ip) = agent.ip_of(leader) else { continue };
        let mut report = agent.build_report();
        let sent_events = std::mem::take(&mut *agent.outbox.lock().unwrap());
        report.events = sent_events.clone();
        let url = super::host_port_url(&ip, API_PORT, "/v1/local/report");
        let res = agent
            .http
            .post(&url)
            .bearer_auth(&agent.me.token)
            .timeout(Duration::from_secs(5))
            .json(&report)
            .send()
            .await;
        let ok = match res {
            Ok(r) if r.status().is_success() => {
                if let Ok(ack) = r.json::<ReportAck>().await {
                    if ack.version > agent.snapshot().version {
                        agent.pull_state_from(&ip).await;
                    }
                }
                true
            }
            Ok(r) => {
                debug!("report rejected: {}", r.status());
                false
            }
            Err(e) => {
                debug!("report to leader failed: {e}");
                false
            }
        };
        if !ok && !sent_events.is_empty() {
            let mut out = agent.outbox.lock().unwrap();
            let mut combined = sent_events;
            combined.extend(out.drain(..));
            if combined.len() > 50 {
                let drop_n = combined.len() - 50;
                combined.drain(..drop_n);
            }
            *out = combined;
        }
    }
}

/// Leader duties: run the scheduler and compute routes.
pub async fn leader_loop(agent: Arc<Agent>) {
    let mut rx = agent.changed.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = rx.changed() => {},
        }
        if !agent.is_leader() {
            agent.dead_since.lock().unwrap().clear();
            agent.reports.lock().unwrap().clear();
            continue;
        }
        // Track how long machines have been unreachable.
        {
            let alive = agent.alive_set();
            let s = agent.snapshot();
            let mut ds = agent.dead_since.lock().unwrap();
            ds.retain(|id, _| s.machines.contains_key(id));
            for m in s.machines.keys() {
                if alive.contains(m) {
                    ds.remove(m);
                } else {
                    ds.entry(*m).or_insert_with(now);
                }
            }
            agent.reports.lock().unwrap().retain(|id, _| s.machines.contains_key(id));
        }
        if agent.leader_for() < 3 && agent.snapshot().machines.len() > 1 {
            continue;
        }
        let live = agent.live();
        let events = {
            let _guard = agent.write_lock.lock().await;
            if !agent.is_leader() {
                continue;
            }
            let before = agent.snapshot();
            let mut s = (*before).clone();
            let events = {
                let mut mem = agent.sched_mem.lock().unwrap();
                scheduler::reconcile(&mut s, &live.view(), &mut mem)
            };
            let changed = match (serde_json::to_vec(&s), serde_json::to_vec(&*before)) {
                (Ok(a), Ok(b)) => a != b,
                _ => false,
            };
            if changed {
                agent.commit(s);
            }
            events
        };
        for e in events {
            agent.event(&e.level, e.message);
        }
        let routes = scheduler::compute_routes(&agent.snapshot(), &live.view());
        *agent.routes.write().unwrap() = Arc::new(routes);
    }
}

/// Followers pull the routing table from the leader.
pub async fn routes_loop(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        if agent.is_leader() {
            continue;
        }
        let Some(ip) = agent.leader_ip() else { continue };
        match agent.peer_get::<Routes>(&ip, "/v1/local/routes").await {
            Ok(r) => *agent.routes.write().unwrap() = Arc::new(r),
            Err(e) => debug!("routes pull failed: {e}"),
        }
    }
}
