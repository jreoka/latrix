//! Autopilot: latrix buys, resizes and deletes servers by itself.
//!
//! Runs on the leader once a minute when `settings.autopilot` is on and a
//! provider token is configured. It looks at what the apps ask for (their
//! instance count × cpu/memory) against what the machines have, and:
//!
//! * **scales up** — buys the cheapest server that covers the shortfall
//!   (live prices from every configured provider, newest Ubuntu LTS, in a
//!   location the cluster already uses when the price is equal), within the
//!   monthly budget; also adds a second machine when apps ask for redundancy
//! * **scales down** — after a sustained quiet period, drains the most
//!   expensive server the cluster can do without, then deletes it
//! * **right-sizes** — replaces a server that is much bigger than its load
//!   with a cheaper one (new one first, then drain + delete the old one)
//! * **heals** — reboots a server it created that stopped responding (via
//!   the provider API), and replaces it if it stays dead
//!
//! Machines you added yourself with `latrix machine add` are never touched.
//! New servers are set up by the leader over SSH with its own key and its
//! own binary, exactly like `latrix machine add` does from your computer.

use super::scheduler::LiveView;
use super::{cmd, Agent, NodeIdentity};
use crate::api_types::JoinRequest;
use crate::cli::machine::{WriteJoin, BOOTSTRAP};
use crate::cli::providers::{self, Offer};
use crate::cli::ssh::Ssh;
use crate::state::*;
use crate::util::{now, random_id};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Scale up when apps ask for more than this share of the capacity.
const UP_UTIL: f64 = 0.80;
/// Consider scaling down below this...
const LOW_UTIL: f64 = 0.45;
/// ...if the remaining machines would stay below this.
const AFTER_REMOVE_UTIL: f64 = 0.65;
/// Checks (minutes) before acting.
const UP_STREAK: u32 = 2;
const DOWN_STREAK: u32 = 30;
const RIGHTSIZE_STREAK: u32 = 60;
/// Memory per machine reserved for the OS, Docker and latrix.
const OVERHEAD_MB: f64 = 400.0;
const MIN_SERVER_MB: u64 = 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capacity {
    pub machines: usize,
    pub cap_mem_mb: f64,
    pub cap_cpu: f64,
    pub req_mem_mb: f64,
    pub req_cpu: f64,
    pub largest_mb: u64,
    pub overloaded: Vec<String>,
    pub utilization: f64,
    pub monthly_cost: f64,
    pub wanted_machines: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Nothing(String),
    ScaleUp { offer: Offer, reason: String, replaces: Option<u32> },
    ScaleDown { machine: u32, reason: String },
}

#[derive(Default)]
pub struct Memory {
    pub high: u32,
    pub low: u32,
    pub cooldown_until: u64,
    pub warned: HashMap<String, u64>,
    /// Machine ID -> unix timestamp of the last successful provider reboot.
    pub rebooted: HashMap<u32, u64>,
}

/// Shared with the API for `latrix autopilot status`.
#[derive(Default)]
pub struct Shared {
    pub status: Mutex<Status>,
    pub busy: AtomicBool,
    pub wake: tokio::sync::Notify,
    pub key_lock: tokio::sync::Mutex<()>,
}

struct BusyGuard(Arc<Agent>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        if let Ok(mut st) = self.0.autopilot.status.lock() {
            st.working_on = None;
        }
        self.0.autopilot.busy.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    pub last_decision: String,
    pub last_check: u64,
    pub capacity: Capacity,
    pub providers: Vec<String>,
    pub cheapest: Option<Offer>,
    pub working_on: Option<String>,
    pub leader_ssh_key: String,
}

fn machine_mem(live: &LiveView, m: &Machine) -> f64 {
    live.reports
        .get(&m.id)
        .map(|r| r.metrics.mem_total_mb)
        .filter(|x| *x > 0)
        .unwrap_or(m.memory_mb) as f64
}

fn machine_cpu(live: &LiveView, m: &Machine) -> f64 {
    live.reports.get(&m.id).map(|r| r.metrics.cpus).filter(|x| *x > 0.0).unwrap_or(m.cpus).max(1.0)
}

/// How many machines the apps need for redundancy or non-colocatable workloads.
pub fn wanted_machines(s: &ClusterState) -> u32 {
    let mut w = 1u32;
    for a in s.apps.values() {
        let Some(c) = a.config() else { continue };
        if !c.stateful() && a.count >= 2 {
            w = w.max(2);
        }
        if let Some(copies) = c.volumes.iter().map(|v| v.copies).max() {
            if copies >= 2 {
                w = w.max(copies);
            }
        }
        if super::scheduler::direct(c) && a.count > 1 {
            w = w.max(a.count);
        }
    }
    w.max(s.settings.min_machines).min(s.settings.max_machines.max(1))
}

pub fn capacity(s: &ClusterState, live: &LiveView) -> Capacity {
    let ready: Vec<&Machine> = s
        .machines
        .values()
        .filter(|m| m.status == MachineStatus::Ready && live.is_alive(m.id))
        .collect();
    let cap_mem: f64 = ready.iter().map(|m| (machine_mem(live, m) - OVERHEAD_MB).max(0.0)).sum();
    let cap_cpu: f64 = ready.iter().map(|m| machine_cpu(live, m)).sum();
    let mut req_mem = 0.0;
    let mut req_cpu = 0.0;
    let mut largest = 0;
    for a in s.apps.values() {
        let Some(c) = a.config() else { continue };
        req_mem += a.count as f64 * c.scale.memory_mb() as f64;
        req_cpu += a.count as f64 * c.scale.cpu;
        if a.count > 0 {
            largest = largest.max(c.scale.memory_mb());
        }
    }
    let overloaded = ready
        .iter()
        .filter(|m| {
            let usable = (machine_mem(live, m) - OVERHEAD_MB).max(0.0);
            usable > 0.0 && s.reserved_mb(m.id) as f64 > usable * 0.95
        })
        .map(|m| m.name.clone())
        .collect();
    let util = if cap_mem <= 0.0 || cap_cpu <= 0.0 {
        if req_mem > 0.0 { f64::INFINITY } else { 0.0 }
    } else {
        (req_mem / cap_mem).max(req_cpu / cap_cpu)
    };
    Capacity {
        machines: ready.len(),
        cap_mem_mb: cap_mem,
        cap_cpu,
        req_mem_mb: req_mem,
        req_cpu,
        largest_mb: largest,
        overloaded,
        utilization: util,
        monthly_cost: s.machines.values().filter_map(|m| m.monthly_cost).sum::<f64>() + 0.0,
        wanted_machines: wanted_machines(s),
    }
}

fn managed(m: &Machine) -> bool {
    m.provider.is_some()
}

/// An app pinned to a region with no ready machine there:
/// (app, its regions, memory one instance needs).
pub fn missing_region(s: &ClusterState, live: &LiveView) -> Option<(String, Vec<String>, u64)> {
    s.apps.values().find_map(|a| {
        let c = a.config()?;
        if a.count == 0 || c.regions.is_empty() {
            return None;
        }
        let has = s
            .machines
            .values()
            .any(|m| m.status == MachineStatus::Ready && live.is_alive(m.id) && c.allows_region(m.region.as_deref()));
        (!has).then(|| (a.name.clone(), c.regions.clone(), c.scale.memory_mb()))
    })
}

/// The region of `m` when an app is pinned to it (a replacement or temporary
/// server must then be bought in the same place).
fn pinned_region(s: &ClusterState, m: &Machine) -> Option<String> {
    let r = m.region.clone()?;
    s.apps
        .values()
        .filter(|a| a.count > 0)
        .filter_map(|a| a.config())
        .any(|c| !c.regions.is_empty() && c.regions.contains(&r))
        .then_some(r)
}

fn offers_in(offers: &[Offer], region: Option<&str>) -> Vec<Offer> {
    offers.iter().filter(|o| region.map(|r| o.location == r).unwrap_or(true)).cloned().collect()
}

/// The decision for this minute. Pure: easy to test, no side effects.
pub fn decide(
    s: &ClusterState,
    live: &LiveView,
    offers: &[Offer],
    leader: u32,
    mem: &mut Memory,
    now: u64,
) -> (Capacity, Decision) {
    let c = capacity(s, live);
    let d = decide_with(s, live, offers, leader, mem, now, &c);
    (c, d)
}

fn can_safely_remove_for_scaledown(s: &ClusterState, live: &LiveView, id: u32) -> bool {
    // Never remove a machine that is the target of an active volume migration.
    if s.volumes.values().any(|v| v.moving_to == Some(id)) {
        return false;
    }
    let remaining: Vec<&Machine> = s
        .machines
        .values()
        .filter(|m| m.id != id && m.status == MachineStatus::Ready && live.is_alive(m.id))
        .collect();
    if remaining.is_empty() {
        return false;
    }
    // Check that every volume currently on `id` can still meet its copy count and has a
    // remaining alive Ready machine in an allowed region with enough usable memory.
    for v in s.volumes.values().filter(|v| v.primary == id) {
        let Some(app) = s.apps.get(&v.app) else { continue };
        let Some(cfg) = app.config() else { continue };
        let eligible: Vec<&&Machine> = remaining
            .iter()
            .filter(|m| {
                cfg.allows_region(m.region.as_deref())
                    && (machine_mem(live, m) - OVERHEAD_MB).max(0.0) >= cfg.scale.memory_mb() as f64
            })
            .collect();
        if eligible.is_empty() {
            return false;
        }
        if v.copies >= 2 && (eligible.len() as u32) < v.copies {
            return false;
        }
    }
    // Check that direct-UDP apps running on `id` still have enough remaining machines.
    for a in s.apps.values() {
        let Some(cfg) = a.config() else { continue };
        if a.count == 0 || !super::scheduler::direct(cfg) {
            continue;
        }
        if s.instances_on(id).any(|i| i.app == a.name && !i.stopping) {
            let eligible = remaining
                .iter()
                .filter(|m| cfg.allows_region(m.region.as_deref()))
                .count();
            if eligible < a.count as usize {
                return false;
            }
        }
    }
    true
}

fn decide_with(
    s: &ClusterState,
    live: &LiveView,
    offers: &[Offer],
    leader: u32,
    mem: &mut Memory,
    now: u64,
    c: &Capacity,
) -> Decision {
    let nothing = |why: &str| Decision::Nothing(why.to_string());
    if offers.is_empty() {
        return nothing("no provider prices available (is a provider token set?)");
    }
    if s.surge.is_some() {
        return nothing("a temporary server for maintenance is in use");
    }
    if s.machines.values().any(|m| matches!(m.status, MachineStatus::Draining | MachineStatus::Maintenance)) {
        return nothing("waiting for a drain / maintenance to finish");
    }
    let arch = s
        .machines
        .get(&leader)
        .map(|m| providers::provider_arch(&m.arch))
        .unwrap_or("x86");
    let prefer: Vec<String> = s.machines.values().filter_map(|m| m.region.clone()).collect();
    let budget = s.settings.monthly_budget;
    let room = if budget > 0.0 { Some(budget - c.monthly_cost) } else { None };
    let total = s.machines.len() as u32;

    // --- scale up --------------------------------------------------------------
    let too_few = (c.machines as u32) < c.wanted_machines;
    let missing = missing_region(s, live);
    let need_up = c.utilization > UP_UTIL || !c.overloaded.is_empty() || too_few || missing.is_some();
    mem.high = if need_up { mem.high + 1 } else { 0 };
    if need_up && mem.high >= UP_STREAK {
        if now < mem.cooldown_until {
            return nothing("cooling down after the last change");
        }
        if total >= s.settings.max_machines {
            return nothing("more capacity needed, but max_machines reached");
        }
        let need_mem = ((c.req_mem_mb / 0.7 - c.cap_mem_mb)
            .max(c.largest_mb as f64 * 1.2)
            + OVERHEAD_MB)
            .max(MIN_SERVER_MB as f64);
        let shortfall_cpu = (c.req_cpu / 0.7 - c.cap_cpu).max(1.0);
        if let Some((app, regions, mb)) = missing {
            // A server where the app must run (cheapest there that fits it).
            let here: Vec<Offer> = offers.iter().filter(|o| regions.contains(&o.location)).cloned().collect();
            let need = (mb as f64 * 1.2 + OVERHEAD_MB).max(MIN_SERVER_MB as f64) as u64;
            let reason = format!("{app} runs in {} and no machine is there", regions.join(", "));
            return match providers::cheapest(&here, need, 1.0, arch, &prefer, room) {
                Some(o) => Decision::ScaleUp { offer: o.clone(), reason, replaces: None },
                None if here.is_empty() => nothing(&format!(
                    "{reason}, but no provider offers servers in {} (check the location name, e.g. hetzner: ash, hil, fsn1, nbg1, hel1, sin)",
                    regions.join(", ")
                )),
                None => nothing(&format!("{reason}, but no server there fits the monthly budget")),
            };
        }
        let only_overloaded = !too_few && c.utilization <= UP_UTIL && !c.overloaded.is_empty();
        if only_overloaded && !s.settings.rebalance {
            let unplaced = s.apps.values().any(|a| {
                let running = s.instances_of(&a.name).filter(|i| !i.stopping).count() as u32;
                running < a.count
            });
            if !unplaced {
                return nothing("a machine is overloaded, but rebalance is off so adding capacity would not move running apps");
            }
        }
        // If scaling up due to overloaded machines that are all in pinned regions, buy there.
        let pool: Vec<Offer> = if only_overloaded {
            let overloaded_regions: Vec<String> = s
                .machines
                .values()
                .filter(|m| c.overloaded.contains(&m.name))
                .filter_map(|m| pinned_region(s, m))
                .collect();
            if !overloaded_regions.is_empty() {
                let filtered: Vec<Offer> = offers
                    .iter()
                    .filter(|o| overloaded_regions.contains(&o.location))
                    .cloned()
                    .collect();
                if filtered.is_empty() { offers.to_vec() } else { filtered }
            } else {
                offers.to_vec()
            }
        } else {
            offers.to_vec()
        };
        let reason = if too_few {
            format!("apps want {} machines for redundancy, have {}", c.wanted_machines, c.machines)
        } else if !c.overloaded.is_empty() {
            format!("{} {} full", c.overloaded.join(", "), if c.overloaded.len() == 1 { "is" } else { "are" })
        } else {
            format!("apps need {:.0}% of current capacity", c.utilization * 100.0)
        };
        return match providers::cheapest(&pool, need_mem as u64, shortfall_cpu, arch, &prefer, room) {
            Some(o) => Decision::ScaleUp { offer: o.clone(), reason, replaces: None },
            None => nothing(&format!(
                "{reason}, but no server fits the monthly budget ({:.2} used of {:.2})",
                c.monthly_cost, budget
            )),
        };
    }

    // --- scale down / right-size -----------------------------------------------
    let low = c.utilization < LOW_UTIL && c.overloaded.is_empty();
    mem.low = if low { mem.low + 1 } else { 0 };
    if !low || mem.low < DOWN_STREAK {
        return nothing(&format!("capacity fine ({:.0}% used)", c.utilization * 100.0));
    }
    if now < mem.cooldown_until {
        return nothing("cooling down after the last change");
    }
    let mut candidates: Vec<&Machine> = s
        .machines
        .values()
        .filter(|m| managed(m) && !m.temporary && m.id != leader && m.status == MachineStatus::Ready && live.alive.contains(&m.id))
        .filter(|m| !s.volumes.values().any(|v| v.moving_to == Some(m.id)))
        .filter(|m| {
            // Never the last machine in a region an app is pinned to.
            match pinned_region(s, m) {
                None => true,
                Some(r) => s.machines.values().any(|o| {
                    o.id != m.id && o.region.as_deref() == Some(r.as_str()) && o.status == MachineStatus::Ready && live.alive.contains(&o.id)
                }),
            }
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.monthly_cost
            .unwrap_or(0.0)
            .partial_cmp(&a.monthly_cost.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if c.machines as u32 > c.wanted_machines {
        for m in &candidates {
            if !can_safely_remove_for_scaledown(s, live, m.id) {
                continue;
            }
            let cap_mem = c.cap_mem_mb - (machine_mem(live, m) - OVERHEAD_MB).max(0.0);
            let cap_cpu = c.cap_cpu - machine_cpu(live, m);
            if cap_mem <= 0.0 || cap_cpu <= 0.0 {
                continue;
            }
            // Ensure at least one SINGLE remaining machine can hold the largest instance.
            let max_single_remaining = s
                .machines
                .values()
                .filter(|o| o.id != m.id && o.status == MachineStatus::Ready && live.is_alive(o.id))
                .map(|o| (machine_mem(live, o) - OVERHEAD_MB).max(0.0))
                .fold(0.0_f64, f64::max);
            // If `m` is in a pinned region, verify remaining machines in that region can fit apps pinned there.
            if let Some(reg) = pinned_region(s, m) {
                let reg_cap: f64 = s
                    .machines
                    .values()
                    .filter(|o| {
                        o.id != m.id
                            && o.status == MachineStatus::Ready
                            && live.is_alive(o.id)
                            && o.region.as_deref() == Some(reg.as_str())
                    })
                    .map(|o| (machine_mem(live, o) - OVERHEAD_MB).max(0.0))
                    .sum();
                let reg_req: f64 = s
                    .apps
                    .values()
                    .filter_map(|a| {
                        let cfg = a.config()?;
                        (a.count > 0 && cfg.regions.len() == 1 && cfg.regions[0] == reg)
                            .then_some(a.count as f64 * cfg.scale.memory_mb() as f64)
                    })
                    .sum();
                if reg_cap <= 0.0 || reg_req / reg_cap >= AFTER_REMOVE_UTIL {
                    continue;
                }
            }
            let after = (c.req_mem_mb / cap_mem).max(c.req_cpu / cap_cpu);
            if after < AFTER_REMOVE_UTIL && c.largest_mb as f64 <= max_single_remaining {
                return Decision::ScaleDown {
                        machine: m.id,
                        reason: format!(
                            "only {:.0}% of capacity used; {:.0}% without {} (saves {:.2}/month)",
                            c.utilization * 100.0,
                            after * 100.0,
                            m.name,
                            m.monthly_cost.unwrap_or(0.0)
                        ),
                    };
            }
        }
    }
    if mem.low >= RIGHTSIZE_STREAK && (s.settings.max_machines == 0 || total < s.settings.max_machines) {
        for m in &candidates {
            let Some(price) = m.monthly_cost else { continue };
            let load_mem = s.reserved_mb(m.id) as f64;
            let load_cpu = s.reserved_cpu(m.id);
            let need = ((load_mem * 1.5).max(c.largest_mb as f64 * 1.2) + OVERHEAD_MB).max(MIN_SERVER_MB as f64);
            let local = offers_in(offers, pinned_region(s, m).as_deref());
            if let Some(o) = providers::cheapest(&local, need as u64, (load_cpu * 1.5).max(1.0), arch, &prefer, None) {
                if o.price < price * 0.7 && o.memory_mb < m.memory_mb {
                    if budget > 0.0 && c.monthly_cost - price + o.price > budget {
                        continue;
                    }
                    let new_usable = (o.memory_mb as f64 - OVERHEAD_MB).max(0.0);
                    let new_cap_mem = c.cap_mem_mb - (machine_mem(live, m) - OVERHEAD_MB).max(0.0) + new_usable;
                    let new_cap_cpu = c.cap_cpu - machine_cpu(live, m) + o.cpus.max(1.0);
                    let max_single_after = s
                        .machines
                        .values()
                        .filter(|x| x.id != m.id && x.status == MachineStatus::Ready && live.is_alive(x.id))
                        .map(|x| (machine_mem(live, x) - OVERHEAD_MB).max(0.0))
                        .fold(new_usable, f64::max);
                    if new_cap_mem <= 0.0 || new_cap_cpu <= 0.0 {
                        continue;
                    }
                    let after = (c.req_mem_mb / new_cap_mem).max(c.req_cpu / new_cap_cpu);
                    if after >= AFTER_REMOVE_UTIL || c.largest_mb as f64 > max_single_after {
                        continue;
                    }
                    return Decision::ScaleUp {
                            offer: o.clone(),
                            reason: format!(
                                "{} is much bigger than its load; {} {} costs {:.2} instead of {:.2}",
                                m.name, o.provider, o.size, o.price, price
                            ),
                            replaces: Some(m.id),
                        };
                }
            }
        }
    }
    nothing(&format!("capacity fine ({:.0}% used)", c.utilization * 100.0))
}

// ---------------------------------------------------------------------------
// execution

fn ssh_dir(agent: &Agent) -> std::path::PathBuf {
    agent.data.join("ssh")
}

/// The leader's own SSH key, used to set up servers it creates.
pub async fn leader_key(agent: &Agent) -> Result<(String, String)> {
    let _guard = agent.autopilot.key_lock.lock().await;
    let dir = ssh_dir(agent);
    crate::util::create_private_dir_all(&dir)?;
    let key = dir.join("id_ed25519");
    let pub_key = dir.join("id_ed25519.pub");
    if !key.exists() {
        let _ = std::fs::remove_file(&pub_key);
        cmd("ssh-keygen", &["-q", "-t", "ed25519", "-N", "", "-C", "latrix-autopilot", "-f", &key.display().to_string()]).await?;
    }
    super::set_private(&key);
    let public = std::fs::read_to_string(&pub_key)
        .with_context(|| format!("reading {}", pub_key.display()))?
        .trim()
        .to_string();
    Ok((key.display().to_string(), public))
}

pub fn leader_ssh(agent: &Agent, target: &str, port: u16, key: &str) -> Ssh {
    let mut ssh = Ssh::new(target, port, Some(key.to_string()));
    ssh.known_hosts = Some(ssh_dir(agent).join("known_hosts").display().to_string());
    ssh
}

/// Set up a server over SSH and join it to the cluster, from the leader.
/// Mirrors `latrix machine add`: upload our own binary, run the setup
/// script, register the machine and start its agent.
pub async fn provision(
    agent: &Arc<Agent>,
    ssh: &Ssh,
    name: &str,
    public_ip: &str,
    region: Option<String>,
    provider: Option<ProviderRef>,
    monthly_cost: Option<f64>,
) -> Result<Machine> {
    let ip: std::net::IpAddr = public_ip
        .trim()
        .parse()
        .with_context(|| format!("invalid public IP '{public_ip}'"))?;
    if ip.is_loopback() || ip.is_unspecified() {
        bail!("invalid public IP '{public_ip}'");
    }
    let progress = |msg: &str| {
        info!("provisioning {name}: {msg}");
        agent.autopilot.status.lock().unwrap().working_on = Some(format!("{name}: {msg}"));
    };
    progress("waiting for SSH");
    ssh.forget_host_key();
    let start = Instant::now();
    loop {
        if ssh.run("true").await.is_ok() {
            break;
        }
        if start.elapsed() > Duration::from_secs(300) {
            bail!("SSH to {} never became available", ssh.target);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let arch = ssh.run("uname -m").await?.trim().to_string();
    if providers::provider_arch(&arch) != providers::provider_arch(std::env::consts::ARCH) {
        bail!("{name} is {arch} but this machine runs {}", std::env::consts::ARCH);
    }
    progress("installing latrix");
    let exe = std::env::current_exe()?;
    let tmp = format!("/root/.latrix-upload-{}", random_id(8));
    if let Err(e) = ssh.upload(&exe, &tmp).await {
        let _ = ssh.run(&format!("rm -f {tmp}")).await;
        return Err(e);
    }
    if let Err(e) = ssh
        .run(&format!(
            "chmod 0755 {tmp} && {tmp} --version >/dev/null && install -m 0755 {tmp} /usr/local/bin/latrix && rm -f {tmp}"
        ))
        .await
    {
        let _ = ssh.run(&format!("rm -f {tmp}")).await;
        return Err(e);
    }
    progress("installing Docker, WireGuard and the firewall");
    ssh.run_input("bash -s", Some(BOOTSTRAP.as_bytes())).await?;
    let pubkey = ssh.run("/usr/local/bin/latrix agent keygen").await?.trim().to_string();
    let facts: super::metrics::Facts = serde_json::from_str(&ssh.run("/usr/local/bin/latrix agent facts").await?)?;
    progress("joining the mesh");
    let req = JoinRequest {
        name: name.into(),
        public_ip: ip.to_string(),
        wg_pubkey: pubkey,
        os: facts.os,
        arch: facts.arch,
        cpus: facts.cpus,
        memory_mb: facts.memory_mb,
        region,
        provider,
        monthly_cost,
    };
    let machine = agent.mutate(|s| super::api::register_machine(s, &req)).await?;
    let wj = WriteJoin {
        identity: NodeIdentity {
            machine_id: machine.id,
            overlay_ip: machine.overlay_ip.clone(),
            token: agent.me.token.clone(),
            cluster: agent.me.cluster.clone(),
        },
        state: (*agent.snapshot()).clone(),
    };
    ssh.run_input("/usr/local/bin/latrix agent write-join", Some(&serde_json::to_vec(&wj)?)).await?;
    ssh.run("systemctl enable latrix >/dev/null 2>&1; systemctl restart latrix").await?;
    progress("waiting for it to come online");
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(120) {
        if agent.alive_set().contains(&machine.id) {
            return Ok(machine);
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    bail!("{name} joined but did not come online within 2 minutes")
}

async fn buy(agent: &Arc<Agent>, offer: &Offer, replaces: Option<u32>, temporary: bool) -> Result<Machine> {
    let s = agent.snapshot();
    let token = s
        .provider_tokens
        .get(&offer.provider)
        .cloned()
        .context("provider token disappeared")?;
    let (key, leader_pub) = leader_key(agent).await?;
    let mut keys = vec![leader_pub];
    keys.extend(s.ssh_keys.iter().cloned());
    let name = loop {
        let n = format!("{}-{}", offer.location.to_ascii_lowercase(), random_id(4));
        if !s.machines.values().any(|m| m.name == n) {
            break n;
        }
    };
    let image = providers::latest_ubuntu(&offer.provider, &token, &offer.size).await;
    agent.autopilot.status.lock().unwrap().working_on = Some(format!("{name}: creating {} {} in {}", offer.provider, offer.size, offer.location));
    let created = providers::create(&offer.provider, &token, &name, &offer.size, &offer.location, &image, &keys).await?;
    let ssh = leader_ssh(agent, &format!("root@{}", created.ip), 22, &key);
    let res = provision(
        agent,
        &ssh,
        &name,
        &created.ip,
        Some(offer.location.clone()),
        Some(created.provider.clone()),
        created.monthly_cost.or(Some(offer.price)),
    )
    .await;
    match res {
        Ok(m) => {
            agent.event(
                "info",
                format!(
                    "autopilot: {} is online ({} {} in {}, {:.2}/month{})",
                    m.name,
                    offer.provider,
                    offer.size,
                    offer.location,
                    offer.price,
                    if temporary { ", temporary: billed by the hour, deleted after maintenance" } else { "" }
                ),
            );
            if let Some(old) = replaces {
                if let Err(e) = mark_for_removal(agent, old, "replaced by a cheaper server").await {
                    warn!("autopilot: new server {} is online, but draining replaced machine #{old} failed: {e:#}", m.name);
                }
            }
            Ok(m)
        }
        Err(e) => {
            // Don't leave a half-set-up server running (and billing).
            let _ = agent
                .mutate(|s| {
                    if let Some(id) = s.machines.values().find(|m| m.name == name).map(|m| m.id) {
                        s.machines.remove(&id);
                    }
                    Ok(())
                })
                .await;
            if let Err(d) = providers::destroy(&created.provider, &token).await {
                agent.event(
                    "warn",
                    format!("autopilot: could not delete failed server {} ({}): {d:#} — delete it in the {} console", name, created.ip, offer.provider),
                );
            }
            Err(e)
        }
    }
}

async fn mark_for_removal(agent: &Arc<Agent>, id: u32, why: &str) -> Result<()> {
    let name = agent
        .mutate(|s| {
            let m = s.machines.get_mut(&id).context("machine is gone")?;
            m.status = MachineStatus::Draining;
            m.maintenance = Some(MaintenanceTask { id: random_id(8), kind: "remove".into(), started_at: now() });
            Ok(m.name.clone())
        })
        .await?;
    agent.event("info", format!("autopilot: draining {name} to remove it ({why})"));
    Ok(())
}

/// Delete drained machines marked for removal: take them out of the
/// cluster, then delete the server at the provider.
async fn finish_removals(agent: &Arc<Agent>) {
    let s = agent.snapshot();
    let done: Vec<Machine> = s
        .machines
        .values()
        .filter(|m| m.status == MachineStatus::Cordoned)
        .filter(|m| m.maintenance.as_ref().map(|t| t.kind == "remove").unwrap_or(false))
        .filter(|m| m.id != agent.me.machine_id)
        .cloned()
        .collect();
    for m in done {
        remove_and_destroy(agent, &m, "removed", false).await;
    }
}

/// Mark orphaned temporary surge servers for removal so they cannot bill indefinitely
/// after a crash, leader failover, or toggling autopilot off.
async fn cleanup_orphaned_temp_machines(agent: &Arc<Agent>) {
    let s = agent.snapshot();
    let active_temp = s.surge.as_ref().and_then(|sg| sg.temp_machine);
    let orphans: Vec<u32> = s
        .machines
        .values()
        .filter(|m| {
            m.temporary
                && m.status == MachineStatus::Ready
                && m.id != agent.me.machine_id
                && Some(m.id) != active_temp
                && now().saturating_sub(m.joined_at) > 300
        })
        .map(|m| m.id)
        .collect();
    for id in orphans {
        let _ = mark_for_removal(agent, id, "orphaned temporary maintenance server").await;
    }
}

async fn remove_and_destroy(agent: &Arc<Agent>, m: &Machine, verb: &str, force_dead: bool) {
    let id = m.id;
    let removed = agent
        .mutate(|s| {
            // Never destroy a machine that still owns a primary volume or is a volume migration target.
            if s.volumes.values().any(|v| v.primary == id || v.moving_to == Some(id)) {
                return Ok(false);
            }
            if !force_dead {
                let Some(cur) = s.machines.get(&id) else { return Ok(false) };
                if cur.status != MachineStatus::Cordoned || s.instances_on(id).next().is_some() {
                    return Ok(false);
                }
            }
            let ids: Vec<String> = s.instances_on(id).map(|i| i.id.clone()).collect();
            for i in ids {
                s.instances.remove(&i);
            }
            for v in s.volumes.values_mut() {
                v.replicas.retain(|r| *r != id);
            }
            if s.surge.as_ref().and_then(|sg| sg.temp_machine) == Some(id) {
                s.surge = None;
            }
            Ok(s.machines.remove(&id).is_some())
        })
        .await
        .unwrap_or(false);
    if !removed {
        return;
    }
    let Some(p) = &m.provider else { return };
    let token = agent.snapshot().provider_tokens.get(&p.provider).cloned();
    match token {
        Some(t) => match providers::destroy(p, &t).await {
            Ok(()) => agent.event(
                "info",
                format!("autopilot: {verb} {} and deleted the server (saves {:.2}/month)", m.name, m.monthly_cost.unwrap_or(0.0)),
            ),
            Err(e) => agent.event("warn", format!("autopilot: could not delete {} at {}: {e:#}", m.name, p.provider)),
        },
        None => agent.event("warn", format!("autopilot: no {} token to delete {}", p.provider, m.name)),
    }
}

/// Reboot unresponsive servers the autopilot manages; replace them if that doesn't help.
async fn heal(agent: &Arc<Agent>, live: &LiveView<'_>, mem: &mut Memory) {
    let s = agent.snapshot();
    let has_quorum = s.machines.len() <= 1 || live.alive.len() * 2 > s.machines.len();
    mem.rebooted.retain(|id, _| s.machines.contains_key(id));
    for m in s.machines.values().filter(|m| managed(m)) {
        if m.id == agent.me.machine_id {
            continue;
        }
        let dead = live.dead_for(m.id);
        if dead == 0 {
            mem.rebooted.remove(&m.id);
            continue;
        }
        // Do not hard-reboot or destroy a machine that is mid-OS-maintenance/reboot.
        if m.status == MachineStatus::Maintenance {
            continue;
        }
        let (Some(p), Some(token)) = (&m.provider, m.provider.as_ref().and_then(|p| s.provider_tokens.get(&p.provider))) else {
            continue;
        };
        let rebooted_at = mem.rebooted.get(&m.id).copied();
        if dead >= 15 * 60 && rebooted_at.is_none() {
            match providers::server_status(p, token).await {
                Ok(None) => {
                    // Provider confirmed the VM no longer exists (HTTP 404).
                    if s.volumes.values().any(|v| v.primary == m.id || v.moving_to == Some(m.id)) {
                        agent.event(
                            "warn",
                            format!("autopilot: {} was deleted at {} but still owns primary volume(s); manual intervention required", m.name, p.provider),
                        );
                    } else {
                        remove_and_destroy(agent, m, "forgot deleted server", true).await;
                    }
                }
                Ok(Some(_)) => {
                    if !has_quorum {
                        let key = format!("no-quorum-{}", m.id);
                        let last = mem.warned.get(&key).copied().unwrap_or(0);
                        if now().saturating_sub(last) > 1800 {
                            mem.warned.insert(key, now());
                            agent.event(
                                "warn",
                                format!(
                                    "autopilot: {} unreachable for 15m, but cluster lacks majority ({}/{} alive) — skipping automatic reboot",
                                    m.name,
                                    live.alive.len(),
                                    s.machines.len()
                                ),
                            );
                        }
                        continue;
                    }
                    let r = providers::reboot(p, token).await;
                    if r.is_ok() {
                        mem.rebooted.insert(m.id, now());
                    }
                    agent.event(
                        if r.is_ok() { "info" } else { "warn" },
                        format!(
                            "autopilot: {} unreachable for 15 minutes, rebooting it{}",
                            m.name,
                            r.err().map(|e| format!(" (failed: {e:#})")).unwrap_or_default()
                        ),
                    );
                }
                Err(e) => warn!("autopilot: status of {}: {e:#}", m.name),
            }
        } else if let Some(rb_at) = rebooted_at {
            if now().saturating_sub(rb_at) >= 30 * 60 && dead >= 45 * 60 {
                if !has_quorum {
                    let key = format!("no-quorum-del-{}", m.id);
                    let last = mem.warned.get(&key).copied().unwrap_or(0);
                    if now().saturating_sub(last) > 1800 {
                        mem.warned.insert(key, now());
                        agent.event(
                            "warn",
                            format!(
                                "autopilot: {} still down after reboot, but cluster lacks majority ({}/{} alive) — refusing automatic server deletion",
                                m.name,
                                live.alive.len(),
                                s.machines.len()
                            ),
                        );
                    }
                    continue;
                }
                if s.volumes.values().any(|v| v.primary == m.id || v.moving_to == Some(m.id)) {
                    let key = format!("vol-primary-{}", m.id);
                    let last = mem.warned.get(&key).copied().unwrap_or(0);
                    if now().saturating_sub(last) > 1800 {
                        mem.warned.insert(key, now());
                        agent.event(
                            "warn",
                            format!(
                                "autopilot: {} still down after reboot, but still owns primary volume(s) — refusing automatic server deletion",
                                m.name
                            ),
                        );
                    }
                    continue;
                }
                agent.event("warn", format!("autopilot: {} still down 30 minutes after reboot, replacing it", m.name));
                remove_and_destroy(agent, m, "replaced dead", true).await;
                mem.rebooted.remove(&m.id);
            }
        }
    }
}

/// Buy a temporary server big enough to hold what runs on `for_machine`
/// while it is updated (cheapest that fits; billed by the hour).
fn buy_temporary(agent: &Arc<Agent>, s: &ClusterState, offers: &[Offer], for_machine: u32) {
    let need_mem = (s.reserved_mb(for_machine) as f64 * 1.25 + OVERHEAD_MB).max(MIN_SERVER_MB as f64) as u64;
    let need_cpu = s.reserved_cpu(for_machine).max(1.0);
    let arch = s.machines.get(&agent.me.machine_id).map(|m| providers::provider_arch(&m.arch)).unwrap_or("x86");
    let prefer: Vec<String> = s.machines.get(&for_machine).and_then(|m| m.region.clone()).into_iter().collect();
    let local = offers_in(offers, s.machines.get(&for_machine).and_then(|m| pinned_region(s, m)).as_deref());
    let Some(offer) = providers::cheapest(&local, need_mem, need_cpu, arch, &prefer, None).cloned() else {
        let a = agent.clone();
        tokio::spawn(async move { set_surge(&a, None, "failed").await });
        agent.event("warn", "autopilot: no server type fits the work to hold during maintenance; updating in place");
        return;
    };
    if agent
        .autopilot
        .busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    agent.event(
        "info",
        format!(
            "autopilot: buying a temporary {} {} in {} (~{:.3}/hour) to hold apps during maintenance",
            offer.provider,
            offer.size,
            offer.location,
            offer.price / 730.0
        ),
    );
    let a = agent.clone();
    tokio::spawn(async move {
        let _guard = BusyGuard(a.clone());
        match buy(&a, &offer, None, true).await {
            Ok(m) => {
                let id = m.id;
                let attached = a
                    .mutate(move |s| {
                        let valid_surge = s
                            .surge
                            .as_ref()
                            .map(|sg| sg.phase == "buying" && sg.temp_machine.is_none())
                            .unwrap_or(false);
                        if valid_surge {
                            if let Some(mm) = s.machines.get_mut(&id) {
                                mm.temporary = true;
                            }
                            if let Some(sg) = s.surge.as_mut() {
                                sg.temp_machine = Some(id);
                                sg.phase = "ready".into();
                            }
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    })
                    .await
                    .unwrap_or(false);
                if !attached {
                    warn!("autopilot: surge ended while provisioning temporary server {}; cleaning it up", m.name);
                    remove_and_destroy(&a, &m, "cleaned up unneeded temporary server", true).await;
                }
            }
            Err(e) => {
                a.event("warn", format!("autopilot: temporary server failed ({e:#}); updating in place"));
                set_surge(&a, None, "failed").await;
            }
        }
    });
}

async fn set_surge(agent: &Arc<Agent>, temp: Option<u32>, phase: &str) {
    let phase = phase.to_string();
    let _ = agent
        .mutate(move |s| {
            if let Some(sg) = s.surge.as_mut() {
                if temp.is_some() {
                    sg.temp_machine = temp;
                }
                sg.phase = phase;
            }
            Ok(())
        })
        .await;
}

#[cfg(test)]
fn catalog_stale(
    cached_at: Option<Instant>,
    cached_tokens: &std::collections::BTreeMap<String, String>,
    current_tokens: &std::collections::BTreeMap<String, String>,
    now: Instant,
) -> bool {
    match cached_at {
        None => true,
        Some(t) => now.saturating_duration_since(t) > Duration::from_secs(3600) || cached_tokens != current_tokens,
    }
}

pub async fn run(agent: Arc<Agent>) {
    tokio::time::sleep(Duration::from_secs(90)).await;
    let mut mem = Memory::default();
    let mut provider_cache: HashMap<String, (Instant, String, Vec<Offer>)> = HashMap::new();
    let mut price_error: Option<String> = None;
    let mut last_decide: Option<Instant> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = agent.autopilot.wake.notified() => {}
        }
        if !agent.is_leader() {
            continue;
        }
        let s = agent.snapshot();
        let mut st = agent.autopilot.status.lock().unwrap().clone();
        st.last_check = now();
        st.providers = s.provider_tokens.keys().cloned().collect();
        if let Ok((_, public)) = leader_key(&agent).await {
            st.leader_ssh_key = public;
        }
        // Always finish already-scheduled removals and clean up orphaned temporary servers,
        // even if autopilot was just toggled off mid-drain or mid-surge.
        if !agent.autopilot.busy.load(Ordering::SeqCst) {
            finish_removals(&agent).await;
            cleanup_orphaned_temp_machines(&agent).await;
        }
        if !s.settings.autopilot {
            st.last_decision = "autopilot is off".into();
            *agent.autopilot.status.lock().unwrap() = st;
            continue;
        }
        if agent.autopilot.busy.load(Ordering::SeqCst) {
            continue;
        }
        let live = agent.live();
        heal(&agent, &live.view(), &mut mem).await;

        // Refresh provider price catalogs independently per provider (hourly or on token change).
        provider_cache.retain(|p, _| s.provider_tokens.contains_key(p));
        let now_inst = Instant::now();
        let mut refreshed_any = false;
        let mut last_err = None;
        for (p, token) in &s.provider_tokens {
            let stale = match provider_cache.get(p) {
                None => true,
                Some((at, tok, _)) => {
                    tok != token || now_inst.saturating_duration_since(*at) > Duration::from_secs(3600)
                }
            };
            if stale {
                refreshed_any = true;
                match providers::catalog(p, token).await {
                    Ok(o) => {
                        provider_cache.insert(p.clone(), (Instant::now(), token.clone(), o));
                    }
                    Err(e) => {
                        warn!("autopilot: {p} prices: {e:#}");
                        let short = if e.to_string().contains("401") { "the API token was rejected".to_string() } else { format!("{e:#}") };
                        last_err = Some(format!("could not read {p} prices: {short}"));
                    }
                }
            }
        }
        if refreshed_any {
            price_error = last_err;
        }
        let offers: Vec<Offer> = provider_cache.values().flat_map(|(_, _, o)| o.iter().cloned()).collect();
        let s = agent.snapshot();
        if let Some(sg) = s.surge.clone().filter(|sg| sg.phase == "buying" && sg.temp_machine.is_none()) {
            if !agent.autopilot.busy.load(Ordering::SeqCst) {
                buy_temporary(&agent, &s, &offers, sg.for_machine);
            }
        }
        // Only advance minute-based scale-up/scale-down streaks once per ~60s even if woken frequently.
        let due_decide = last_decide
            .map(|t| Instant::now().saturating_duration_since(t) >= Duration::from_secs(55))
            .unwrap_or(true);
        if !due_decide {
            let working = agent.autopilot.status.lock().unwrap().working_on.clone();
            st.working_on = working;
            *agent.autopilot.status.lock().unwrap() = st;
            continue;
        }
        last_decide = Some(Instant::now());
        let (cap, decision) = decide(&s, &live.view(), &offers, agent.me.machine_id, &mut mem, now());
        let arch = s
            .machines
            .get(&agent.me.machine_id)
            .map(|m| providers::provider_arch(&m.arch))
            .unwrap_or("x86");
        st.cheapest = providers::cheapest(&offers, MIN_SERVER_MB, 1.0, arch, &[], None).cloned();
        st.capacity = cap;
        match decision {
            Decision::Nothing(why) => {
                let why = match (&price_error, offers.is_empty()) {
                    (Some(e), true) => e.clone(),
                    _ => why,
                };
                if why.contains("budget") || why.contains("max_machines") {
                    let last = mem.warned.get(&why).copied().unwrap_or(0);
                    if now().saturating_sub(last) > 3600 {
                        mem.warned.insert(why.clone(), now());
                        agent.event("warn", format!("autopilot: {why}"));
                    }
                }
                st.last_decision = why;
            }
            Decision::ScaleDown { machine, reason } => {
                st.last_decision = format!("scaling down: {reason}");
                mem.cooldown_until = now() + 15 * 60;
                mem.low = 0;
                if let Err(e) = mark_for_removal(&agent, machine, &reason).await {
                    warn!("autopilot: {e:#}");
                }
            }
            Decision::ScaleUp { offer, reason, replaces } => {
                if agent
                    .autopilot
                    .busy
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
                {
                    st.last_decision = "another provisioning operation is already in progress".into();
                } else {
                    st.last_decision = format!(
                        "{}: {reason} → buying {} {} in {} ({:.2}/month)",
                        if replaces.is_some() { "right-sizing" } else { "scaling up" },
                        offer.provider,
                        offer.size,
                        offer.location,
                        offer.price
                    );
                    agent.event("info", format!("autopilot: {}", st.last_decision));
                    mem.cooldown_until = now() + 10 * 60;
                    mem.high = 0;
                    mem.low = 0;
                    let a = agent.clone();
                    tokio::spawn(async move {
                        let _guard = BusyGuard(a.clone());
                        if let Err(e) = buy(&a, &offer, replaces, false).await {
                            a.event("warn", format!("autopilot: adding a server failed: {e:#}"));
                        }
                    });
                }
            }
        }
        let working = agent.autopilot.status.lock().unwrap().working_on.clone();
        st.working_on = working;
        *agent.autopilot.status.lock().unwrap() = st;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use std::collections::{HashMap as Map, HashSet};

    fn machine(id: u32, mem: u64, managed: bool, price: f64) -> Machine {
        Machine {
            id,
            name: format!("m{id}"),
            public_ip: format!("1.1.1.{id}"),
            overlay_ip: format!("10.77.0.{id}"),
            wg_pubkey: String::new(),
            os: String::new(),
            arch: "x86_64".into(),
            cpus: 2.0,
            memory_mb: mem,
            region: Some("fsn1".into()),
            provider: managed.then(|| ProviderRef { provider: "hetzner".into(), id: id.to_string(), size: "x".into(), region: "fsn1".into() }),
            monthly_cost: Some(price),
            status: MachineStatus::Ready,
            joined_at: 0,
            maintenance: None,
            last_maintenance: 0,
            temporary: false,
        }
    }

    fn app(s: &mut ClusterState, name: &str, count: u32, mem: &str) {
        let mut cfg: AppConfig = toml::from_str(&format!("app = \"{name}\"\n")).unwrap();
        cfg.scale.count = Some(count);
        cfg.scale.memory = mem.into();
        cfg.scale.cpu = 0.25;
        s.apps.insert(
            name.into(),
            App {
                name: name.into(),
                vip: String::new(),
                current: 1,
                releases: vec![Release {
                    version: 1,
                    image: "i".into(),
                    config: cfg,
                    created_at: 0,
                    status: ReleaseStatus::Active,
                    sources: vec![],
                    description: String::new(),
                }],
                secrets: Default::default(),
                count,
                created_at: 0,
                last_builder: None,
                dns_records: vec![],
            },
        );
    }

    fn offers() -> Vec<Offer> {
        let o = |size: &str, mem: u64, cpus: f64, price: f64| Offer {
            provider: "hetzner".into(),
            size: size.into(),
            location: "fsn1".into(),
            cpus,
            memory_mb: mem,
            disk_gb: 40,
            arch: "x86".into(),
            price,
        };
        let mut v = vec![o("small", 4096, 2.0, 4.0), o("medium", 8192, 4.0, 8.0), o("large", 16384, 8.0, 16.0)];
        v.push(Offer { location: "ash".into(), price: 5.0, ..v[0].clone() });
        v
    }

    fn run(s: &ClusterState, mem: &mut Memory, checks: u32) -> Decision {
        let alive: HashSet<u32> = s.machines.keys().copied().collect();
        let dead = Map::new();
        let reports = Map::new();
        let live = LiveView { now: 1000, alive: &alive, dead_since: &dead, reports: &reports, leader_for: 1000 };
        let mut last = Decision::Nothing(String::new());
        for _ in 0..checks {
            last = decide(s, &live, &offers(), 1, mem, 10_000).1;
        }
        last
    }

    #[test]
    fn buys_a_machine_in_a_pinned_region_and_keeps_it() {
        let mut s = ClusterState::default();
        s.settings.autopilot = true;
        s.settings.max_machines = 5;
        s.machines.insert(1, machine(1, 8192, true, 8.0));
        app(&mut s, "game", 1, "512MB");
        s.apps.get_mut("game").unwrap().releases[0].config.regions = vec!["ash".into()];
        let mut mem = Memory::default();
        match run(&s, &mut mem, 2) {
            Decision::ScaleUp { offer, replaces: None, .. } => assert_eq!(offer.location, "ash"),
            d => panic!("{d:?}"),
        }
        // Once there, the ash machine is never the one removed.
        let mut ash = machine(2, 4096, true, 5.0);
        ash.region = Some("ash".into());
        s.machines.insert(2, ash);
        let mut mem = Memory::default();
        match run(&s, &mut mem, 70) {
            Decision::ScaleDown { machine, .. } => panic!("removed {machine}"),
            Decision::ScaleUp { replaces: Some(m), offer, .. } => assert!(m != 2 || offer.location == "ash"),
            _ => {}
        }
    }

    #[test]
    fn scales_up_cheapest_that_fits() {
        let mut s = ClusterState::default();
        s.settings.autopilot = true;
        s.machines.insert(1, machine(1, 4096, true, 4.0));
        app(&mut s, "web", 6, "1GB"); // 6GB on a 4GB box
        let d = run(&s, &mut Memory::default(), 2);
        match d {
            Decision::ScaleUp { offer, replaces: None, .. } => assert_eq!(offer.size, "medium"),
            other => panic!("expected scale up, got {other:?}"),
        }
    }

    #[test]
    fn needs_two_checks_before_buying() {
        let mut s = ClusterState::default();
        s.machines.insert(1, machine(1, 4096, true, 4.0));
        app(&mut s, "web", 6, "1GB");
        assert!(matches!(run(&s, &mut Memory::default(), 1), Decision::Nothing(_)));
    }

    #[test]
    fn respects_budget() {
        let mut s = ClusterState::default();
        s.settings.monthly_budget = 10.0;
        s.machines.insert(1, machine(1, 4096, true, 4.0));
        app(&mut s, "web", 6, "1GB");
        match run(&s, &mut Memory::default(), 2) {
            Decision::Nothing(why) => assert!(why.contains("budget"), "{why}"),
            other => panic!("expected budget refusal, got {other:?}"),
        }
    }

    #[test]
    fn adds_second_machine_for_redundancy() {
        let mut s = ClusterState::default();
        s.machines.insert(1, machine(1, 16384, true, 16.0));
        app(&mut s, "web", 2, "256MB");
        match run(&s, &mut Memory::default(), 2) {
            Decision::ScaleUp { offer, .. } => assert_eq!(offer.size, "small", "cheapest server is enough"),
            other => panic!("expected scale up, got {other:?}"),
        }
    }

    #[test]
    fn scales_down_idle_machines_but_never_user_machines() {
        let mut s = ClusterState::default();
        s.machines.insert(1, machine(1, 8192, false, 0.0)); // leader, added by the user
        s.machines.insert(2, machine(2, 8192, true, 8.0));
        s.machines.insert(3, machine(3, 8192, false, 0.0)); // user machine
        app(&mut s, "web", 1, "256MB");
        let mut mem = Memory::default();
        match run(&s, &mut mem, DOWN_STREAK) {
            Decision::ScaleDown { machine, .. } => assert_eq!(machine, 2),
            other => panic!("expected scale down, got {other:?}"),
        }
        // with only user machines left, nothing to remove
        s.machines.remove(&2);
        assert!(matches!(run(&s, &mut Memory::default(), DOWN_STREAK), Decision::Nothing(_)));
    }

    #[test]
    fn right_sizes_oversized_machine() {
        let mut s = ClusterState::default();
        s.machines.insert(1, machine(1, 4096, false, 0.0));
        let mut big = machine(2, 16384, true, 16.0);
        big.region = Some("fsn1".into());
        s.machines.insert(2, big);
        app(&mut s, "web", 2, "256MB"); // wants 2 machines, so no plain scale-down
        let mut mem = Memory::default();
        match run(&s, &mut mem, RIGHTSIZE_STREAK) {
            Decision::ScaleUp { offer, replaces: Some(2), .. } => assert_eq!(offer.size, "small"),
            other => panic!("expected replacement, got {other:?}"),
        }
    }

    #[test]
    fn catalog_invalidates_when_provider_tokens_change() {
        use std::collections::BTreeMap;
        let t0 = Instant::now();
        let hetzner = BTreeMap::from([("hetzner".into(), "tok1".into())]);
        let both = BTreeMap::from([("hetzner".into(), "tok1".into()), ("digitalocean".into(), "tok2".into())]);
        let rotated = BTreeMap::from([("hetzner".into(), "tok-new".into())]);

        assert!(catalog_stale(None, &BTreeMap::new(), &hetzner, t0));
        assert!(!catalog_stale(Some(t0), &hetzner, &hetzner, t0 + Duration::from_secs(60)));
        assert!(catalog_stale(Some(t0), &hetzner, &both, t0 + Duration::from_secs(60)));
        assert!(catalog_stale(Some(t0), &hetzner, &rotated, t0 + Duration::from_secs(60)));
        assert!(catalog_stale(Some(t0), &hetzner, &hetzner, t0 + Duration::from_secs(3601)));
    }

    #[test]
    fn buys_1gb_server_for_small_app() {
        let mut s = ClusterState::default();
        s.settings.autopilot = true;
        s.settings.max_machines = 5;
        s.machines.insert(1, machine(1, 4096, true, 5.49));
        app(&mut s, "tiny", 1, "256MB");
        s.apps.get_mut("tiny").unwrap().releases[0].config.regions = vec!["nyc1".into()];
        let offers = vec![
            Offer { provider: "digitalocean".into(), size: "s-1vcpu-512mb-10gb".into(), location: "nyc1".into(), cpus: 1.0, memory_mb: 512, disk_gb: 10, arch: "x86".into(), price: 4.0 },
            Offer { provider: "digitalocean".into(), size: "s-1vcpu-1gb".into(), location: "nyc1".into(), cpus: 1.0, memory_mb: 1024, disk_gb: 25, arch: "x86".into(), price: 6.0 },
            Offer { provider: "digitalocean".into(), size: "s-1vcpu-2gb".into(), location: "nyc1".into(), cpus: 1.0, memory_mb: 2048, disk_gb: 50, arch: "x86".into(), price: 12.0 },
        ];
        let alive: HashSet<u32> = s.machines.keys().copied().collect();
        let dead = Map::new();
        let reports = Map::new();
        let live = LiveView { now: 1000, alive: &alive, dead_since: &dead, reports: &reports, leader_for: 1000 };
        let mut mem = Memory::default();
        let _ = decide(&s, &live, &offers, 1, &mut mem, 10_000);
        match decide(&s, &live, &offers, 1, &mut mem, 10_060).1 {
            Decision::ScaleUp { offer, .. } => assert_eq!(offer.size, "s-1vcpu-1gb"),
            other => panic!("expected 1GB droplet, got {other:?}"),
        }
    }

    #[test]
    fn scale_down_respects_largest_app_and_volume_primary() {
        // Two machines: m1 (2GB user) + m2 (8GB managed). App needs 3GB -> removing m2 would leave no machine able to fit 3GB!
        let mut s = ClusterState::default();
        s.machines.insert(1, machine(1, 2048, false, 0.0));
        s.machines.insert(2, machine(2, 8192, true, 16.0));
        app(&mut s, "big", 1, "3GB");
        let dec = run(&s, &mut Memory::default(), DOWN_STREAK);
        assert!(
            !matches!(dec, Decision::ScaleDown { machine: 2, .. }),
            "must not scale down the only machine that can fit a 3GB app: {dec:?}"
        );

        // Stateful app with copies = 3 wants 3 machines even though count = 1.
        let mut s2 = ClusterState::default();
        s2.machines.insert(1, machine(1, 4096, false, 0.0));
        s2.machines.insert(2, machine(2, 4096, true, 4.0));
        app(&mut s2, "db", 1, "256MB");
        s2.apps.get_mut("db").unwrap().releases[0].config.volumes.push(crate::config::VolumeConfig {
            name: "data".into(),
            path: "/data".into(),
            copies: 3,
            sync: "60s".into(),
            pre_sync: None,
            size: None,
        });
        assert_eq!(wanted_machines(&s2), 3);
    }
}
