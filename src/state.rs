//! Cluster state. The leader owns the authoritative copy and replicates it
//! to every machine, so any machine can take over if the leader dies.

use crate::config::AppConfig;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterState {
    pub version: u64,
    pub cluster: String,
    #[serde(default)]
    pub next_machine_id: u32,
    #[serde(default)]
    pub next_vip: u32,
    #[serde(default)]
    pub machines: BTreeMap<u32, Machine>,
    #[serde(default)]
    pub apps: BTreeMap<String, App>,
    #[serde(default)]
    pub instances: BTreeMap<String, Instance>,
    #[serde(default)]
    pub volumes: BTreeMap<String, Volume>,
    #[serde(default)]
    pub certs: BTreeMap<String, Cert>,
    /// ACME http-01 tokens -> key authorizations (replicated so any machine can answer).
    #[serde(default)]
    pub acme_challenges: BTreeMap<String, String>,
    #[serde(default)]
    pub acme_account: Option<String>,
    #[serde(default)]
    pub settings: Settings,
    /// Volume directories to delete everywhere (destroyed with --purge-volumes).
    #[serde(default)]
    pub tombstones: BTreeMap<String, u64>,
    /// Cloud provider API tokens the autopilot uses (never shown in status).
    #[serde(default)]
    pub provider_tokens: BTreeMap<String, String>,
    /// A temporary server bought so a machine can be updated without downtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surge: Option<Surge>,
    /// Extra SSH public keys installed on servers the autopilot creates
    /// (yours, so `latrix` on your computer can reach them).
    #[serde(default)]
    pub ssh_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
#[serde(rename_all = "lowercase")]
pub enum MachineStatus {
    /// Accepting work.
    Ready,
    /// Keeps what it runs, accepts nothing new.
    Cordoned,
    /// Moving everything off.
    Draining,
    /// Drained and running OS updates / rebooting.
    Maintenance,
}

impl std::fmt::Display for MachineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            MachineStatus::Ready => "ready",
            MachineStatus::Cordoned => "cordoned",
            MachineStatus::Draining => "draining",
            MachineStatus::Maintenance => "maintenance",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MaintenanceTask {
    pub id: String,
    /// "updates" (apply OS updates, reboot if needed) or "drain" (just empty the machine).
    pub kind: String,
    pub started_at: u64,
}

/// "Buy a temporary server, move work there, update the machine, move work
/// back, delete the temporary server."
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Surge {
    /// The machine to update.
    pub for_machine: u32,
    pub requested_at: u64,
    #[serde(default)]
    pub temp_machine: Option<u32>,
    /// buying | ready | maintaining | returning | failed
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderRef {
    pub provider: String,
    pub id: String,
    pub size: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Machine {
    pub id: u32,
    pub name: String,
    pub public_ip: String,
    pub overlay_ip: String,
    #[serde(default)]
    pub wg_pubkey: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub cpus: f64,
    #[serde(default)]
    pub memory_mb: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_cost: Option<f64>,
    pub status: MachineStatus,
    pub joined_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<MaintenanceTask>,
    #[serde(default)]
    pub last_maintenance: u64,
    /// Bought only to hold apps while another machine is updated; deleted after.
    #[serde(default)]
    pub temporary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseStatus {
    Deploying,
    Active,
    Failed,
    Superseded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub version: u64,
    pub image: String,
    pub config: AppConfig,
    pub created_at: u64,
    pub status: ReleaseStatus,
    /// Machines whose local registry holds the image (empty for public images).
    #[serde(default)]
    pub sources: Vec<u32>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub name: String,
    pub vip: String,
    pub current: u64,
    pub releases: Vec<Release>,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    /// Current desired instance count (moves between min/max when autoscaling).
    pub count: u32,
    pub created_at: u64,
    #[serde(default)]
    pub last_builder: Option<u32>,
}

impl App {
    pub fn release(&self, v: u64) -> Option<&Release> {
        self.releases.iter().find(|r| r.version == v)
    }
    pub fn current_release(&self) -> Option<&Release> {
        self.release(self.current)
    }
    pub fn config(&self) -> Option<&AppConfig> {
        self.current_release().map(|r| &r.config)
    }
    pub fn next_version(&self) -> u64 {
        self.releases.iter().map(|r| r.version).max().unwrap_or(0) + 1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Instance {
    pub id: String,
    pub app: String,
    pub release: u64,
    pub machine: u32,
    pub created_at: u64,
    /// Set when the instance should be shut down (it is removed from
    /// load balancing immediately and deleted once its container is gone).
    #[serde(default)]
    pub stopping: bool,
    #[serde(default)]
    pub stopping_since: u64,
    /// When set, this instance is a replacement for another one (rebalance
    /// or drain); the old one is stopped once this one is healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Volume {
    /// "<app>__<name>"
    pub id: String,
    pub app: String,
    pub name: String,
    pub path: String,
    /// The machine that holds the live copy.
    pub primary: u32,
    /// Machines holding asynchronously synced copies.
    pub replicas: Vec<u32>,
    pub copies: u32,
    pub sync_secs: u64,
    pub created_at: u64,
    /// Planned move in progress (drain/maintenance): target machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moving_to: Option<u32>,
    #[serde(default)]
    pub moving_since: u64,
    /// State version at which the move was requested. The primary reports the
    /// state version it had seen when it performed its final sync, which avoids
    /// relying on clocks being in sync across machines.
    #[serde(default)]
    pub moving_version: u64,
}

impl Volume {
    pub fn dir_name(app: &str, name: &str) -> String {
        format!("{app}__{name}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Cert {
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_after: u64,
    pub issued_at: u64,
    /// When no app used this domain any more (0 = in use). Deleted 7 days later.
    #[serde(default)]
    pub unused_since: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    /// Apply OS updates automatically, one machine at a time, draining first.
    #[serde(default = "yes")]
    pub auto_updates: bool,
    /// UTC window for automatic updates, e.g. "02:00-05:00". Empty = any time.
    #[serde(default = "default_window")]
    pub update_window: String,
    /// Move instances around to even out load.
    #[serde(default = "yes")]
    pub rebalance: bool,
    /// Scale apps between their min/max automatically.
    #[serde(default = "yes")]
    pub autoscale: bool,
    /// Email for Let's Encrypt.
    #[serde(default)]
    pub acme_email: String,
    /// Use Let's Encrypt staging (for testing).
    #[serde(default)]
    pub acme_staging: bool,
    /// Optional wildcard domain: every app gets <app>.<base_domain>.
    #[serde(default)]
    pub base_domain: String,
    /// Monthly budget in your provider's currency; latrix warns when the
    /// estimate exceeds it.
    #[serde(default)]
    pub monthly_budget: f64,
    /// Volume data no app uses (on a given machine) is deleted automatically
    /// after this many days. 0 = on the next scan.
    #[serde(default = "three")]
    pub volume_retention_days: f64,
    /// Machines upgrade themselves to new latrix releases (one at a time).
    #[serde(default = "yes")]
    pub auto_upgrade: bool,
    /// Webhook for alerts (Discord, Slack or any URL accepting JSON).
    #[serde(default)]
    pub alert_webhook: String,
    /// Daily snapshots kept per volume (0 = off).
    #[serde(default = "seven")]
    pub volume_snapshots: u32,
    /// Let latrix buy, resize and delete servers by itself (needs a provider token).
    #[serde(default)]
    pub autopilot: bool,
    /// Autopilot keeps at least this many machines.
    #[serde(default = "one")]
    pub min_machines: u32,
    /// ...and never more than this many.
    #[serde(default = "five")]
    pub max_machines: u32,
}

fn seven() -> u32 {
    7
}
fn three() -> f64 {
    3.0
}
fn one() -> u32 {
    1
}
fn five() -> u32 {
    5
}

fn yes() -> bool {
    true
}
fn default_window() -> String {
    "02:00-05:00".into()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_updates: true,
            update_window: default_window(),
            rebalance: true,
            autoscale: true,
            acme_email: String::new(),
            acme_staging: false,
            base_domain: String::new(),
            monthly_budget: 0.0,
            volume_retention_days: 3.0,
            auto_upgrade: true,
            alert_webhook: String::new(),
            volume_snapshots: 7,
            autopilot: false,
            min_machines: 1,
            max_machines: 5,
        }
    }
}

impl ClusterState {
    pub fn instances_of<'a>(&'a self, app: &'a str) -> impl Iterator<Item = &'a Instance> + 'a {
        self.instances.values().filter(move |i| i.app == app)
    }
    pub fn instances_on(&self, machine: u32) -> impl Iterator<Item = &Instance> + '_ {
        self.instances.values().filter(move |i| i.machine == machine)
    }
    pub fn volumes_of<'a>(&'a self, app: &'a str) -> impl Iterator<Item = &'a Volume> + 'a {
        self.volumes.values().filter(move |v| v.app == app)
    }
    pub fn machine_by_name(&self, name: &str) -> Option<&Machine> {
        self.machines
            .values()
            .find(|m| m.name == name || m.id.to_string() == name)
    }
    /// Memory (MB) reserved by instances on a machine.
    pub fn reserved_mb(&self, machine: u32) -> u64 {
        self.instances_on(machine)
            .filter(|i| !i.stopping)
            .filter_map(|i| {
                let app = self.apps.get(&i.app)?;
                Some(app.release(i.release)?.config.scale.memory_mb())
            })
            .sum()
    }
    pub fn reserved_cpu(&self, machine: u32) -> f64 {
        self.instances_on(machine)
            .filter(|i| !i.stopping)
            .filter_map(|i| {
                let app = self.apps.get(&i.app)?;
                Some(app.release(i.release)?.config.scale.cpu)
            })
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Live (non-replicated) information reported by agents to the leader.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metrics {
    pub cpus: f64,
    /// Whole-machine CPU usage 0..100.
    pub cpu_pct: f64,
    pub mem_total_mb: u64,
    pub mem_used_mb: u64,
    pub disk_total_gb: f64,
    pub disk_used_gb: f64,
    pub load1: f64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct InstanceReport {
    pub id: String,
    /// pulling | starting | running | stopping | failed | exited
    pub status: String,
    pub healthy: bool,
    /// container port -> host port (bound on the overlay IP).
    #[serde(default)]
    pub ports: BTreeMap<u16, u16>,
    #[serde(default)]
    pub restarts: u32,
    /// Percent of one core (docker stats style).
    #[serde(default)]
    pub cpu_pct: f64,
    #[serde(default)]
    pub mem_mb: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub healthy_since: u64,
    /// When a previously healthy instance started failing its checks (0 = healthy / never was).
    #[serde(default)]
    pub unhealthy_since: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VolumeReport {
    pub id: String,
    /// replica machine -> unix time of last successful sync.
    #[serde(default)]
    pub synced: BTreeMap<u32, u64>,
    /// Time of the last sync performed while no container was using the volume
    /// (a consistent, final copy — used for zero-loss planned moves).
    #[serde(default)]
    pub idle_synced_at: u64,
    /// replica machine -> cluster state version seen when that sync started.
    #[serde(default)]
    pub synced_version: BTreeMap<u32, u64>,
    /// State version seen when the last idle (final) sync started.
    #[serde(default)]
    pub idle_synced_version: u64,
    #[serde(default)]
    pub size_mb: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateInfo {
    pub pending: u32,
    pub reboot_required: bool,
    pub checked_at: u64,
    #[serde(default)]
    pub package_manager: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeReport {
    pub machine: u32,
    pub state_version: u64,
    pub agent_version: String,
    pub metrics: Metrics,
    pub instances: Vec<InstanceReport>,
    pub volumes: Vec<VolumeReport>,
    pub updates: UpdateInfo,
    /// Id of a finished maintenance task.
    #[serde(default)]
    pub maintenance_done: Option<String>,
    #[serde(default)]
    pub build_cache_gb: f64,
    /// Events raised on this machine since the last report.
    #[serde(default)]
    pub events: Vec<Event>,
    /// False when this machine's Docker daemon is not answering.
    #[serde(default = "yes")]
    pub docker_ok: bool,
}

// ---------------------------------------------------------------------------
// Routing table computed by the leader and pulled by every proxy.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Backend {
    pub instance: String,
    pub machine: u32,
    pub ip: String,
    pub ports: BTreeMap<u16, u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct AppRoute {
    pub app: String,
    pub vip: String,
    /// Hostnames routed to this app.
    pub hosts: Vec<String>,
    pub http_port: Option<u16>,
    pub force_https: bool,
    /// Internal TCP ports reachable on the VIP.
    pub ports: Vec<u16>,
    /// (public port, container port)
    pub public_ports: Vec<(u16, u16)>,
    pub backends: Vec<Backend>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Routes {
    pub apps: BTreeMap<String, AppRoute>,
    /// DNS names (without trailing dot) -> VIP.
    pub dns: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// Events (kept in memory on the leader, shown in status/dashboard).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: u64,
    pub level: String,
    pub message: String,
}
