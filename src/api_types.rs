//! Request/response types shared between the CLI and the agent API.

use crate::config::AppConfig;
use crate::state::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub name: String,
    pub public_ip: String,
    pub wg_pubkey: String,
    pub os: String,
    pub arch: String,
    pub cpus: f64,
    pub memory_mb: u64,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub provider: Option<ProviderRef>,
    #[serde(default)]
    pub monthly_cost: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub machine: Machine,
    pub identity: crate::agent::NodeIdentity,
    pub state: ClusterState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineAction {
    /// drain | cordon | uncordon | update
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildPlan {
    pub machine: u32,
    pub machine_name: String,
    pub tag: String,
    pub cache_from: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BuildRequest {
    pub app: String,
    pub tag: String,
    #[serde(default)]
    pub dockerfile: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    #[serde(default)]
    pub git: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    /// Subdirectory of the git checkout to use as context.
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub cache_from: Vec<String>,
    /// Your terminal's width: when set, Docker's live colored progress view
    /// is streamed as-is (built in a pseudo-terminal of that width).
    #[serde(default)]
    pub tty_cols: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildResult {
    pub ok: bool,
    pub image: String,
    pub error: Option<String>,
    pub seconds: u64,
}

pub const BUILD_RESULT_PREFIX: &str = "LATRIX_RESULT ";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub config: AppConfig,
    pub image: String,
    #[serde(default)]
    pub builder: Option<u32>,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResponse {
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScaleRequest {
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub min: Option<u32>,
    #[serde(default)]
    pub max: Option<u32>,
    #[serde(default)]
    pub cpu: Option<f64>,
    #[serde(default)]
    pub memory: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretsRequest {
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub unset: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RollbackRequest {
    #[serde(default)]
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineView {
    pub machine: Machine,
    pub alive: bool,
    pub leader: bool,
    pub metrics: Option<Metrics>,
    pub updates: Option<UpdateInfo>,
    pub instances: usize,
    pub reserved_mb: u64,
    pub reserved_cpu: f64,
    pub agent_version: String,
    pub build_cache_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceView {
    pub instance: Instance,
    pub machine_name: String,
    pub report: Option<InstanceReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseView {
    pub version: u64,
    pub image: String,
    pub status: ReleaseStatus,
    pub created_at: u64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeView {
    pub volume: Volume,
    pub primary_name: String,
    pub replica_names: Vec<String>,
    pub report: Option<VolumeReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppView {
    pub name: String,
    pub group: Option<String>,
    pub current: u64,
    pub release_status: Option<ReleaseStatus>,
    pub image: String,
    pub count: u32,
    pub min: u32,
    pub max: u32,
    pub autoscale: bool,
    pub stateful: bool,
    pub cpu: f64,
    pub memory: String,
    pub urls: Vec<String>,
    pub internal: Vec<String>,
    pub instances: Vec<InstanceView>,
    pub releases: Vec<ReleaseView>,
    pub volumes: Vec<VolumeView>,
    pub secret_names: Vec<String>,
    pub config: Option<AppConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertView {
    pub domain: String,
    pub not_after: u64,
    pub issued_at: u64,
    #[serde(default)]
    pub unused_since: u64,
}

/// A domain still waiting for its certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCert {
    pub domain: String,
    pub reason: String,
    pub retry_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusView {
    pub cluster: String,
    pub version: u64,
    pub leader: Option<u32>,
    pub dev: bool,
    pub settings: Settings,
    pub machines: Vec<MachineView>,
    pub apps: Vec<AppView>,
    pub certs: Vec<CertView>,
    pub events: Vec<Event>,
    pub monthly_cost: f64,
    #[serde(default)]
    pub autopilot: Option<crate::agent::autopilot::Status>,
    #[serde(default)]
    pub certs_pending: Vec<PendingCert>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutopilotRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub budget: Option<f64>,
    #[serde(default)]
    pub min_machines: Option<u32>,
    #[serde(default)]
    pub max_machines: Option<u32>,
    /// provider -> API token
    #[serde(default)]
    pub tokens: BTreeMap<String, String>,
    /// SSH public keys to install on servers the autopilot creates.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutopilotView {
    pub enabled: bool,
    pub budget: f64,
    pub min_machines: u32,
    pub max_machines: u32,
    pub status: crate::agent::autopilot::Status,
}

/// Ask the leader to set up a server over SSH (it must accept the leader's key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionRequest {
    pub ssh: String,
    pub name: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub public_ip: Option<String>,
}

/// Everything needed to recreate an app elsewhere (used by backups).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppExport {
    pub config: AppConfig,
    pub image: String,
    /// Machines whose registry has the image (empty = public image).
    pub sources: Vec<u32>,
    pub secrets: BTreeMap<String, String>,
    pub count: u32,
    pub volumes: Vec<Volume>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
}
