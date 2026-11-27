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
    #[serde(default)]
    pub dns_records: Vec<crate::config::DnsRecordConfig>,
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
    #[serde(default)]
    pub dns: Option<DnsSummary>,
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

/// `latrix keys`: SSH keys every machine accepts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SshKeysRequest {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SshKeysView {
    pub keys: Vec<String>,
    /// The cluster's own key (used to set up servers); always accepted.
    pub cluster_key: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_records: Vec<crate::config::DnsRecordConfig>,
}

// ---------------------------------------------------------------------------
// Cloudflare DNS management

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudflareSetupRequest {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub remove: bool,
    #[serde(default)]
    pub proxied: Option<bool>,
    #[serde(default)]
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsRecordRemove {
    pub name: String,
    #[serde(default, rename = "type")]
    pub record_type: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppDnsRequest {
    #[serde(default)]
    pub add: Vec<crate::config::DnsRecordConfig>,
    #[serde(default)]
    pub remove: Vec<DnsRecordRemove>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecordStatus {
    pub app: Option<String>,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub proxied: bool,
    pub ttl: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
    /// Where this record came from: "http" | "config" | "cli" | "base_domain"
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// "synced" | "pending" | "disabled" | "no_zone" | "error"
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsStatusView {
    pub configured: bool,
    pub proxied_default: bool,
    pub ttl_default: u32,
    pub base_domain: String,
    pub zones: Vec<String>,
    pub last_sync: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub records: Vec<DnsRecordStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsSyncResult {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub errors: Vec<String>,
    pub status: DnsStatusView,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsSummary {
    pub configured: bool,
    pub zones: Vec<String>,
    pub records: Vec<DnsRecordStatus>,
    pub last_sync: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
}

// ---------------------------------------------------------------------------
// Fluxer (`latrix rexctl`) management

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlServiceStatus {
    pub service: String,
    pub app: String,
    pub image: String,
    pub status: String,
    pub healthy: usize,
    pub desired: u32,
    pub machines: Vec<String>,
    pub memory: String,
    pub release: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlStatusView {
    pub installed: bool,
    pub project: String,
    pub domain: String,
    pub release: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_release: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_available: Option<String>,
    pub auto_upgrade: bool,
    pub upgrade_interval_hours: u64,
    pub upgrading: Option<String>,
    pub last_check: u64,
    pub last_upgrade: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub storage: String,
    pub bundled_voice: bool,
    pub voice_endpoints: Vec<String>,
    pub kv_mode: String,
    pub rust_mode: String,
    pub cert_ready: bool,
    pub services: Vec<RexctlServiceStatus>,
    /// Masked settings for safe display (secrets redacted).
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlUpgradeRequest {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlUpgradeResult {
    pub upgraded: bool,
    pub from_release: String,
    pub to_release: String,
    pub updated_services: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlAutoUpgradeRequest {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub interval_hours: Option<u64>,
    #[serde(default)]
    pub check_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlConfigRequest {
    #[serde(default)]
    pub set: BTreeMap<String, String>,
    #[serde(default)]
    pub unset: Vec<String>,
}
