//! `latrix.toml` — the per-app config file.
//!
//! The goal is that the smallest useful file is three lines:
//!
//! ```toml
//! app = "hello"
//! [http]
//! port = 8080
//! ```
//!
//! Everything else has a sensible default.

use crate::util::{
    parse_duration, parse_size_mb, validate_git_branch, validate_git_url, validate_image_ref,
    validate_name,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Unique app name (lowercase, digits, dashes).
    pub app: String,
    /// Optional stack/group name. Apps in the same group can reach each
    /// other by their short name (e.g. `db`) — used by compose imports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Short name inside the group (defaults to the app name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Extra DNS aliases inside the group (e.g. `app-proxy`, `admin`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Only run on machines in these regions/locations (e.g. "ash" or
    /// ["ash", "hil"]). Empty = anywhere.
    #[serde(default, alias = "region", deserialize_with = "one_or_many", skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
    #[serde(default)]
    pub build: BuildConfig,
    /// Override the image's command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Command>,
    /// Optional `/dev/shm` size (e.g. "1GB" for Postgres).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<String>,
    /// Optional `nofile` ulimit (e.g. 65536 for high-connection gateways).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nofile: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Public HTTP(S) service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,
    /// Extra TCP ports (internal by default, reachable as `<app>.internal:<port>`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortConfig>,
    /// Custom DNS records managed automatically when Cloudflare DNS is enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<DnsRecordConfig>,
    #[serde(default)]
    pub scale: ScaleConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeConfig>,
    #[serde(default)]
    pub deploy: DeployConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Command {
    Shell(String),
    Exec(Vec<String>),
}

impl Command {
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Command::Shell(s) => vec!["sh".into(), "-c".into(), s.clone()],
            Command::Exec(v) => v.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    /// Use a prebuilt image instead of building (e.g. "nginx:1.27").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Dockerfile path relative to the context (default "Dockerfile").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    /// Build context directory relative to latrix.toml (default ".").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    /// Build from a git repository on the cluster instead of uploading local files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Multi-stage build target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HttpConfig {
    /// Port the container listens on.
    pub port: u16,
    /// Custom domains. Point their DNS (A record) at any of your machines;
    /// latrix gets Let's Encrypt certificates automatically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    /// Health check path, e.g. "/healthz". Without it latrix checks that the port accepts connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    /// Redirect http -> https once a certificate exists (default true).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub force_https: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PortConfig {
    /// Container port.
    pub port: u16,
    /// Also expose on every machine's public IP (plain TCP, load balanced).
    #[serde(default)]
    pub public: bool,
    /// Public port if different from the container port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,
    /// "tcp" (default) or "udp". UDP ports must be public and are published
    /// directly on the IP of the machine running the app (game servers,
    /// voice, ...): no proxy hop, at most one instance per machine.
    #[serde(default = "tcp", skip_serializing_if = "is_tcp")]
    pub protocol: String,
}

/// A DNS record managed for an app (e.g. via Cloudflare DNS).
///
/// Omit `type` and `content` to automatically point A/AAAA records at the
/// cluster's machines (or for UDP apps, at the machine(s) running the app).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsRecordConfig {
    /// Fully-qualified DNS name, e.g. "play.example.com" or "_minecraft._tcp.play.example.com".
    pub name: String,
    /// Record type: "A", "AAAA", "CNAME", "TXT", "MX", "SRV", "CAA".
    /// Omit to auto-manage A/AAAA records pointing at the cluster/app IPs.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub record_type: Option<String>,
    /// Record target/value. Omit for auto-managed A/AAAA records pointing at cluster/app IPs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Cloudflare proxy (orange cloud). Omit to use `settings.cloudflare_proxied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxied: Option<bool>,
    /// TTL in seconds (1 = Auto in Cloudflare, or 60..=86400). Omit to use `settings.cloudflare_ttl`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// Priority for MX / SRV records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u16>,
}

/// Normalize a DNS hostname (trim, lowercase, strip trailing dot).
pub fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Validate an HTTP domain hostname strictly.
pub fn validate_domain(raw: &str) -> Result<String> {
    let d = normalize_dns_name(raw);
    if d.is_empty()
        || d.len() > 253
        || !d.contains('.')
        || d.starts_with('.')
        || d.contains("..")
        || d.contains('/')
        || d.contains(':')
        || d.contains('*')
        || d.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid domain '{raw}'");
    }
    for label in d.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("invalid domain '{raw}'");
        }
    }
    Ok(d)
}

/// Validate a DNS record configuration (used by `latrix.toml` and `latrix dns add`).
pub fn validate_dns_record(r: &DnsRecordConfig) -> Result<()> {
    let name = normalize_dns_name(&r.name);
    if name.is_empty()
        || !name.contains('.')
        || name.contains('/')
        || name.contains(':')
        || name.chars().any(|c| c.is_whitespace())
    {
        bail!("invalid DNS record name '{}'", r.name);
    }
    let ty = r.record_type.as_deref().map(|t| t.trim().to_ascii_uppercase());
    let content = r.content.as_deref().map(str::trim).filter(|c| !c.is_empty());
    let resolved_ty = match (ty.as_deref(), content) {
        (Some(t), _) => {
            if !matches!(t, "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "SRV" | "CAA") {
                bail!("DNS record '{}': unsupported type '{t}' (supported: A, AAAA, CNAME, TXT, MX, SRV, CAA)", r.name);
            }
            Some(t)
        }
        (None, Some(c)) => {
            if c.parse::<std::net::Ipv4Addr>().is_ok() {
                Some("A")
            } else if c.parse::<std::net::Ipv6Addr>().is_ok() {
                Some("AAAA")
            } else {
                bail!("DNS record '{}': set `type` (e.g. CNAME, TXT, MX, SRV, CAA) when providing `content`", r.name);
            }
        }
        (None, None) => None, // auto A/AAAA
    };
    match (resolved_ty, content) {
        (Some("A"), Some(c)) => {
            if c.parse::<std::net::Ipv4Addr>().is_err() {
                bail!("DNS record '{}': A record content '{c}' must be an IPv4 address", r.name);
            }
        }
        (Some("AAAA"), Some(c)) => {
            if c.parse::<std::net::Ipv6Addr>().is_err() {
                bail!("DNS record '{}': AAAA record content '{c}' must be an IPv6 address", r.name);
            }
        }
        (Some(t @ ("CNAME" | "TXT" | "MX" | "SRV" | "CAA")), None) => {
            bail!("DNS record '{}': {t} record requires `content`", r.name);
        }
        _ => {}
    }
    if let Some(true) = r.proxied {
        if matches!(resolved_ty, Some("TXT" | "MX" | "SRV" | "CAA")) {
            bail!(
                "DNS record '{}': only A, AAAA and CNAME records can be proxied by Cloudflare",
                r.name
            );
        }
    }
    if let Some(ttl) = r.ttl {
        if ttl != 1 && !(60..=86400).contains(&ttl) {
            bail!("DNS record '{}': ttl must be 1 (auto) or between 60 and 86400 seconds", r.name);
        }
    }
    Ok(())
}

fn tcp() -> String {
    "tcp".into()
}
fn is_tcp(p: &String) -> bool {
    p == "tcp"
}

fn one_or_many<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScaleConfig {
    /// Fixed number of instances. Ignored when min/max are set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    /// Autoscaling lower bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<u32>,
    /// Autoscaling upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
    /// CPU cores per instance (limit + scheduling weight).
    #[serde(default = "default_cpu")]
    pub cpu: f64,
    /// Memory per instance, e.g. "256MB" or "1GB".
    #[serde(default = "default_memory")]
    pub memory: String,
}

fn default_cpu() -> f64 {
    0.5
}
fn default_memory() -> String {
    "256MB".into()
}

impl Default for ScaleConfig {
    fn default() -> Self {
        ScaleConfig {
            count: None,
            min: None,
            max: None,
            cpu: default_cpu(),
            memory: default_memory(),
        }
    }
}

impl ScaleConfig {
    pub fn memory_mb(&self) -> u64 {
        parse_size_mb(&self.memory).unwrap_or(256)
    }
    /// (min, max) instance counts.
    pub fn bounds(&self) -> (u32, u32) {
        match (self.min, self.max) {
            (Some(min), Some(max)) => (min, max.max(min)),
            (Some(min), None) => (min, min.max(self.count.unwrap_or(min))),
            (None, Some(max)) => (1.min(max), max),
            (None, None) => {
                let c = self.count.unwrap_or(1);
                (c, c)
            }
        }
    }
    pub fn autoscale(&self) -> bool {
        let (min, max) = self.bounds();
        max > min
    }
    pub fn initial(&self) -> u32 {
        let (min, max) = self.bounds();
        self.count.unwrap_or(min).clamp(min, max)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VolumeConfig {
    pub name: String,
    /// Mount path inside the container.
    pub path: String,
    /// Total copies kept across machines (primary + replicas). Default 2.
    #[serde(default = "default_copies")]
    pub copies: u32,
    /// How often changes are replicated, e.g. "30s".
    #[serde(default = "default_sync")]
    pub sync: String,
    /// Optional command run inside the container before each sync
    /// (e.g. "sqlite3 /data/db.sqlite '.backup /data/db.backup'").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pre_sync: Option<String>,
    /// Size to request on Kubernetes (PersistentVolumeClaim), e.g. "20GB".
    /// latrix's own machines don't need it (volumes use the machine's disk).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

fn default_copies() -> u32 {
    2
}
fn default_sync() -> String {
    "30s".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeployConfig {
    /// "rolling" (default, zero downtime) or "immediate".
    #[serde(default = "default_strategy")]
    pub strategy: String,
    /// How long a new instance may take to become healthy before the
    /// release is rolled back automatically.
    #[serde(default = "default_health_timeout")]
    pub health_timeout: String,
    /// Grace period for stopping containers.
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout: String,
}

fn default_strategy() -> String {
    "rolling".into()
}
fn default_health_timeout() -> String {
    "90s".into()
}
fn default_stop_timeout() -> String {
    "10s".into()
}

impl Default for DeployConfig {
    fn default() -> Self {
        DeployConfig {
            strategy: default_strategy(),
            health_timeout: default_health_timeout(),
            stop_timeout: default_stop_timeout(),
        }
    }
}

impl DeployConfig {
    pub fn health_timeout_secs(&self) -> u64 {
        parse_duration(&self.health_timeout)
            .map(|d| d.as_secs())
            .unwrap_or(90)
    }
    pub fn stop_timeout_secs(&self) -> u64 {
        parse_duration(&self.stop_timeout)
            .map(|d| d.as_secs())
            .unwrap_or(10)
    }
    pub fn rolling(&self) -> bool {
        self.strategy != "immediate"
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<AppConfig> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        let cfg: AppConfig =
            toml::from_str(&text).with_context(|| format!("invalid {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        validate_name("app", &self.app)?;
        if let Some(g) = &self.group {
            validate_name("group", g)?;
        }
        if let Some(s) = &self.service {
            validate_name("service", s)?;
        }
        for a in &self.aliases {
            validate_name("alias", a)?;
        }
        if let Some(shm) = &self.shm_size {
            if parse_size_mb(shm).context("shm_size")? == 0 {
                bail!("shm_size must be at least 1MB");
            }
        }
        if self.build.image.is_some() && self.build.git.is_some() {
            bail!("[build] set either `image` or `git`, not both");
        }
        if let Some(img) = &self.build.image {
            validate_image_ref(img).context("[build] image")?;
        }
        if let Some(git) = &self.build.git {
            validate_git_url(git).context("[build] git")?;
        }
        if let Some(branch) = &self.build.branch {
            validate_git_branch(branch).context("[build] branch")?;
        }
        for (k, v) in &self.env {
            if k.is_empty() || k.contains(['=', '\0', '\r', '\n']) {
                bail!("[env] invalid variable name '{k}'");
            }
            if v.contains('\0') {
                bail!("[env] variable '{k}' cannot contain NUL bytes");
            }
        }
        if let (Some(min), Some(max)) = (self.scale.min, self.scale.max) {
            if min > max {
                bail!("[scale] min ({min}) cannot exceed max ({max})");
            }
        }
        let (min, max) = self.scale.bounds();
        if max == 0 && min == 0 && self.scale.count != Some(0) {
            bail!("[scale] max must be at least 1");
        }
        if !self.scale.cpu.is_finite() || self.scale.cpu < 0.0 {
            bail!("[scale] cpu must be a finite non-negative number");
        }
        if parse_size_mb(&self.scale.memory).context("[scale] memory")? == 0 {
            bail!("[scale] memory must be at least 1MB");
        }
        let ht = parse_duration(&self.deploy.health_timeout).context("[deploy] health_timeout")?;
        if ht.as_secs() == 0 || ht.as_secs() > 86_400 {
            bail!("[deploy] health_timeout must be between 1s and 24h");
        }
        let st = parse_duration(&self.deploy.stop_timeout).context("[deploy] stop_timeout")?;
        if st.as_secs() > 3_600 {
            bail!("[deploy] stop_timeout must be at most 1h");
        }
        if !["rolling", "immediate"].contains(&self.deploy.strategy.as_str()) {
            bail!("[deploy] strategy must be \"rolling\" or \"immediate\"");
        }
        let mut seen = BTreeSet::new();
        for v in &self.volumes {
            validate_name("volume", &v.name)?;
            if !seen.insert(v.name.clone()) {
                bail!("duplicate volume '{}'", v.name);
            }
            if !v.path.starts_with('/') {
                bail!("volume '{}' path must be absolute", v.name);
            }
            if v.path == "/"
                || v.path == "/__latrix_vol"
                || v.path.contains(':')
                || v.path.chars().any(|c| c.is_control())
                || Path::new(&v.path)
                    .components()
                    .any(|c| matches!(c, Component::ParentDir))
            {
                bail!("volume '{}' has an invalid mount path '{}'", v.name, v.path);
            }
            if v.copies == 0 {
                bail!("volume '{}' copies must be at least 1", v.name);
            }
            let sync = parse_duration(&v.sync).with_context(|| format!("volume '{}' sync", v.name))?;
            if sync.as_secs() == 0 {
                bail!("volume '{}' sync interval must be at least 1s", v.name);
            }
            if let Some(sz) = &v.size {
                if parse_size_mb(sz).with_context(|| format!("volume '{}' size", v.name))? == 0 {
                    bail!("volume '{}' size must be at least 1MB", v.name);
                }
            }
        }
        if !self.volumes.is_empty() && max > 1 {
            bail!(
                "apps with volumes run as a single instance (one writer per volume). \
                 Remove [scale] count/max > 1 — latrix keeps replicas of the volume on other \
                 machines and fails over automatically."
            );
        }
        if let Some(h) = &self.http {
            if h.port == 0 {
                bail!("[http] port must be 1-65535");
            }
            if let Some(path) = &h.health {
                if !path.starts_with('/')
                    || path.starts_with("//")
                    || path.chars().any(|c| c.is_whitespace() || c.is_control())
                {
                    bail!("[http] invalid health path '{path}' (must start with '/' and contain no whitespace)");
                }
            }
            for d in &h.domains {
                validate_domain(d)?;
            }
        }
        let mut seen_public = BTreeSet::new();
        for p in &self.ports {
            if p.port == 0 {
                bail!("port must be 1-65535");
            }
            if p.public_port == Some(0) {
                bail!("port {}: public_port must be 1-65535", p.port);
            }
            if !["tcp", "udp"].contains(&p.protocol.as_str()) {
                bail!("port {}: protocol must be \"tcp\" or \"udp\"", p.port);
            }
            if p.protocol == "udp" && !p.public {
                bail!("port {}: UDP ports must be public = true (they are published on the machine's IP)", p.port);
            }
            if p.public {
                let pub_p = p.public_port.unwrap_or(p.port);
                if !seen_public.insert((p.protocol.clone(), pub_p)) {
                    bail!("duplicate public {} port {pub_p}", p.protocol);
                }
            }
        }
        for r in &self.dns {
            validate_dns_record(r)?;
        }
        Ok(())
    }

    /// All container ports that should be reachable (http + extra).
    /// TCP ports (http + extra) the proxy and health checks use.
    pub fn container_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.http.iter().map(|h| h.port).collect();
        for p in self.ports.iter().filter(|p| p.protocol == "tcp") {
            if !ports.contains(&p.port) {
                ports.push(p.port);
            }
        }
        ports
    }

    /// UDP ports, published directly on the machine: (public port, container port).
    pub fn udp_ports(&self) -> Vec<(u16, u16)> {
        self.ports
            .iter()
            .filter(|p| p.protocol == "udp")
            .map(|p| (p.public_port.unwrap_or(p.port), p.port))
            .collect()
    }

    /// Is machine `region` allowed for this app?
    pub fn allows_region(&self, region: Option<&str>) -> bool {
        self.regions.is_empty() || region.map(|r| self.regions.iter().any(|x| x == r)).unwrap_or(false)
    }

    pub fn service_name(&self) -> &str {
        self.service.as_deref().unwrap_or(&self.app)
    }

    pub fn stateful(&self) -> bool {
        !self.volumes.is_empty()
    }
}

/// A starter config written by `latrix launch`.
pub fn template(app: &str, port: Option<u16>, image: Option<&str>) -> String {
    let app_q = serde_json::to_string(app).unwrap_or_else(|_| format!("\"{app}\""));
    let mut s = format!(
        "# latrix app config — https://github.com/jreoka/latrix\napp = {app_q}\n\n[build]\n"
    );
    match image {
        Some(img) => {
            let img_q = serde_json::to_string(img).unwrap_or_else(|_| format!("\"{img}\""));
            s.push_str(&format!("image = {img_q}\n"));
        }
        None => s.push_str("# Builds the Dockerfile in this directory on the cluster.\n# dockerfile = \"Dockerfile\"\n# image = \"nginx:1.27\"   # or deploy a prebuilt image\n"),
    }
    if let Some(p) = port {
        s.push_str(&format!(
            "\n[http]\nport = {p}\n# domains = [\"{app}.example.com\"]   # HTTPS certificates are automatic\n# health = \"/healthz\"\n"
        ));
    }
    s.push_str(
        "\n[scale]\ncount = 2          # or set min/max for autoscaling\n# min = 1\n# max = 5\ncpu = 0.5\nmemory = \"256MB\"\n\n[env]\n# LOG_LEVEL = \"info\"\n\n# [[volumes]]          # replicated across machines; implies a single instance\n# name = \"data\"\n# path = \"/data\"\n# copies = 2\n",
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal() {
        let c: AppConfig = toml::from_str("app = \"hello\"\n[http]\nport = 8080\n").unwrap();
        c.validate().unwrap();
        assert_eq!(c.scale.bounds(), (1, 1));
        assert_eq!(c.container_ports(), vec![8080]);
        assert!(!c.scale.autoscale());
    }

    #[test]
    fn autoscale_bounds() {
        let c: AppConfig =
            toml::from_str("app = \"x\"\n[scale]\nmin = 2\nmax = 6\n").unwrap();
        assert!(c.scale.autoscale());
        assert_eq!(c.scale.initial(), 2);
    }

    #[test]
    fn volumes_force_single_instance() {
        let c: AppConfig = toml::from_str(
            "app = \"db\"\n[scale]\ncount = 3\n[[volumes]]\nname = \"data\"\npath = \"/data\"\n",
        )
        .unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn template_parses() {
        let t = template("demo", Some(3000), None);
        let c: AppConfig = toml::from_str(&t).unwrap();
        c.validate().unwrap();
        let t = template("demo", None, Some("redis:7"));
        let c: AppConfig = toml::from_str(&t).unwrap();
        c.validate().unwrap();
    }

    #[test]
    fn examples_are_valid() {
        for text in [
            include_str!("../examples/web/latrix.toml"),
            include_str!("../examples/postgres/latrix.toml"),
            include_str!("../examples/worker/latrix.toml"),
        ] {
            let c: AppConfig = toml::from_str(text).unwrap();
            c.validate().unwrap();
        }
    }

    #[test]
    fn regions_and_udp() {
        let c: AppConfig = toml::from_str(
            "app = \"game\"\nregion = \"ash\"\n[[ports]]\nport = 7777\nprotocol = \"udp\"\npublic = true\n[[ports]]\nport = 8080\n",
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.regions, vec!["ash"]);
        assert_eq!(c.udp_ports(), vec![(7777, 7777)]);
        assert_eq!(c.container_ports(), vec![8080]);
        assert!(c.allows_region(Some("ash")) && !c.allows_region(Some("fsn1")) && !c.allows_region(None));
        let many: AppConfig = toml::from_str("app = \"x\"\nregions = [\"ash\", \"hil\"]\n").unwrap();
        assert_eq!(many.regions.len(), 2);
        let bad: AppConfig = toml::from_str("app = \"x\"\n[[ports]]\nport = 1\nprotocol = \"udp\"\n").unwrap();
        assert!(bad.validate().is_err(), "udp must be public");
    }

    #[test]
    fn unknown_fields_rejected() {
        assert!(toml::from_str::<AppConfig>("app = \"x\"\nbogus = 1\n").is_err());
    }

    #[test]
    fn dns_records_parse_and_validate() {
        let c: AppConfig = toml::from_str(
            r#"
app = "shop"
[http]
port = 3000
domains = ["shop.example.com"]
[[dns]]
name = "play.example.com"
[[dns]]
name = "www.shop.example.com"
type = "CNAME"
content = "shop.example.com"
proxied = true
[[dns]]
name = "shop.example.com"
type = "TXT"
content = "v=spf1 -all"
ttl = 300
"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.dns.len(), 3);

        // TXT cannot be proxied
        let bad_proxy: AppConfig = toml::from_str(
            "app = \"x\"\n[[dns]]\nname = \"a.example.com\"\ntype = \"TXT\"\ncontent = \"hi\"\nproxied = true\n",
        )
        .unwrap();
        assert!(bad_proxy.validate().is_err());

        // CNAME requires content
        let bad_cname: AppConfig = toml::from_str(
            "app = \"x\"\n[[dns]]\nname = \"a.example.com\"\ntype = \"CNAME\"\n",
        )
        .unwrap();
        assert!(bad_cname.validate().is_err());

        // Invalid TTL
        let bad_ttl: AppConfig = toml::from_str(
            "app = \"x\"\n[[dns]]\nname = \"a.example.com\"\nttl = 10\n",
        )
        .unwrap();
        assert!(bad_ttl.validate().is_err());
    }

    #[test]
    fn aliases_shm_and_nofile_validate() {
        let c: AppConfig = toml::from_str(
            "app = \"fluxer-rust\"\ngroup = \"fluxer\"\nservice = \"rust\"\naliases = [\"app-proxy\", \"admin\"]\nshm_size = \"1GB\"\nnofile = 65536\n",
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.aliases, vec!["app-proxy", "admin"]);
        assert_eq!(c.shm_size.as_deref(), Some("1GB"));
        assert_eq!(c.nofile, Some(65536));

        let bad_shm: AppConfig = toml::from_str("app = \"x\"\nshm_size = \"bogus\"\n").unwrap();
        assert!(bad_shm.validate().is_err());
    }

    #[test]
    fn validation_catches_edge_cases_and_injections() {
        assert!(validate_domain("sub-1.example.com").is_ok());
        assert!(validate_domain("*.example.com").is_err());
        assert!(validate_domain("https://example.com").is_err());
        assert!(validate_domain("bad host.com").is_err());
        assert!(validate_domain("example.com/path").is_err());
        assert!(validate_domain("-bad.example.com").is_err());

        // Non-finite / negative CPU
        let mut c: AppConfig = toml::from_str("app = \"x\"\n").unwrap();
        c.scale.cpu = f64::NAN;
        assert!(c.validate().is_err());
        c.scale.cpu = -1.0;
        assert!(c.validate().is_err());

        // Zero port, zero memory, min > max, duplicate public ports
        assert!(toml::from_str::<AppConfig>("app = \"x\"\n[http]\nport = 0\n").unwrap().validate().is_err());
        assert!(toml::from_str::<AppConfig>("app = \"x\"\n[scale]\nmemory = \"0MB\"\n").unwrap().validate().is_err());
        assert!(toml::from_str::<AppConfig>("app = \"x\"\n[scale]\nmin = 5\nmax = 2\n").unwrap().validate().is_err());
        assert!(toml::from_str::<AppConfig>(
            "app = \"x\"\n[[ports]]\nport = 8080\npublic = true\n[[ports]]\nport = 9090\npublic = true\npublic_port = 8080\n"
        )
        .unwrap()
        .validate()
        .is_err());

        // Volume path traversal or root mount
        assert!(toml::from_str::<AppConfig>("app = \"x\"\n[[volumes]]\nname = \"v\"\npath = \"/\"\n").unwrap().validate().is_err());
        assert!(toml::from_str::<AppConfig>("app = \"x\"\n[[volumes]]\nname = \"v\"\npath = \"/data/../etc\"\n").unwrap().validate().is_err());

        // Invalid git URL / branch
        assert!(toml::from_str::<AppConfig>("app = \"x\"\n[build]\ngit = \"--upload-pack=id\"\n").unwrap().validate().is_err());
        assert!(toml::from_str::<AppConfig>("app = \"x\"\n[build]\ngit = \"https://github.com/a/b.git\"\nbranch = \"-bad\"\n").unwrap().validate().is_err());

        // Template escapes quotes in image string cleanly
        let t = template("demo", Some(8080), Some("my\"img"));
        let parsed: AppConfig = toml::from_str(&t).unwrap();
        assert_eq!(parsed.build.image.as_deref(), Some("my\"img"));
    }
}
