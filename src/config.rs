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

use crate::util::{parse_duration, parse_size_mb, validate_name};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

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
    /// Only run on machines in these regions/locations (e.g. "ash" or
    /// ["ash", "hil"]). Empty = anywhere.
    #[serde(default, alias = "region", deserialize_with = "one_or_many", skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
    #[serde(default)]
    pub build: BuildConfig,
    /// Override the image's command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Command>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Public HTTP(S) service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpConfig>,
    /// Extra TCP ports (internal by default, reachable as `<app>.internal:<port>`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<PortConfig>,
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
        if self.build.image.is_some() && self.build.git.is_some() {
            bail!("[build] set either `image` or `git`, not both");
        }
        let (min, max) = self.scale.bounds();
        if max == 0 && min == 0 && self.scale.count != Some(0) {
            bail!("[scale] max must be at least 1");
        }
        if self.scale.cpu < 0.0 {
            bail!("[scale] cpu must be positive");
        }
        parse_size_mb(&self.scale.memory).context("[scale] memory")?;
        parse_duration(&self.deploy.health_timeout).context("[deploy] health_timeout")?;
        parse_duration(&self.deploy.stop_timeout).context("[deploy] stop_timeout")?;
        if !["rolling", "immediate"].contains(&self.deploy.strategy.as_str()) {
            bail!("[deploy] strategy must be \"rolling\" or \"immediate\"");
        }
        let mut seen = std::collections::BTreeSet::new();
        for v in &self.volumes {
            validate_name("volume", &v.name)?;
            if !seen.insert(v.name.clone()) {
                bail!("duplicate volume '{}'", v.name);
            }
            if !v.path.starts_with('/') {
                bail!("volume '{}' path must be absolute", v.name);
            }
            if v.copies == 0 {
                bail!("volume '{}' copies must be at least 1", v.name);
            }
            parse_duration(&v.sync).with_context(|| format!("volume '{}' sync", v.name))?;
            if let Some(sz) = &v.size {
                parse_size_mb(sz).with_context(|| format!("volume '{}' size", v.name))?;
            }
        }
        if !self.volumes.is_empty() && max > 1 {
            bail!(
                "apps with volumes run as a single instance (one writer per volume). \
                 Remove [scale] count/max > 1 — latrix keeps replicas of the volume on other \
                 machines and fails over automatically."
            );
        }
        for p in &self.ports {
            if !["tcp", "udp"].contains(&p.protocol.as_str()) {
                bail!("port {}: protocol must be \"tcp\" or \"udp\"", p.port);
            }
            if p.protocol == "udp" && !p.public {
                bail!("port {}: UDP ports must be public = true (they are published on the machine's IP)", p.port);
            }
        }
        for d in self.http.iter().flat_map(|h| h.domains.iter()) {
            if d.contains('/') || d.contains(':') || !d.contains('.') {
                bail!("invalid domain '{d}'");
            }
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
    let mut s = format!(
        "# latrix app config — https://github.com/jreoka/latrix\napp = \"{app}\"\n\n[build]\n"
    );
    match image {
        Some(img) => s.push_str(&format!("image = \"{img}\"\n")),
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
}
