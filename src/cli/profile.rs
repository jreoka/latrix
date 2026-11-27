//! Local CLI configuration (~/.config/latrix/config.toml): which clusters you
//! manage and how to reach their machines over SSH.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default)]
    pub clusters: BTreeMap<String, ClusterProfile>,
    /// Cloud provider API tokens (hetzner, digitalocean).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub providers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterProfile {
    pub token: String,
    /// The local dev cluster started with `latrix dev`.
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub machines: Vec<MachineSsh>,
    /// SSH key for machines latrix creates (used for ones the autopilot adds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_key: Option<String>,
    /// Set when this "cluster" is a Kubernetes cluster used as a deploy target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<K8sTarget>,
}

/// A Kubernetes cluster latrix deploys to (through kubectl).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct K8sTarget {
    /// kubeconfig context (default: kubectl's current context)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubeconfig: Option<String>,
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Registry for images built by `latrix deploy`, e.g. ghcr.io/you
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_class: Option<String>,
    /// cert-manager ClusterIssuer used for HTTPS (set by `latrix k8s setup-tls`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// Platform images are built for.
    #[serde(default = "default_platform")]
    pub platform: String,
    /// Every app with [http] also gets <app>.<base_domain>.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_domain: Option<String>,
}

pub fn default_namespace() -> String {
    "default".into()
}
pub fn default_platform() -> String {
    "linux/amd64".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineSsh {
    pub name: String,
    /// user@host
    pub ssh: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

fn default_port() -> u16 {
    22
}

impl CliConfig {
    pub fn path() -> PathBuf {
        if let Ok(p) = std::env::var("LATRIX_CONFIG") {
            return PathBuf::from(p);
        }
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("latrix")
            .join("config.toml")
    }

    pub fn load() -> Result<CliConfig> {
        let p = Self::path();
        if !p.exists() {
            return Ok(CliConfig::default());
        }
        let text = std::fs::read_to_string(&p)?;
        toml::from_str(&text).with_context(|| format!("invalid {}", p.display()))
    }

    pub fn save(&self) -> Result<()> {
        let p = Self::path();
        crate::util::write_atomic(&p, toml::to_string_pretty(self)?.as_bytes())?;
        crate::agent::set_private(&p);
        Ok(())
    }

    /// Resolve which cluster a command targets.
    pub fn cluster_name(&self, flag: Option<&str>) -> Result<String> {
        if let Some(f) = flag {
            if !self.clusters.contains_key(f) {
                bail!("unknown cluster '{f}' (see `latrix cluster list`)");
            }
            return Ok(f.to_string());
        }
        if let Some(c) = &self.current {
            if self.clusters.contains_key(c) {
                return Ok(c.clone());
            }
        }
        match self.clusters.len() {
            0 => Err(anyhow!(
                "no cluster configured yet.\n  • add a server:     latrix machine add root@<ip>\n  • or try it locally: latrix dev"
            )),
            1 => Ok(self.clusters.keys().next().unwrap().clone()),
            _ => Err(anyhow!("several clusters configured; pick one with `latrix cluster use <name>` or --cluster")),
        }
    }

    pub fn profile(&self, flag: Option<&str>) -> Result<(String, ClusterProfile)> {
        let name = self.cluster_name(flag)?;
        Ok((name.clone(), self.clusters[&name].clone()))
    }
}
