//! Automatic Cloudflare DNS management.
//!
//! When a Cloudflare API token is configured (`latrix dns cloudflare <token>`),
//! the leader reconciles DNS records in Cloudflare automatically:
//!
//! * `[http] domains` on every app → A/AAAA records pointing to the cluster's
//!   healthy machines (updated automatically as machines join, leave, drain,
//!   fail over or get bought by the autopilot).
//! * `settings.base_domain` → wildcard `*.<base_domain>` A/AAAA records.
//! * `[[dns]]` in `latrix.toml` and `latrix dns add` records on each app →
//!   auto-IP A/AAAA records (pointing to the specific machine(s) running the
//!   app for UDP apps, or cluster machines otherwise), OR explicit records
//!   (A, AAAA, CNAME, TXT, MX, SRV, CAA) with per-record `proxied` / `ttl` /
//!   `priority`.
//!
//! Only records created/owned by latrix (tracked in replicated cluster state
//! and tagged with `comment = "latrix:<cluster>"`) are deleted when an app or
//! domain is removed; unrelated records in your Cloudflare zones are never
//! touched.

use super::scheduler::{self, LiveView};
use super::Agent;
use crate::api_types::{DnsRecordStatus, DnsStatusView, DnsSummary, DnsSyncResult};
use crate::config::{normalize_dns_name, DnsRecordConfig};
use crate::state::{ClusterState, MachineStatus, ManagedDnsRecord};
use crate::util::now;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};

pub const CF_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Shared state on the Agent for Cloudflare DNS.
#[derive(Default)]
pub struct Shared {
    pub status: Mutex<RuntimeStatus>,
    pub wake: tokio::sync::Notify,
    pub sync_lock: tokio::sync::Mutex<()>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeStatus {
    pub zones: Vec<CfZone>,
    pub last_sync: u64,
    pub last_error: Option<String>,
    pub record_errors: BTreeMap<String, String>,
    pub last_fingerprint: String,
    pub last_warned: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfZone {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CfRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub priority: Option<u16>,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredRecord {
    pub app: Option<String>,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub proxied: bool,
    pub ttl: u32,
    pub priority: Option<u16>,
    /// Where it came from: "http" | "config" | "cli" | "base_domain"
    pub source: String,
    /// True when content was automatically derived from machine IPs.
    pub auto_ip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    Create(DesiredRecord),
    Update { id: String, desired: DesiredRecord },
    Delete { id: String, name: String, record_type: String, content: String },
}

pub fn comment_tag(cluster: &str) -> String {
    let tag = format!("latrix:{cluster}");
    tag.chars().take(100).collect()
}

pub fn is_proxyable(record_type: &str) -> bool {
    matches!(record_type, "A" | "AAAA" | "CNAME")
}

pub fn eligible_domain(d: &str) -> bool {
    let d = normalize_dns_name(d);
    !d.is_empty()
        && d.contains('.')
        && !d.ends_with(".localhost")
        && !d.ends_with(".internal")
        && !d.ends_with(".sslip.io")
        && d.parse::<IpAddr>().is_err()
}

/// Find the most specific Cloudflare zone for `name` (longest suffix match).
pub fn find_zone<'a>(zones: &'a [CfZone], name: &str) -> Option<&'a CfZone> {
    let n = normalize_dns_name(name);
    let n = n.strip_prefix("*.").unwrap_or(&n);
    zones
        .iter()
        .filter(|z| {
            let zn = normalize_dns_name(&z.name);
            n == zn || n.ends_with(&format!(".{zn}"))
        })
        .max_by_key(|z| z.name.len())
}

fn parse_public_ip(s: &str) -> Option<IpAddr> {
    let ip: IpAddr = s.trim().parse().ok()?;
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip)
}

/// Public IPs of machines that should receive cluster-wide traffic (HTTP proxy,
/// public TCP, wildcard `base_domain`).
///
/// Prefers alive `Ready` or `Cordoned` machines; falls back to any alive
/// machine, then all machines in state (so DNS never drops to zero IPs during
/// transient blips or single-machine maintenance).
pub fn target_ips(s: &ClusterState, live: &LiveView) -> (Vec<String>, Vec<String>) {
    let collect = |machines: Vec<&crate::state::Machine>| -> (Vec<String>, Vec<String>) {
        let mut v4 = BTreeSet::new();
        let mut v6 = BTreeSet::new();
        for m in machines {
            if let Some(ip) = parse_public_ip(&m.public_ip) {
                match ip {
                    IpAddr::V4(a) => {
                        v4.insert(a.to_string());
                    }
                    IpAddr::V6(a) => {
                        v6.insert(a.to_string());
                    }
                }
            }
        }
        (v4.into_iter().collect(), v6.into_iter().collect())
    };

    let active: Vec<_> = s
        .machines
        .values()
        .filter(|m| {
            live.is_alive(m.id) && matches!(m.status, MachineStatus::Ready | MachineStatus::Cordoned)
        })
        .collect();
    let res = collect(active);
    if !res.0.is_empty() || !res.1.is_empty() {
        return res;
    }
    let alive: Vec<_> = s.machines.values().filter(|m| live.is_alive(m.id)).collect();
    let res = collect(alive);
    if !res.0.is_empty() || !res.1.is_empty() {
        return res;
    }
    collect(s.machines.values().collect())
}

/// Public IPs of machines running non-stopping instances of a UDP-direct app.
pub fn app_direct_ips(s: &ClusterState, live: &LiveView, app: &str) -> (Vec<String>, Vec<String>) {
    let collect = |only_alive: bool| -> (Vec<String>, Vec<String>) {
        let mut v4 = BTreeSet::new();
        let mut v6 = BTreeSet::new();
        for i in s.instances_of(app).filter(|i| !i.stopping) {
            if only_alive && !live.is_alive(i.machine) {
                continue;
            }
            if let Some(m) = s.machines.get(&i.machine) {
                if let Some(ip) = parse_public_ip(&m.public_ip) {
                    match ip {
                        IpAddr::V4(a) => {
                            v4.insert(a.to_string());
                        }
                        IpAddr::V6(a) => {
                            v6.insert(a.to_string());
                        }
                    }
                }
            }
        }
        (v4.into_iter().collect(), v6.into_iter().collect())
    };
    let res = collect(true);
    if !res.0.is_empty() || !res.1.is_empty() {
        return res;
    }
    collect(false)
}

fn effective_ttl(proxied: bool, ttl: u32) -> u32 {
    if proxied {
        1
    } else if ttl == 1 || (60..=86400).contains(&ttl) {
        ttl
    } else {
        60
    }
}

fn record_spec_key(r: &DnsRecordConfig) -> (String, String) {
    let name = normalize_dns_name(&r.name);
    let ty = match (r.record_type.as_deref(), r.content.as_deref()) {
        (Some(t), _) => t.trim().to_ascii_uppercase(),
        (None, Some(c)) if c.trim().parse::<std::net::Ipv4Addr>().is_ok() => "A".into(),
        (None, Some(c)) if c.trim().parse::<std::net::Ipv6Addr>().is_ok() => "AAAA".into(),
        _ => "AUTO".into(),
    };
    (name, ty)
}

/// Compute every DNS record the cluster wants in Cloudflare right now.
pub fn desired_records(s: &ClusterState, live: &LiveView) -> Vec<DesiredRecord> {
    let (cluster_v4, cluster_v6) = target_ips(s, live);
    let default_proxied = s.settings.cloudflare_proxied;
    let default_ttl = s.settings.cloudflare_ttl;

    let mut out: Vec<DesiredRecord> = vec![];
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();

    fn push_unique(
        out: &mut Vec<DesiredRecord>,
        seen: &mut BTreeSet<(String, String, String)>,
        rec: DesiredRecord,
    ) {
        let key = (
            rec.name.clone(),
            rec.record_type.clone(),
            normalize_content(&rec.record_type, &rec.content),
        );
        if seen.insert(key) {
            out.push(rec);
        }
    }

    for (app_name, app) in &s.apps {
        let cfg = app.config();
        let is_direct = cfg.map(scheduler::direct).unwrap_or(false);
        let (ips_v4, ips_v6) = if is_direct {
            let direct = app_direct_ips(s, live, app_name);
            if direct.0.is_empty() && direct.1.is_empty() {
                // App not scheduled onto a machine yet; skip until placed.
                (vec![], vec![])
            } else {
                direct
            }
        } else {
            (cluster_v4.clone(), cluster_v6.clone())
        };

        // Merge latrix.toml [[dns]] with CLI-managed app.dns_records.
        // CLI records override config records with the same (name, type).
        let mut combined: Vec<(DnsRecordConfig, &'static str)> = vec![];
        let cli_keys: BTreeSet<(String, String)> = app.dns_records.iter().map(record_spec_key).collect();
        if let Some(c) = cfg {
            for r in &c.dns {
                if !cli_keys.contains(&record_spec_key(r)) {
                    combined.push((r.clone(), "config"));
                }
            }
        }
        for r in &app.dns_records {
            combined.push((r.clone(), "cli"));
        }

        // Track hostnames explicitly handled as A/AAAA/CNAME/AUTO so [http].domains
        // doesn't duplicate or fight an explicit [[dns]] / CLI override.
        let mut covered_hosts: BTreeSet<String> = BTreeSet::new();

        for (r, source) in combined {
            let name = normalize_dns_name(&r.name);
            if !eligible_domain(&name) {
                continue;
            }
            let content_opt = r
                .content
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(String::from);
            let ty_opt = r
                .record_type
                .as_deref()
                .map(|t| t.trim().to_ascii_uppercase())
                .filter(|t| !t.is_empty());

            match content_opt {
                None => {
                    // Auto-IP A/AAAA record(s)
                    covered_hosts.insert(name.clone());
                    let proxied = if is_direct {
                        false
                    } else {
                        r.proxied.unwrap_or(default_proxied)
                    };
                    let ttl = effective_ttl(proxied, r.ttl.unwrap_or(default_ttl));
                    let want_v4 = matches!(ty_opt.as_deref(), None | Some("A"));
                    let want_v6 = matches!(ty_opt.as_deref(), None | Some("AAAA"));
                    if want_v4 {
                        for ip in &ips_v4 {
                            push_unique(&mut out, &mut seen, DesiredRecord {
                                app: Some(app_name.clone()),
                                name: name.clone(),
                                record_type: "A".into(),
                                content: ip.clone(),
                                proxied,
                                ttl,
                                priority: None,
                                source: source.into(),
                                auto_ip: true,
                            });
                        }
                    }
                    if want_v6 {
                        for ip in &ips_v6 {
                            push_unique(&mut out, &mut seen, DesiredRecord {
                                app: Some(app_name.clone()),
                                name: name.clone(),
                                record_type: "AAAA".into(),
                                content: ip.clone(),
                                proxied,
                                ttl,
                                priority: None,
                                source: source.into(),
                                auto_ip: true,
                            });
                        }
                    }
                }
                Some(content) => {
                    let record_type = match ty_opt {
                        Some(t) => t,
                        None if content.parse::<std::net::Ipv4Addr>().is_ok() => "A".into(),
                        None if content.parse::<std::net::Ipv6Addr>().is_ok() => "AAAA".into(),
                        None => continue,
                    };
                    if matches!(record_type.as_str(), "A" | "AAAA" | "CNAME") {
                        covered_hosts.insert(name.clone());
                    }
                    let proxied = if is_proxyable(&record_type) {
                        r.proxied.unwrap_or(if is_direct { false } else { default_proxied })
                    } else {
                        false
                    };
                    let ttl = effective_ttl(proxied, r.ttl.unwrap_or(default_ttl));
                    let priority = if record_type == "MX" {
                        Some(r.priority.unwrap_or(10))
                    } else {
                        r.priority
                    };
                    push_unique(&mut out, &mut seen, DesiredRecord {
                        app: Some(app_name.clone()),
                        name,
                        record_type,
                        content,
                        proxied,
                        ttl,
                        priority,
                        source: source.into(),
                        auto_ip: false,
                    });
                }
            }
        }

        // Automatic records for [http].domains
        if let Some(http) = cfg.and_then(|c| c.http.as_ref()) {
            for d in &http.domains {
                let name = normalize_dns_name(d);
                if !eligible_domain(&name) || covered_hosts.contains(&name) {
                    continue;
                }
                let proxied = default_proxied;
                let ttl = effective_ttl(proxied, default_ttl);
                for ip in &cluster_v4 {
                    push_unique(&mut out, &mut seen, DesiredRecord {
                        app: Some(app_name.clone()),
                        name: name.clone(),
                        record_type: "A".into(),
                        content: ip.clone(),
                        proxied,
                        ttl,
                        priority: None,
                        source: "http".into(),
                        auto_ip: true,
                    });
                }
                for ip in &cluster_v6 {
                    push_unique(&mut out, &mut seen, DesiredRecord {
                        app: Some(app_name.clone()),
                        name: name.clone(),
                        record_type: "AAAA".into(),
                        content: ip.clone(),
                        proxied,
                        ttl,
                        priority: None,
                        source: "http".into(),
                        auto_ip: true,
                    });
                }
            }
        }
    }

    // Wildcard record for settings.base_domain (always DNS-only so any subdomain depth works with Let's Encrypt).
    let base = normalize_dns_name(&s.settings.base_domain);
    if eligible_domain(&base) {
        let wild = format!("*.{base}");
        let already = out.iter().any(|r| r.name == wild && matches!(r.record_type.as_str(), "A" | "AAAA" | "CNAME"));
        if !already {
            let ttl = effective_ttl(false, default_ttl);
            for ip in &cluster_v4 {
                push_unique(&mut out, &mut seen, DesiredRecord {
                    app: None,
                    name: wild.clone(),
                    record_type: "A".into(),
                    content: ip.clone(),
                    proxied: false,
                    ttl,
                    priority: None,
                    source: "base_domain".into(),
                    auto_ip: true,
                });
            }
            for ip in &cluster_v6 {
                push_unique(&mut out, &mut seen, DesiredRecord {
                    app: None,
                    name: wild.clone(),
                    record_type: "AAAA".into(),
                    content: ip.clone(),
                    proxied: false,
                    ttl,
                    priority: None,
                    source: "base_domain".into(),
                    auto_ip: true,
                });
            }
        }
    }

    out
}

pub fn normalize_content(record_type: &str, content: &str) -> String {
    let c = content.trim();
    match record_type {
        "CNAME" | "MX" => c.trim_end_matches('.').to_ascii_lowercase(),
        "TXT" => c.trim_matches('"').to_string(),
        "SRV" => {
            // Normalize whitespace and strip trailing dot from target
            let parts: Vec<&str> = c.split_whitespace().collect();
            if parts.len() == 4 {
                format!(
                    "{} {} {} {}",
                    parts[0],
                    parts[1],
                    parts[2],
                    parts[3].trim_end_matches('.').to_ascii_lowercase()
                )
            } else if parts.len() == 3 {
                format!(
                    "{} {} {}",
                    parts[0],
                    parts[1],
                    parts[2].trim_end_matches('.').to_ascii_lowercase()
                )
            } else {
                c.to_string()
            }
        }
        "CAA" => {
            let parts: Vec<&str> = c.splitn(3, char::is_whitespace).collect();
            if parts.len() == 3 {
                format!(
                    "{} {} {}",
                    parts[0],
                    parts[1].to_ascii_lowercase(),
                    parts[2].trim().trim_matches('"')
                )
            } else {
                c.to_string()
            }
        }
        _ => c.to_string(),
    }
}

fn srv_effective_content(content: &str, priority: Option<u16>) -> Result<(u16, u16, u16, String)> {
    let parts: Vec<&str> = content.split_whitespace().collect();
    match (parts.as_slice(), priority) {
        ([p, w, port, target], _) => Ok((
            p.parse().context("SRV priority must be a number")?,
            w.parse().context("SRV weight must be a number")?,
            port.parse().context("SRV port must be a number")?,
            target.trim_end_matches('.').to_ascii_lowercase(),
        )),
        ([w, port, target], Some(p)) => Ok((
            p,
            w.parse().context("SRV weight must be a number")?,
            port.parse().context("SRV port must be a number")?,
            target.trim_end_matches('.').to_ascii_lowercase(),
        )),
        ([w, port, target], None) => Ok((
            0,
            w.parse().context("SRV weight must be a number")?,
            port.parse().context("SRV port must be a number")?,
            target.trim_end_matches('.').to_ascii_lowercase(),
        )),
        _ => bail!("SRV content must be \"<priority> <weight> <port> <target>\" (or \"<weight> <port> <target>\" with priority)"),
    }
}

fn caa_effective_content(content: &str) -> Result<(u8, String, String)> {
    let parts: Vec<&str> = content.trim().splitn(3, char::is_whitespace).collect();
    if parts.len() != 3 {
        bail!("CAA content must be \"<flags> <tag> <value>\" (e.g. 0 issue \"letsencrypt.org\")");
    }
    let flags: u8 = parts[0].parse().context("CAA flags must be 0..=255")?;
    let tag = parts[1].trim().to_ascii_lowercase();
    let value = parts[2].trim().trim_matches('"').to_string();
    Ok((flags, tag, value))
}

fn cf_record_content(r: &CfRecord) -> String {
    if r.record_type == "SRV" {
        if let Some(d) = &r.data {
            if let (Some(p), Some(w), Some(port), Some(t)) = (
                d["priority"].as_u64(),
                d["weight"].as_u64(),
                d["port"].as_u64(),
                d["target"].as_str(),
            ) {
                return format!("{p} {w} {port} {}", t.trim_end_matches('.').to_ascii_lowercase());
            }
        }
        // Cloudflare sometimes returns "weight port target" in content with priority separate.
        let parts: Vec<&str> = r.content.split_whitespace().collect();
        if parts.len() == 3 {
            let p = r.priority.unwrap_or(0);
            return format!(
                "{p} {} {} {}",
                parts[0],
                parts[1],
                parts[2].trim_end_matches('.').to_ascii_lowercase()
            );
        }
    }
    if r.record_type == "CAA" {
        if let Some(d) = &r.data {
            if let (Some(f), Some(tag), Some(val)) = (
                d["flags"].as_u64(),
                d["tag"].as_str(),
                d["value"].as_str(),
            ) {
                return format!("{f} {} {}", tag.to_ascii_lowercase(), val.trim_matches('"'));
            }
        }
    }
    normalize_content(&r.record_type, &r.content)
}

fn desired_normalized_content(d: &DesiredRecord) -> String {
    if d.record_type == "SRV" {
        if let Ok((p, w, port, t)) = srv_effective_content(&d.content, d.priority) {
            return format!("{p} {w} {port} {t}");
        }
    }
    if d.record_type == "CAA" {
        if let Ok((f, tag, val)) = caa_effective_content(&d.content) {
            return format!("{f} {tag} {val}");
        }
    }
    normalize_content(&d.record_type, &d.content)
}

fn record_matches(existing: &CfRecord, desired: &DesiredRecord, tag: &str) -> bool {
    let same_name = normalize_dns_name(&existing.name) == desired.name;
    let same_type = existing.record_type.eq_ignore_ascii_case(&desired.record_type);
    let same_content = cf_record_content(existing) == desired_normalized_content(desired);
    let same_proxied = !is_proxyable(&desired.record_type) || existing.proxied == desired.proxied;
    let same_ttl = existing.ttl == desired.ttl;
    let same_prio = if desired.record_type == "MX" {
        existing.priority == desired.priority
    } else {
        true
    };
    let same_comment = existing.comment.as_deref() == Some(tag);
    same_name && same_type && same_content && same_proxied && same_ttl && same_prio && same_comment
}

/// Pure diff between desired records in a single Cloudflare zone and the
/// existing records returned by Cloudflare.
///
/// Ordering guarantees zero-downtime IP rotations:
/// 1. Delete conflicting managed records (e.g. CNAME when switching to A, or vice versa).
/// 2. Update records in-place (reusing record IDs when e.g. a single IP changes).
/// 3. Create newly added records (new IPs go live before old IPs are removed).
/// 4. Delete stale records owned by latrix (or stale A/AAAA IPs on actively managed names).
pub fn plan_zone_sync(
    cluster: &str,
    zone: &CfZone,
    desired: &[DesiredRecord],
    existing: &[CfRecord],
    managed: &[ManagedDnsRecord],
) -> Vec<SyncAction> {
    let tag = comment_tag(cluster);
    let managed_ids: BTreeSet<&str> = managed
        .iter()
        .filter(|m| m.zone_id == zone.id)
        .map(|m| m.record_id.as_str())
        .collect();
    let is_owned = |r: &CfRecord| -> bool {
        managed_ids.contains(r.id.as_str()) || r.comment.as_deref() == Some(tag.as_str())
    };

    // Group desired and existing by (name, record_type).
    let mut desired_by_key: BTreeMap<(String, String), Vec<&DesiredRecord>> = BTreeMap::new();
    for d in desired {
        desired_by_key
            .entry((d.name.clone(), d.record_type.clone()))
            .or_default()
            .push(d);
    }
    let mut existing_by_key: BTreeMap<(String, String), Vec<&CfRecord>> = BTreeMap::new();
    for e in existing {
        existing_by_key
            .entry((normalize_dns_name(&e.name), e.record_type.to_ascii_uppercase()))
            .or_default()
            .push(e);
    }

    let mut pre_deletes: Vec<SyncAction> = vec![];
    let mut updates: Vec<SyncAction> = vec![];
    let mut creates: Vec<SyncAction> = vec![];
    let mut post_deletes: Vec<SyncAction> = vec![];
    let mut claimed_existing: BTreeSet<String> = BTreeSet::new();

    // 1. Check for CNAME <-> A/AAAA conflicts on the same hostname (must delete before creating).
    let desired_names: BTreeSet<&str> = desired.iter().map(|d| d.name.as_str()).collect();
    for name in &desired_names {
        let want_cname = desired_by_key.contains_key(&(name.to_string(), "CNAME".into()));
        let want_addr = desired_by_key.contains_key(&(name.to_string(), "A".into()))
            || desired_by_key.contains_key(&(name.to_string(), "AAAA".into()));
        for e in existing {
            if normalize_dns_name(&e.name) != *name || !is_owned(e) {
                continue;
            }
            let et = e.record_type.to_ascii_uppercase();
            if (want_cname && (et == "A" || et == "AAAA")) || (want_addr && et == "CNAME") {
                claimed_existing.insert(e.id.clone());
                pre_deletes.push(SyncAction::Delete {
                    id: e.id.clone(),
                    name: normalize_dns_name(&e.name),
                    record_type: et,
                    content: e.content.clone(),
                });
            }
        }
    }

    // 2. Reconcile each desired (name, type) group.
    for ((name, ty), want_list) in &desired_by_key {
        let have_list: Vec<&CfRecord> = existing_by_key
            .get(&(name.clone(), ty.clone()))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|e| !claimed_existing.contains(&e.id))
            .collect();

        let mut remaining_want: Vec<&DesiredRecord> = vec![];
        let mut used_have: BTreeSet<String> = BTreeSet::new();

        // Pass A: exact content match (either already identical, or update metadata/proxied/ttl/comment).
        for w in want_list {
            let w_norm = desired_normalized_content(w);
            if let Some(h) = have_list
                .iter()
                .find(|h| !used_have.contains(&h.id) && cf_record_content(h) == w_norm)
            {
                used_have.insert(h.id.clone());
                claimed_existing.insert(h.id.clone());
                if !record_matches(h, w, &tag) {
                    updates.push(SyncAction::Update {
                        id: h.id.clone(),
                        desired: (*w).clone(),
                    });
                }
            } else {
                remaining_want.push(*w);
            }
        }

        // Remaining unmatched existing records of the same (name, type).
        // For A, AAAA, CNAME: all records on this managed hostname belong to this set
        // (so stale IPs from dead/old servers are replaced/cleaned up).
        // For TXT, MX, SRV, CAA: ONLY touch records owned by latrix so user's other
        // TXT/MX records on the same hostname are never modified or deleted!
        let replaceable_have: Vec<&CfRecord> = have_list
            .into_iter()
            .filter(|h| !used_have.contains(&h.id))
            .filter(|h| matches!(ty.as_str(), "A" | "AAAA" | "CNAME") || is_owned(h))
            .collect();

        // Pass B: pair up remaining wants with replaceable existing records to update in-place
        // (atomic replacement, e.g. UDP app moving from IP1 to IP2).
        let pair_count = remaining_want.len().min(replaceable_have.len());
        for i in 0..pair_count {
            let h = replaceable_have[i];
            let w = remaining_want[i];
            claimed_existing.insert(h.id.clone());
            updates.push(SyncAction::Update {
                id: h.id.clone(),
                desired: w.clone(),
            });
        }
        // Pass C: create any extra desired records.
        for w in &remaining_want[pair_count..] {
            creates.push(SyncAction::Create((*w).clone()));
        }
        // Pass D: delete any extra stale existing records (after creates!).
        for h in &replaceable_have[pair_count..] {
            claimed_existing.insert(h.id.clone());
            post_deletes.push(SyncAction::Delete {
                id: h.id.clone(),
                name: normalize_dns_name(&h.name),
                record_type: h.record_type.to_ascii_uppercase(),
                content: h.content.clone(),
            });
        }
    }

    // 3. Delete any remaining latrix-owned records that are no longer desired at all
    //    (e.g. removed domain, destroyed app, changed base_domain).
    for e in existing {
        if claimed_existing.contains(&e.id) || !is_owned(e) {
            continue;
        }
        // Never touch ACME DNS-01 challenge TXT records during regular sync.
        if e.record_type.eq_ignore_ascii_case("TXT")
            && normalize_dns_name(&e.name).starts_with("_acme-challenge.")
        {
            continue;
        }
        post_deletes.push(SyncAction::Delete {
            id: e.id.clone(),
            name: normalize_dns_name(&e.name),
            record_type: e.record_type.to_ascii_uppercase(),
            content: e.content.clone(),
        });
    }

    let mut actions = Vec::with_capacity(
        pre_deletes.len() + updates.len() + creates.len() + post_deletes.len(),
    );
    actions.extend(pre_deletes);
    actions.extend(updates);
    actions.extend(creates);
    actions.extend(post_deletes);
    actions
}

// ---------------------------------------------------------------------------
// Cloudflare v4 HTTP API client

pub struct CfClient {
    http: reqwest::Client,
    token: String,
    base: String,
}

#[derive(Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfApiError>,
    result: Option<T>,
    #[serde(default)]
    result_info: Option<CfResultInfo>,
}

#[derive(Deserialize)]
struct CfApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct CfResultInfo {
    #[serde(default)]
    total_pages: u32,
}

impl CfClient {
    pub fn new(http: reqwest::Client, token: impl Into<String>) -> Self {
        Self::with_base(http, token, CF_API_BASE)
    }

    pub fn with_base(
        http: reqwest::Client,
        token: impl Into<String>,
        base: impl Into<String>,
    ) -> Self {
        Self {
            http,
            token: token.into(),
            base: base.into().trim_end_matches('/').to_string(),
        }
    }

    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(T, Option<CfResultInfo>)> {
        let url = format!("{}{}", self.base, path);
        let mut rb = self
            .http
            .request(method, &url)
            .bearer_auth(&self.token)
            .timeout(Duration::from_secs(20));
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.with_context(|| format!("Cloudflare API {path}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        let env: CfEnvelope<T> = serde_json::from_str(&text).with_context(|| {
            format!(
                "Cloudflare API {path} returned {status}: {}",
                text.chars().take(300).collect::<String>()
            )
        })?;
        if !status.is_success() || !env.success {
            let errs = env
                .errors
                .iter()
                .map(|e| {
                    if e.code != 0 {
                        format!("{} ({})", e.message, e.code)
                    } else {
                        e.message.clone()
                    }
                })
                .collect::<Vec<_>>()
                .join("; ");
            let msg = if errs.is_empty() {
                format!("{status}")
            } else {
                errs
            };
            bail!("Cloudflare: {msg}");
        }
        let result = env
            .result
            .ok_or_else(|| anyhow!("Cloudflare API {path}: missing result"))?;
        Ok((result, env.result_info))
    }

    /// List all accessible active zones for this token.
    pub async fn list_zones(&self) -> Result<Vec<CfZone>> {
        let mut all = vec![];
        for page in 1..=20u32 {
            let (mut list, info): (Vec<CfZone>, _) = self
                .request(
                    reqwest::Method::GET,
                    &format!("/zones?per_page=50&page={page}&status=active"),
                    None,
                )
                .await?;
            all.append(&mut list);
            let total_pages = info.map(|i| i.total_pages).unwrap_or(1);
            if page >= total_pages {
                break;
            }
        }
        all.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all)
    }

    /// List all DNS records in a zone.
    pub async fn list_records(&self, zone_id: &str) -> Result<Vec<CfRecord>> {
        let mut all = vec![];
        for page in 1..=50u32 {
            let (mut list, info): (Vec<CfRecord>, _) = self
                .request(
                    reqwest::Method::GET,
                    &format!("/zones/{zone_id}/dns_records?per_page=100&page={page}"),
                    None,
                )
                .await?;
            all.append(&mut list);
            let total_pages = info.map(|i| i.total_pages).unwrap_or(1);
            if page >= total_pages {
                break;
            }
        }
        Ok(all)
    }

    fn build_record_body(d: &DesiredRecord, comment: &str) -> Result<Value> {
        let mut obj = serde_json::Map::new();
        obj.insert("type".into(), json!(d.record_type));
        obj.insert("name".into(), json!(d.name));
        obj.insert("ttl".into(), json!(effective_ttl(d.proxied, d.ttl)));
        obj.insert("comment".into(), json!(comment));
        if is_proxyable(&d.record_type) {
            obj.insert("proxied".into(), json!(d.proxied));
        }
        match d.record_type.as_str() {
            "SRV" => {
                let (priority, weight, port, target) =
                    srv_effective_content(&d.content, d.priority)?;
                obj.insert(
                    "data".into(),
                    json!({
                        "priority": priority,
                        "weight": weight,
                        "port": port,
                        "target": target,
                    }),
                );
            }
            "CAA" => {
                let (flags, tag, value) = caa_effective_content(&d.content)?;
                obj.insert(
                    "data".into(),
                    json!({
                        "flags": flags,
                        "tag": tag,
                        "value": value,
                    }),
                );
            }
            "MX" => {
                obj.insert("content".into(), json!(d.content.trim().trim_end_matches('.')));
                obj.insert("priority".into(), json!(d.priority.unwrap_or(10)));
            }
            "CNAME" => {
                obj.insert("content".into(), json!(d.content.trim().trim_end_matches('.')));
            }
            _ => {
                obj.insert("content".into(), json!(d.content.trim()));
            }
        }
        Ok(Value::Object(obj))
    }

    pub async fn create_record(
        &self,
        zone_id: &str,
        d: &DesiredRecord,
        comment: &str,
    ) -> Result<CfRecord> {
        let body = Self::build_record_body(d, comment)?;
        let (rec, _) = self
            .request(
                reqwest::Method::POST,
                &format!("/zones/{zone_id}/dns_records"),
                Some(body),
            )
            .await?;
        Ok(rec)
    }

    pub async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        d: &DesiredRecord,
        comment: &str,
    ) -> Result<CfRecord> {
        let body = Self::build_record_body(d, comment)?;
        let (rec, _) = self
            .request(
                reqwest::Method::PUT,
                &format!("/zones/{zone_id}/dns_records/{record_id}"),
                Some(body),
            )
            .await?;
        Ok(rec)
    }

    pub async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        let (_val, _): (Value, _) = self
            .request(
                reqwest::Method::DELETE,
                &format!("/zones/{zone_id}/dns_records/{record_id}"),
                None,
            )
            .await?;
        Ok(())
    }

    /// Create a temporary `_acme-challenge.<domain>` TXT record for ACME DNS-01.
    pub async fn create_acme_txt(
        &self,
        zone_id: &str,
        domain: &str,
        value: &str,
    ) -> Result<String> {
        let d = DesiredRecord {
            app: None,
            name: format!("_acme-challenge.{}", normalize_dns_name(domain)),
            record_type: "TXT".into(),
            content: value.to_string(),
            proxied: false,
            ttl: 60,
            priority: None,
            source: "acme".into(),
            auto_ip: false,
        };
        let rec = self.create_record(zone_id, &d, "latrix:acme-dns01").await?;
        Ok(rec.id)
    }
}

/// Verify a Cloudflare API token and return its accessible zones.
pub async fn verify_token(http: &reqwest::Client, token: &str) -> Result<Vec<CfZone>> {
    let token = token.trim();
    if token.is_empty() {
        bail!("Cloudflare API token cannot be empty");
    }
    let cf = CfClient::new(http.clone(), token);
    let zones = cf.list_zones().await.context(
        "could not verify Cloudflare token (create an API token with Zone:Read and Zone:DNS:Edit at dash.cloudflare.com/profile/api-tokens)",
    )?;
    Ok(zones)
}

/// Helper for ACME DNS-01: find the Cloudflare zone for `domain` using the cluster token.
pub async fn find_zone_for_domain(agent: &Agent, domain: &str) -> Option<(String, String, CfZone)> {
    let token = agent.snapshot().cloudflare_token.clone()?;
    // Check cached zones first, fall back to live query.
    let cached = {
        let st = agent.cloudflare.status.lock().unwrap();
        find_zone(&st.zones, domain).cloned()
    };
    if let Some(z) = cached {
        return Some((token, domain.to_string(), z));
    }
    let cf = CfClient::new(agent.http.clone(), &token);
    let zones = cf.list_zones().await.ok()?;
    let found = find_zone(&zones, domain).cloned();
    {
        let mut st = agent.cloudflare.status.lock().unwrap();
        st.zones = zones;
    }
    found.map(|z| (token, domain.to_string(), z))
}

// ---------------------------------------------------------------------------
// Sync execution & status reporting

fn record_key(name: &str, record_type: &str, content: &str) -> String {
    format!("{name}|{record_type}|{}", normalize_content(record_type, content))
}

fn compute_fingerprint(token: &str, desired: &[DesiredRecord]) -> String {
    let mut parts: Vec<String> = desired
        .iter()
        .map(|d| {
            format!(
                "{}|{}|{}|{}|{}|{:?}",
                d.name, d.record_type, d.content, d.proxied, d.ttl, d.priority
            )
        })
        .collect();
    parts.sort();
    // Include token length & tail (not full token) plus desired records.
    let tail: String = token.chars().rev().take(6).collect();
    format!("{}:{}|{}", token.len(), tail, parts.join("\n"))
}

/// Build the user-facing `DnsStatusView` for `GET /v1/dns` and `latrix dns`.
pub fn status_view(agent: &Agent) -> DnsStatusView {
    let s = agent.snapshot();
    let live = agent.live();
    let desired = desired_records(&s, &live.view());
    let rt = agent.cloudflare.status.lock().unwrap().clone();
    let configured = s.cloudflare_token.is_some();

    let managed_keys: BTreeSet<String> = s
        .managed_dns
        .iter()
        .map(|m| record_key(&m.name, &m.record_type, &m.content))
        .collect();

    let records = desired
        .into_iter()
        .map(|d| {
            let key = record_key(&d.name, &d.record_type, &d.content);
            let zone = find_zone(&rt.zones, &d.name).map(|z| z.name.clone());
            let err = rt.record_errors.get(&key).cloned();
            let (status, error) = if !configured {
                ("disabled".into(), None)
            } else if let Some(e) = err {
                ("error".into(), Some(e))
            } else if zone.is_none() && rt.last_sync > 0 {
                (
                    "no_zone".into(),
                    Some("no matching Cloudflare zone for this domain".into()),
                )
            } else if managed_keys.contains(&key) {
                ("synced".into(), None)
            } else {
                ("pending".into(), None)
            };
            DnsRecordStatus {
                app: d.app,
                name: d.name,
                record_type: d.record_type,
                content: d.content,
                proxied: d.proxied,
                ttl: d.ttl,
                priority: d.priority,
                source: d.source,
                zone,
                status,
                error,
            }
        })
        .collect();

    DnsStatusView {
        configured,
        proxied_default: s.settings.cloudflare_proxied,
        ttl_default: s.settings.cloudflare_ttl,
        base_domain: s.settings.base_domain.clone(),
        zones: rt.zones.iter().map(|z| z.name.clone()).collect(),
        last_sync: rt.last_sync,
        last_error: rt.last_error,
        records,
    }
}

pub fn summary(agent: &Agent) -> DnsSummary {
    let v = status_view(agent);
    DnsSummary {
        configured: v.configured,
        zones: v.zones,
        records: v.records,
        last_sync: v.last_sync,
        last_error: v.last_error,
    }
}

/// Synchronize desired records with Cloudflare right now.
pub async fn sync_now(agent: &Arc<Agent>) -> Result<DnsSyncResult> {
    let _lock = agent.cloudflare.sync_lock.lock().await;
    sync_locked(agent, CF_API_BASE).await
}

async fn sync_locked(agent: &Arc<Agent>, api_base: &str) -> Result<DnsSyncResult> {
    let s = agent.snapshot();
    let Some(token) = s.cloudflare_token.clone() else {
        return Ok(DnsSyncResult {
            status: status_view(agent),
            ..Default::default()
        });
    };
    let live = agent.live();
    let desired = desired_records(&s, &live.view());
    let cf = CfClient::with_base(agent.http.clone(), &token, api_base);
    let zones = match cf.list_zones().await {
        Ok(z) => z,
        Err(e) => {
            let msg = format!("{e:#}");
            {
                let mut rt = agent.cloudflare.status.lock().unwrap();
                rt.last_error = Some(msg.clone());
            }
            return Err(e);
        }
    };

    let tag = comment_tag(&s.cluster);
    let mut by_zone: HashMap<String, (&CfZone, Vec<DesiredRecord>)> = HashMap::new();
    for d in &desired {
        if let Some(z) = find_zone(&zones, &d.name) {
            by_zone
                .entry(z.id.clone())
                .or_insert_with(|| (z, vec![]))
                .1
                .push(d.clone());
        }
    }
    // Also include zones that currently hold managed_dns records so removed apps/domains get cleaned up!
    for m in &s.managed_dns {
        if let Some(z) = zones.iter().find(|z| z.id == m.zone_id) {
            by_zone.entry(z.id.clone()).or_insert_with(|| (z, vec![]));
        }
    }

    let mut created = 0usize;
    let mut updated = 0usize;
    let mut deleted = 0usize;
    let mut errors: Vec<String> = vec![];
    let mut record_errors: BTreeMap<String, String> = BTreeMap::new();
    let mut new_managed: Vec<ManagedDnsRecord> = vec![];

    // Carry forward managed records from zones we couldn't inspect (if any).
    let touched_zones: BTreeSet<String> = by_zone.keys().cloned().collect();
    for m in &s.managed_dns {
        if !touched_zones.contains(&m.zone_id) {
            new_managed.push(m.clone());
        }
    }

    let mut zone_entries: Vec<(String, &CfZone, Vec<DesiredRecord>)> = by_zone
        .into_iter()
        .map(|(id, (z, d))| (id, z, d))
        .collect();
    zone_entries.sort_by(|a, b| a.1.name.cmp(&b.1.name));

    for (zone_id, zone, zone_desired) in zone_entries {
        let existing = match cf.list_records(&zone_id).await {
            Ok(list) => list,
            Err(e) => {
                let msg = format!("{}: {e:#}", zone.name);
                errors.push(msg.clone());
                for d in &zone_desired {
                    record_errors.insert(record_key(&d.name, &d.record_type, &d.content), msg.clone());
                }
                // Preserve existing managed entries for this zone on transient read failure.
                for m in s.managed_dns.iter().filter(|m| m.zone_id == zone_id) {
                    new_managed.push(m.clone());
                }
                continue;
            }
        };

        let actions = plan_zone_sync(&s.cluster, zone, &zone_desired, &existing, &s.managed_dns);

        // Track live record IDs by (name, type, normalized_content) for updating ClusterState.managed_dns.
        let mut live_by_id: HashMap<String, CfRecord> =
            existing.into_iter().map(|r| (r.id.clone(), r)).collect();

        for action in actions {
            match action {
                SyncAction::Create(d) => match cf.create_record(&zone_id, &d, &tag).await {
                    Ok(rec) => {
                        created += 1;
                        info!("cloudflare: created {} {} -> {}", d.record_type, d.name, d.content);
                        live_by_id.insert(rec.id.clone(), rec);
                    }
                    Err(e) => {
                        let msg = format!("create {} {} ({}): {e:#}", d.record_type, d.name, d.content);
                        record_errors.insert(record_key(&d.name, &d.record_type, &d.content), format!("{e:#}"));
                        errors.push(msg);
                    }
                },
                SyncAction::Update { id, desired: d } => {
                    match cf.update_record(&zone_id, &id, &d, &tag).await {
                        Ok(rec) => {
                            updated += 1;
                            info!("cloudflare: updated {} {} -> {}", d.record_type, d.name, d.content);
                            live_by_id.insert(rec.id.clone(), rec);
                        }
                        Err(e) => {
                            let msg = format!("update {} {} ({}): {e:#}", d.record_type, d.name, d.content);
                            record_errors.insert(record_key(&d.name, &d.record_type, &d.content), format!("{e:#}"));
                            errors.push(msg);
                        }
                    }
                }
                SyncAction::Delete {
                    id,
                    name,
                    record_type,
                    content,
                } => match cf.delete_record(&zone_id, &id).await {
                    Ok(()) => {
                        deleted += 1;
                        info!("cloudflare: deleted {record_type} {name} ({content})");
                        live_by_id.remove(&id);
                    }
                    Err(e) => {
                        errors.push(format!("delete {record_type} {name} ({content}): {e:#}"));
                    }
                },
            }
        }

        // Rebuild managed_dns entries for this zone from all records currently in Cloudflare
        // that match our desired set (or still carry our comment after a failed delete).
        let desired_apps: HashMap<String, Option<String>> = zone_desired
            .iter()
            .map(|d| (record_key(&d.name, &d.record_type, &d.content), d.app.clone()))
            .collect();
        for rec in live_by_id.values() {
            let norm_name = normalize_dns_name(&rec.name);
            let norm_ty = rec.record_type.to_ascii_uppercase();
            let norm_content = cf_record_content(rec);
            let k = record_key(&norm_name, &norm_ty, &norm_content);
            let is_desired = desired_apps.contains_key(&k);
            let is_tagged = rec.comment.as_deref() == Some(tag.as_str());
            if is_desired || is_tagged {
                new_managed.push(ManagedDnsRecord {
                    zone_id: zone.id.clone(),
                    zone_name: zone.name.clone(),
                    record_id: rec.id.clone(),
                    name: norm_name,
                    record_type: norm_ty,
                    content: norm_content,
                    proxied: rec.proxied,
                    ttl: rec.ttl,
                    priority: rec.priority,
                    app: desired_apps.get(&k).cloned().flatten(),
                });
            }
        }
    }

    new_managed.sort_by(|a, b| {
        (&a.name, &a.record_type, &a.content, &a.record_id).cmp(&(
            &b.name,
            &b.record_type,
            &b.content,
            &b.record_id,
        ))
    });

    if new_managed != s.managed_dns && agent.is_leader() {
        let updated_managed = new_managed.clone();
        let _ = agent
            .mutate(move |st| {
                st.managed_dns = updated_managed;
                Ok(())
            })
            .await;
    }

    let last_error = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };
    let fingerprint = compute_fingerprint(&token, &desired);
    {
        let mut rt = agent.cloudflare.status.lock().unwrap();
        rt.zones = zones;
        rt.last_sync = now();
        rt.last_error = last_error.clone();
        rt.record_errors = record_errors;
        if errors.is_empty() {
            rt.last_fingerprint = fingerprint;
        } else {
            rt.last_fingerprint.clear();
        }
    }

    if created > 0 || updated > 0 || deleted > 0 {
        let mut bits = vec![];
        if created > 0 {
            bits.push(format!("{created} created"));
        }
        if updated > 0 {
            bits.push(format!("{updated} updated"));
        }
        if deleted > 0 {
            bits.push(format!("{deleted} deleted"));
        }
        agent.event("info", format!("cloudflare DNS synced ({})", bits.join(", ")));
        // Wake ACME immediately so certificates are issued right after DNS points here.
        if created > 0 || updated > 0 {
            agent.acme_wake.notify_one();
        }
    }
    if let Some(err) = &last_error {
        let should_warn = {
            let mut rt = agent.cloudflare.status.lock().unwrap();
            let t = now();
            if t.saturating_sub(rt.last_warned) >= 300 {
                rt.last_warned = t;
                true
            } else {
                false
            }
        };
        if should_warn {
            agent.event("warn", format!("cloudflare DNS sync error: {err}"));
        }
    }

    Ok(DnsSyncResult {
        created,
        updated,
        deleted,
        errors,
        status: status_view(agent),
    })
}

/// Leader background loop: watches state changes and periodically reconciles
/// Cloudflare DNS records.
pub async fn run(agent: Arc<Agent>) {
    if agent.dev {
        return;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut rx = agent.changed.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        let forced = tokio::select! {
            _ = tick.tick() => false,
            _ = rx.changed() => {
                // Small debounce so rapid multi-step mutations batch cleanly.
                tokio::time::sleep(Duration::from_secs(2)).await;
                false
            }
            _ = agent.cloudflare.wake.notified() => true,
        };
        if !agent.is_leader() {
            continue;
        }
        let s = agent.snapshot();
        let Some(token) = s.cloudflare_token.as_deref() else {
            continue;
        };
        // Skip redundant API calls when nothing changed recently (re-verify against Cloudflare every 5 minutes).
        if !forced {
            let live = agent.live();
            let desired = desired_records(&s, &live.view());
            let fp = compute_fingerprint(token, &desired);
            let rt = agent.cloudflare.status.lock().unwrap();
            if !rt.last_fingerprint.is_empty()
                && rt.last_fingerprint == fp
                && now().saturating_sub(rt.last_sync) < 300
            {
                continue;
            }
        }
        match sync_now(&agent).await {
            Ok(res) => {
                if !res.errors.is_empty() {
                    debug!("cloudflare sync completed with {} error(s)", res.errors.len());
                }
            }
            Err(e) => {
                warn!("cloudflare DNS sync failed: {e:#}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::state::{App, Instance, Machine, Release, ReleaseStatus};
    use std::collections::HashSet;

    fn mk_machine(id: u32, ip: &str, status: MachineStatus) -> Machine {
        Machine {
            id,
            name: format!("m{id}"),
            public_ip: ip.into(),
            overlay_ip: format!("10.77.0.{id}"),
            wg_pubkey: String::new(),
            os: "ubuntu".into(),
            arch: "x86_64".into(),
            cpus: 2.0,
            memory_mb: 4096,
            region: None,
            provider: None,
            monthly_cost: None,
            status,
            joined_at: 0,
            maintenance: None,
            last_maintenance: 0,
            temporary: false,
        }
    }

    fn mk_app(name: &str, toml_str: &str) -> App {
        let cfg: AppConfig = toml::from_str(toml_str).unwrap();
        cfg.validate().unwrap();
        App {
            name: name.into(),
            vip: "10.78.0.1".into(),
            current: 1,
            releases: vec![Release {
                version: 1,
                image: "img".into(),
                config: cfg,
                created_at: 0,
                status: ReleaseStatus::Active,
                sources: vec![],
                description: String::new(),
            }],
            secrets: Default::default(),
            count: 1,
            created_at: 0,
            last_builder: None,
            dns_records: vec![],
        }
    }

    fn live<'a>(
        alive: &'a HashSet<u32>,
        dead: &'a HashMap<u32, u64>,
        reports: &'a HashMap<u32, crate::state::NodeReport>,
    ) -> LiveView<'a> {
        LiveView {
            now: 1000,
            alive,
            dead_since: dead,
            reports,
            leader_for: 100,
        }
    }

    #[test]
    fn zone_matching_picks_most_specific() {
        let zones = vec![
            CfZone { id: "z1".into(), name: "example.com".into(), status: "active".into() },
            CfZone { id: "z2".into(), name: "sub.example.com".into(), status: "active".into() },
        ];
        assert_eq!(find_zone(&zones, "example.com").unwrap().id, "z1");
        assert_eq!(find_zone(&zones, "shop.example.com").unwrap().id, "z1");
        assert_eq!(find_zone(&zones, "api.sub.example.com").unwrap().id, "z2");
        assert_eq!(find_zone(&zones, "*.sub.example.com").unwrap().id, "z2");
        assert!(find_zone(&zones, "notexample.com").is_none());
        assert!(find_zone(&zones, "other.org").is_none());
    }

    #[test]
    fn desired_records_http_udp_custom_and_base_domain() {
        let mut s = ClusterState {
            cluster: "prod".into(),
            ..Default::default()
        };
        s.settings.base_domain = "apps.example.com".into();
        s.settings.cloudflare_proxied = false;
        s.settings.cloudflare_ttl = 60;
        s.machines.insert(1, mk_machine(1, "203.0.113.10", MachineStatus::Ready));
        s.machines.insert(2, mk_machine(2, "203.0.113.11", MachineStatus::Ready));
        s.machines.insert(3, mk_machine(3, "203.0.113.12", MachineStatus::Draining));

        let mut web = mk_app(
            "web",
            r#"
app = "web"
[http]
port = 8080
domains = ["shop.example.com", "alt.example.com"]
[[dns]]
name = "shop.example.com"
proxied = true
[[dns]]
name = "www.shop.example.com"
type = "CNAME"
content = "shop.example.com"
proxied = true
"#,
        );
        web.dns_records.push(DnsRecordConfig {
            name: "shop.example.com".into(),
            record_type: Some("TXT".into()),
            content: Some("v=spf1 -all".into()),
            proxied: None,
            ttl: Some(300),
            priority: None,
        });
        s.apps.insert("web".into(), web);

        let game = mk_app(
            "game",
            r#"
app = "game"
[[ports]]
port = 7777
protocol = "udp"
public = true
[[dns]]
name = "play.example.com"
"#,
        );
        s.apps.insert("game".into(), game);
        s.instances.insert(
            "g1".into(),
            Instance {
                id: "g1".into(),
                app: "game".into(),
                release: 1,
                machine: 2,
                created_at: 0,
                stopping: false,
                stopping_since: 0,
                replaces: None,
            },
        );

        let alive: HashSet<u32> = [1, 2, 3].into();
        let dead = HashMap::new();
        let reports = HashMap::new();
        let want = desired_records(&s, &live(&alive, &dead, &reports));

        // shop.example.com: proxied=true override from [[dns]], ttl=1 (auto), points to ready machines 1 & 2 (not draining 3)
        let shop_a: Vec<_> = want
            .iter()
            .filter(|r| r.name == "shop.example.com" && r.record_type == "A")
            .collect();
        assert_eq!(shop_a.len(), 2);
        assert!(shop_a.iter().all(|r| r.proxied && r.ttl == 1));
        assert_eq!(shop_a.iter().map(|r| r.content.as_str()).collect::<Vec<_>>(), vec!["203.0.113.10", "203.0.113.11"]);

        // alt.example.com: uses cluster defaults (proxied=false, ttl=60)
        let alt_a: Vec<_> = want
            .iter()
            .filter(|r| r.name == "alt.example.com" && r.record_type == "A")
            .collect();
        assert_eq!(alt_a.len(), 2);
        assert!(alt_a.iter().all(|r| !r.proxied && r.ttl == 60 && r.source == "http"));

        // www CNAME
        let cname = want.iter().find(|r| r.name == "www.shop.example.com").unwrap();
        assert_eq!(cname.record_type, "CNAME");
        assert_eq!(cname.content, "shop.example.com");
        assert!(cname.proxied);

        // TXT record from CLI
        let txt = want
            .iter()
            .find(|r| r.name == "shop.example.com" && r.record_type == "TXT")
            .unwrap();
        assert_eq!(txt.content, "v=spf1 -all");
        assert!(!txt.proxied);
        assert_eq!(txt.ttl, 300);

        // UDP game server points ONLY to machine 2 where it runs, never proxied
        let play: Vec<_> = want.iter().filter(|r| r.name == "play.example.com").collect();
        assert_eq!(play.len(), 1);
        assert_eq!(play[0].content, "203.0.113.11");
        assert!(!play[0].proxied);

        // Wildcard base_domain points to ready machines, unproxied
        let wild: Vec<_> = want.iter().filter(|r| r.name == "*.apps.example.com").collect();
        assert_eq!(wild.len(), 2);
        assert!(wild.iter().all(|r| !r.proxied && r.source == "base_domain"));
    }

    #[test]
    fn plan_zone_sync_preserves_unmanaged_and_is_zero_downtime() {
        let zone = CfZone { id: "z1".into(), name: "example.com".into(), status: "active".into() };
        let tag = comment_tag("prod");
        let existing = vec![
            // User's own unrelated MX record — must NEVER be touched!
            CfRecord {
                id: "user-mx".into(),
                name: "example.com".into(),
                record_type: "MX".into(),
                content: "mail.external.com".into(),
                proxied: false,
                ttl: 3600,
                priority: Some(10),
                comment: None,
                data: None,
            },
            // User's own TXT record on shop.example.com — must NEVER be touched!
            CfRecord {
                id: "user-txt".into(),
                name: "shop.example.com".into(),
                record_type: "TXT".into(),
                content: "google-site-verification=xyz".into(),
                proxied: false,
                ttl: 300,
                priority: None,
                comment: None,
                data: None,
            },
            // Existing managed A record that is still valid
            CfRecord {
                id: "a1".into(),
                name: "shop.example.com".into(),
                record_type: "A".into(),
                content: "203.0.113.10".into(),
                proxied: false,
                ttl: 60,
                priority: None,
                comment: Some(tag.clone()),
                data: None,
            },
            // Existing managed A record for a removed app — must be deleted!
            CfRecord {
                id: "old-app".into(),
                name: "gone.example.com".into(),
                record_type: "A".into(),
                content: "203.0.113.10".into(),
                proxied: false,
                ttl: 60,
                priority: None,
                comment: Some(tag.clone()),
                data: None,
            },
        ];
        let desired = vec![
            DesiredRecord {
                app: Some("shop".into()),
                name: "shop.example.com".into(),
                record_type: "A".into(),
                content: "203.0.113.10".into(),
                proxied: false,
                ttl: 60,
                priority: None,
                source: "http".into(),
                auto_ip: true,
            },
            DesiredRecord {
                app: Some("shop".into()),
                name: "shop.example.com".into(),
                record_type: "A".into(),
                content: "203.0.113.11".into(),
                proxied: false,
                ttl: 60,
                priority: None,
                source: "http".into(),
                auto_ip: true,
            },
            DesiredRecord {
                app: Some("shop".into()),
                name: "shop.example.com".into(),
                record_type: "TXT".into(),
                content: "v=spf1 -all".into(),
                proxied: false,
                ttl: 60,
                priority: None,
                source: "cli".into(),
                auto_ip: false,
            },
        ];

        let actions = plan_zone_sync("prod", &zone, &desired, &existing, &[]);
        // Should create shop 203.0.113.11, create shop TXT, delete gone.example.com,
        // and leave a1, user-mx, and user-txt untouched!
        assert_eq!(actions.len(), 3, "{actions:?}");
        assert!(matches!(&actions[0], SyncAction::Create(d) if d.content == "203.0.113.11"));
        assert!(matches!(&actions[1], SyncAction::Create(d) if d.record_type == "TXT"));
        assert!(matches!(&actions[2], SyncAction::Delete { id, .. } if id == "old-app"));
    }

    #[test]
    fn plan_zone_sync_idempotent_and_in_place_ip_swap() {
        let zone = CfZone { id: "z1".into(), name: "example.com".into(), status: "active".into() };
        let tag = comment_tag("prod");
        let existing = vec![CfRecord {
            id: "r1".into(),
            name: "play.example.com".into(),
            record_type: "A".into(),
            content: "203.0.113.10".into(),
            proxied: false,
            ttl: 60,
            priority: None,
            comment: Some(tag.clone()),
            data: None,
        }];
        let same = vec![DesiredRecord {
            app: Some("game".into()),
            name: "play.example.com".into(),
            record_type: "A".into(),
            content: "203.0.113.10".into(),
            proxied: false,
            ttl: 60,
            priority: None,
            source: "config".into(),
            auto_ip: true,
        }];
        assert!(plan_zone_sync("prod", &zone, &same, &existing, &[]).is_empty(), "idempotent");

        // Game server moves to machine 2: updated in place (single PUT, zero gap).
        let moved = vec![DesiredRecord {
            content: "203.0.113.20".into(),
            ..same[0].clone()
        }];
        let actions = plan_zone_sync("prod", &zone, &moved, &existing, &[]);
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], SyncAction::Update { id, desired } if id == "r1" && desired.content == "203.0.113.20"));
    }

    #[test]
    fn plan_zone_sync_handles_cname_to_a_switch() {
        let zone = CfZone { id: "z1".into(), name: "example.com".into(), status: "active".into() };
        let tag = comment_tag("prod");
        let existing = vec![CfRecord {
            id: "c1".into(),
            name: "app.example.com".into(),
            record_type: "CNAME".into(),
            content: "other.example.com".into(),
            proxied: false,
            ttl: 60,
            priority: None,
            comment: Some(tag),
            data: None,
        }];
        let desired = vec![DesiredRecord {
            app: Some("app".into()),
            name: "app.example.com".into(),
            record_type: "A".into(),
            content: "203.0.113.10".into(),
            proxied: false,
            ttl: 60,
            priority: None,
            source: "http".into(),
            auto_ip: true,
        }];
        let actions = plan_zone_sync("prod", &zone, &desired, &existing, &[]);
        assert_eq!(actions.len(), 2);
        // CNAME must be deleted BEFORE A is created!
        assert!(matches!(&actions[0], SyncAction::Delete { id, .. } if id == "c1"));
        assert!(matches!(&actions[1], SyncAction::Create(d) if d.record_type == "A"));
    }

    #[tokio::test]
    async fn cf_client_roundtrip_against_mock_server() {
        use axum::{
            extract::{Path, State},
            routing::{get, put},
            Json, Router,
        };

        #[derive(Default)]
        struct MockCf {
            records: Mutex<Vec<CfRecord>>,
            next_id: Mutex<u32>,
        }

        let mock = Arc::new(MockCf::default());
        let app = Router::new()
            .route(
                "/zones",
                get(|| async {
                    Json(json!({
                        "success": true,
                        "result": [{"id": "zone1", "name": "example.com", "status": "active"}],
                        "result_info": {"total_pages": 1}
                    }))
                }),
            )
            .route(
                "/zones/{zid}/dns_records",
                get(|State(m): State<Arc<MockCf>>| async move {
                    let list = m.records.lock().unwrap().clone();
                    Json(json!({"success": true, "result": list, "result_info": {"total_pages": 1}}))
                })
                .post(|State(m): State<Arc<MockCf>>, Json(body): Json<Value>| async move {
                    let mut n = m.next_id.lock().unwrap();
                    *n += 1;
                    let rec = CfRecord {
                        id: format!("rec{}", *n),
                        name: body["name"].as_str().unwrap_or("").into(),
                        record_type: body["type"].as_str().unwrap_or("").into(),
                        content: body["content"].as_str().unwrap_or("").into(),
                        proxied: body["proxied"].as_bool().unwrap_or(false),
                        ttl: body["ttl"].as_u64().unwrap_or(1) as u32,
                        priority: body["priority"].as_u64().map(|p| p as u16),
                        comment: body["comment"].as_str().map(String::from),
                        data: body.get("data").cloned(),
                    };
                    m.records.lock().unwrap().push(rec.clone());
                    Json(json!({"success": true, "result": rec}))
                }),
            )
            .route(
                "/zones/{zid}/dns_records/{rid}",
                put(|State(m): State<Arc<MockCf>>, Path((_, rid)): Path<(String, String)>, Json(body): Json<Value>| async move {
                    let mut list = m.records.lock().unwrap();
                    let rec = list.iter_mut().find(|r| r.id == rid).unwrap();
                    rec.content = body["content"].as_str().unwrap_or("").into();
                    rec.proxied = body["proxied"].as_bool().unwrap_or(false);
                    rec.ttl = body["ttl"].as_u64().unwrap_or(1) as u32;
                    rec.comment = body["comment"].as_str().map(String::from);
                    Json(json!({"success": true, "result": rec.clone()}))
                })
                .delete(|State(m): State<Arc<MockCf>>, Path((_, rid)): Path<(String, String)>| async move {
                    m.records.lock().unwrap().retain(|r| r.id != rid);
                    Json(json!({"success": true, "result": {"id": rid}}))
                }),
            )
            .with_state(mock.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let cf = CfClient::with_base(reqwest::Client::new(), "test-token", format!("http://{addr}"));
        let zones = cf.list_zones().await.unwrap();
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].name, "example.com");

        let d = DesiredRecord {
            app: Some("web".into()),
            name: "web.example.com".into(),
            record_type: "A".into(),
            content: "203.0.113.10".into(),
            proxied: false,
            ttl: 60,
            priority: None,
            source: "http".into(),
            auto_ip: true,
        };
        let created = cf.create_record("zone1", &d, "latrix:prod").await.unwrap();
        assert_eq!(created.id, "rec1");
        assert_eq!(cf.list_records("zone1").await.unwrap().len(), 1);

        let mut d2 = d.clone();
        d2.content = "203.0.113.20".into();
        let updated = cf.update_record("zone1", &created.id, &d2, "latrix:prod").await.unwrap();
        assert_eq!(updated.content, "203.0.113.20");

        cf.delete_record("zone1", &created.id).await.unwrap();
        assert!(cf.list_records("zone1").await.unwrap().is_empty());
    }
}
