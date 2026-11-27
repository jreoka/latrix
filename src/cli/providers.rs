//! Optional: create servers on Hetzner Cloud or DigitalOcean and add them to
//! the cluster in one step. Tokens come from `latrix provider set` or the
//! HCLOUD_TOKEN / DIGITALOCEAN_TOKEN environment variables.

use super::profile::CliConfig;
use crate::state::ProviderRef;
use crate::util::{self, print_table, random_id};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct ProviderApiError {
    url: String,
    status: reqwest::StatusCode,
    body: String,
}

impl std::fmt::Display for ProviderApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}: {}", self.url, self.status, self.body)
    }
}

impl std::error::Error for ProviderApiError {}

pub struct Created {
    pub ip: String,
    pub monthly_cost: Option<f64>,
    pub provider: ProviderRef,
}

pub fn canonical(p: &str) -> Result<&'static str> {
    match p.to_ascii_lowercase().as_str() {
        "hetzner" | "hcloud" => Ok("hetzner"),
        "digitalocean" | "do" => Ok("digitalocean"),
        other => bail!("unknown provider '{other}' (supported: hetzner, digitalocean)"),
    }
}

fn validate_provider_id(id: &str) -> Result<&str> {
    let id = id.trim();
    if id.is_empty()
        || id.len() > 64
        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("invalid provider server id '{id}'");
    }
    Ok(id)
}

pub fn token(cfg: &CliConfig, provider: &str) -> Result<String> {
    let p = canonical(provider)?;
    let env = if p == "hetzner" { "HCLOUD_TOKEN" } else { "DIGITALOCEAN_TOKEN" };
    std::env::var(env)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| cfg.providers.get(p).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
        .ok_or_else(|| anyhow!("no API token for {p}: run `latrix provider set {p} <token>` or set {env}"))
}

/// Fallback when the provider's image list can't be read.
fn fallback_image(provider: &str) -> Result<&'static str> {
    match provider {
        "hetzner" => Ok("ubuntu-24.04"),
        "digitalocean" => Ok("ubuntu-24-04-x64"),
        other => bail!("unknown provider '{other}'"),
    }
}

/// Parse "26.04" into (26, 4).
fn ubuntu_version(v: &str) -> Option<(u32, u32)> {
    let (a, b) = v.split_once('.')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// Prefer the newest LTS release (YY.04 with an even year), else the newest release.
fn pick_newest(candidates: Vec<((u32, u32), String)>) -> Option<String> {
    let lts = |(major, minor): (u32, u32)| minor == 4 && major % 2 == 0;
    let best_lts = candidates.iter().filter(|(v, _)| lts(*v)).max_by_key(|(v, _)| *v);
    best_lts
        .or_else(|| candidates.iter().max_by_key(|(v, _)| *v))
        .map(|(_, name)| name.clone())
}

/// Newest Ubuntu image on Hetzner for an architecture ("x86" or "arm").
pub fn pick_hetzner_ubuntu(images: &Value, arch: &str) -> Option<String> {
    let list = images["images"].as_array()?;
    pick_newest(
        list.iter()
            .filter(|i| i["os_flavor"] == "ubuntu" && i["architecture"] == arch)
            .filter(|i| i["deprecated"].is_null() && i["status"] != "unavailable")
            .filter_map(|i| Some((ubuntu_version(i["os_version"].as_str()?)?, i["name"].as_str()?.to_string())))
            .collect(),
    )
}

/// Newest Ubuntu x64 image on DigitalOcean (slugs like "ubuntu-26-04-x64").
pub fn pick_do_ubuntu(images: &Value) -> Option<String> {
    let list = images["images"].as_array()?;
    pick_newest(
        list.iter()
            .filter_map(|i| i["slug"].as_str())
            .filter_map(|slug| {
                let rest = slug.strip_prefix("ubuntu-")?.strip_suffix("-x64")?;
                let (a, b) = rest.split_once('-')?;
                Some(((a.parse().ok()?, b.parse().ok()?), slug.to_string()))
            })
            .collect(),
    )
}

async fn hetzner_paginated(
    http: &reqwest::Client,
    token: &str,
    base_url: &str,
    array_key: &str,
) -> Result<Vec<Value>> {
    let sep = if base_url.contains('?') { '&' } else { '?' };
    let mut all = vec![];
    for page in 1..=50u32 {
        let url = format!("{base_url}{sep}per_page=50&page={page}");
        let v = api(http, reqwest::Method::GET, &url, token, None).await?;
        if let Some(arr) = v[array_key].as_array() {
            all.extend(arr.iter().cloned());
        }
        match v["meta"]["pagination"]["next_page"].as_u64() {
            Some(next) if next > page as u64 => {}
            _ => break,
        }
    }
    Ok(all)
}

async fn do_paginated(
    http: &reqwest::Client,
    token: &str,
    first_url: &str,
    array_key: &str,
) -> Result<Vec<Value>> {
    let sep = if first_url.contains('?') { '&' } else { '?' };
    let mut next_url = Some(format!("{first_url}{sep}per_page=200"));
    let mut all = vec![];
    for _ in 0..50 {
        let Some(url) = next_url.take() else { break };
        let parsed = reqwest::Url::parse(&url)?;
        if parsed.scheme() != "https" || parsed.host_str() != Some("api.digitalocean.com") {
            bail!("unexpected DigitalOcean pagination URL '{url}'");
        }
        let v = api(http, reqwest::Method::GET, &url, token, None).await?;
        if let Some(arr) = v[array_key].as_array() {
            all.extend(arr.iter().cloned());
        }
        next_url = v["links"]["pages"]["next"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from);
    }
    Ok(all)
}

/// The newest Ubuntu LTS the provider offers for this server size, so new
/// machines don't start on an old release.
pub async fn latest_ubuntu(provider: &str, token: &str, size: &str) -> String {
    let http = reqwest::Client::new();
    use reqwest::Method as M;
    let found = match provider {
        "hetzner" => {
            let base = "https://api.hetzner.cloud/v1";
            let arch = api(&http, M::GET, &format!("{base}/server_types?name={size}"), token, None)
                .await
                .ok()
                .and_then(|v| v["server_types"][0]["architecture"].as_str().map(String::from))
                .unwrap_or_else(|| "x86".into());
            hetzner_paginated(&http, token, &format!("{base}/images?type=system"), "images")
                .await
                .ok()
                .and_then(|list| pick_hetzner_ubuntu(&json!({"images": list}), &arch))
        }
        "digitalocean" => do_paginated(
            &http,
            token,
            "https://api.digitalocean.com/v2/images?type=distribution",
            "images",
        )
        .await
        .ok()
        .and_then(|list| pick_do_ubuntu(&json!({"images": list}))),
        _ => None,
    };
    found.unwrap_or_else(|| {
        let f = fallback_image(provider).unwrap_or("ubuntu-24.04");
        tracing::warn!("could not list {provider} images; using {f} (pass --image to choose)");
        f.to_string()
    })
}

/// The SSH key used for servers latrix creates: (public key, private key
/// path to use, or None for ssh's defaults). Uses --key or your usual key
/// (~/.ssh/id_ed25519 etc.); if you have none, latrix creates and manages
/// its own key next to its config, so you don't need to set anything up.
pub fn ssh_key(key: Option<&str>) -> Result<(String, Option<String>)> {
    ssh_key_in(key, dirs::home_dir().as_deref(), &managed_key_path())
}

fn ssh_key_in(
    key: Option<&str>,
    home_dir: Option<&Path>,
    own: &Path,
) -> Result<(String, Option<String>)> {
    if let Some(k) = key {
        let (priv_path, pub_path) = if let Some(stripped) = k.strip_suffix(".pub") {
            (PathBuf::from(stripped), PathBuf::from(k))
        } else {
            (PathBuf::from(k), PathBuf::from(format!("{k}.pub")))
        };
        if !priv_path.exists() {
            bail!("private SSH key '{}' not found", priv_path.display());
        }
        let pubkey = std::fs::read_to_string(&pub_path)
            .with_context(|| format!("reading {} (the public half of --key)", pub_path.display()))?;
        return Ok((pubkey.trim().to_string(), Some(priv_path.display().to_string())));
    }
    if let Some(home) = home_dir {
        let ssh_dir = home.join(".ssh");
        for f in ["id_ed25519", "id_ecdsa", "id_rsa"] {
            let priv_p = ssh_dir.join(f);
            let pub_p = ssh_dir.join(format!("{f}.pub"));
            if priv_p.is_file() {
                if let Ok(k) = std::fs::read_to_string(&pub_p) {
                    let trimmed = k.trim();
                    if !trimmed.is_empty() {
                        return Ok((trimmed.to_string(), None));
                    }
                }
            }
        }
    }
    let own_pub = PathBuf::from(format!("{}.pub", own.display()));
    if !own.is_file() || !own_pub.is_file() {
        if let Some(dir) = own.parent() {
            util::create_private_dir_all(dir)?;
        }
        let _ = std::fs::remove_file(own);
        let _ = std::fs::remove_file(&own_pub);
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "latrix", "-f"])
            .arg(own)
            .stdin(std::process::Stdio::null())
            .status()
            .context("could not run ssh-keygen (is OpenSSH installed?)")?;
        if !st.success() {
            bail!("ssh-keygen failed");
        }
        crate::agent::set_private(own);
        println!("==> created an SSH key for latrix at {}", own.display());
    }
    let pubkey = std::fs::read_to_string(&own_pub)?;
    Ok((pubkey.trim().to_string(), Some(own.display().to_string())))
}

pub fn managed_key_path() -> PathBuf {
    CliConfig::path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("id_ed25519")
}

fn same_key(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> Option<String> {
        let mut it = s.split_whitespace();
        let ty = it.next()?;
        let data = it.next()?;
        Some(format!("{ty} {data}"))
    };
    match (norm(a), norm(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

async fn api(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> Result<Value> {
    let mut rb = client.request(method, url).bearer_auth(token).timeout(Duration::from_secs(30));
    if let Some(b) = body {
        rb = rb.json(&b);
    }
    let r = rb.send().await?;
    let status = r.status();
    let text = r.text().await?;
    if !status.is_success() {
        return Err(anyhow::Error::new(ProviderApiError {
            url: url.to_string(),
            status,
            body: text.chars().take(400).collect(),
        }));
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(&text)?)
}

/// Make sure every public key is registered with the provider; returns their ids.
async fn ensure_keys(
    http: &reqwest::Client,
    provider: &str,
    token: &str,
    url: &str,
    pubkeys: &[String],
) -> Result<Vec<Value>> {
    let list = match provider {
        "hetzner" => hetzner_paginated(http, token, url, "ssh_keys").await?,
        "digitalocean" => do_paginated(http, token, url, "ssh_keys").await?,
        other => bail!("unknown provider '{other}'"),
    };
    let mut unique: Vec<&str> = vec![];
    for pk in pubkeys {
        let t = pk.trim();
        if t.is_empty() {
            continue;
        }
        if !unique.iter().any(|u| same_key(u, t)) {
            unique.push(t);
        }
    }
    let mut ids = vec![];
    for pk in unique {
        match list.iter().find(|k| same_key(k["public_key"].as_str().unwrap_or(""), pk)) {
            Some(k) if !k["id"].is_null() => ids.push(k["id"].clone()),
            _ => {
                let k = api(
                    http,
                    reqwest::Method::POST,
                    url,
                    token,
                    Some(json!({"name": format!("latrix-{}", random_id(5)), "public_key": pk})),
                )
                .await?;
                let id = k["ssh_key"]["id"].clone();
                if id.is_null() {
                    bail!("{provider} did not return an SSH key ID when uploading key");
                }
                ids.push(id);
            }
        }
    }
    Ok(ids)
}

pub async fn create(
    provider: &str,
    token: &str,
    name: &str,
    size: &str,
    region: &str,
    image: &str,
    pubkeys: &[String],
) -> Result<Created> {
    let http = reqwest::Client::new();
    use reqwest::Method as M;
    match provider {
        "hetzner" => {
            let base = "https://api.hetzner.cloud/v1";
            let key_ids = ensure_keys(&http, "hetzner", token, &format!("{base}/ssh_keys"), pubkeys).await?;
            let res = api(
                &http,
                M::POST,
                &format!("{base}/servers"),
                token,
                Some(json!({
                    "name": name, "server_type": size, "image": image, "location": region,
                    "ssh_keys": key_ids, "start_after_create": true,
                    "labels": {"managed-by": "latrix"}
                })),
            )
            .await?;
            let id = res["server"]["id"].as_i64().context("no server id in response")?;
            let pref = ProviderRef {
                provider: "hetzner".into(),
                id: id.to_string(),
                size: size.into(),
                region: region.into(),
            };
            let poll = async {
                let start = Instant::now();
                let mut consecutive_errs = 0u32;
                loop {
                    match api(&http, M::GET, &format!("{base}/servers/{id}"), token, None).await {
                        Ok(s) => {
                            consecutive_errs = 0;
                            let srv = &s["server"];
                            let ip = srv["public_net"]["ipv4"]["ip"].as_str().unwrap_or("").to_string();
                            if srv["status"] == "running" && !ip.is_empty() {
                                let price = srv["server_type"]["prices"]
                                    .as_array()
                                    .and_then(|p| p.iter().find(|x| x["location"] == region).or(p.first()))
                                    .and_then(|p| p["price_monthly"]["gross"].as_str())
                                    .and_then(|p| p.parse::<f64>().ok());
                                return Ok(Created {
                                    ip,
                                    monthly_cost: price,
                                    provider: pref.clone(),
                                });
                            }
                        }
                        Err(e) => {
                            consecutive_errs += 1;
                            if consecutive_errs >= 5 {
                                return Err(e);
                            }
                        }
                    }
                    if start.elapsed() > Duration::from_secs(300) {
                        bail!("server {id} did not start within 5 minutes");
                    }
                    tokio::time::sleep(Duration::from_secs(4)).await;
                }
            }
            .await;
            if poll.is_err() {
                let _ = destroy(&pref, token).await;
            }
            poll
        }
        "digitalocean" => {
            let base = "https://api.digitalocean.com/v2";
            let key_ids = ensure_keys(&http, "digitalocean", token, &format!("{base}/account/keys"), pubkeys).await?;
            let res = api(
                &http,
                M::POST,
                &format!("{base}/droplets"),
                token,
                Some(json!({
                    "name": name, "region": region, "size": size, "image": image,
                    "ssh_keys": key_ids, "tags": ["latrix"]
                })),
            )
            .await?;
            let id = res["droplet"]["id"].as_i64().context("no droplet id in response")?;
            let pref = ProviderRef {
                provider: "digitalocean".into(),
                id: id.to_string(),
                size: size.into(),
                region: region.into(),
            };
            let poll = async {
                let start = Instant::now();
                let mut consecutive_errs = 0u32;
                loop {
                    match api(&http, M::GET, &format!("{base}/droplets/{id}"), token, None).await {
                        Ok(d) => {
                            consecutive_errs = 0;
                            let dr = &d["droplet"];
                            let ip = dr["networks"]["v4"]
                                .as_array()
                                .and_then(|n| n.iter().find(|x| x["type"] == "public"))
                                .and_then(|x| x["ip_address"].as_str())
                                .unwrap_or("")
                                .to_string();
                            if dr["status"] == "active" && !ip.is_empty() {
                                return Ok(Created {
                                    ip,
                                    monthly_cost: dr["size"]["price_monthly"].as_f64(),
                                    provider: pref.clone(),
                                });
                            }
                        }
                        Err(e) => {
                            consecutive_errs += 1;
                            if consecutive_errs >= 5 {
                                return Err(e);
                            }
                        }
                    }
                    if start.elapsed() > Duration::from_secs(300) {
                        bail!("droplet {id} did not become active within 5 minutes");
                    }
                    tokio::time::sleep(Duration::from_secs(4)).await;
                }
            }
            .await;
            if poll.is_err() {
                let _ = destroy(&pref, token).await;
            }
            poll
        }
        other => bail!("unknown provider '{other}'"),
    }
}

pub async fn destroy(p: &ProviderRef, token: &str) -> Result<()> {
    let id = validate_provider_id(&p.id)?;
    let http = reqwest::Client::new();
    let url = match p.provider.as_str() {
        "hetzner" => format!("https://api.hetzner.cloud/v1/servers/{id}"),
        "digitalocean" => format!("https://api.digitalocean.com/v2/droplets/{id}"),
        other => bail!("unknown provider {other}"),
    };
    api(&http, reqwest::Method::DELETE, &url, token, None).await?;
    Ok(())
}

/// One purchasable server: a size in a location, with its monthly price.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Offer {
    pub provider: String,
    pub size: String,
    pub location: String,
    pub cpus: f64,
    pub memory_mb: u64,
    pub disk_gb: u64,
    /// "x86" or "arm"
    pub arch: String,
    pub price: f64,
}

/// Parse Hetzner's /server_types into offers (one per size and location).
pub fn hetzner_offers(v: &Value) -> Vec<Offer> {
    let mut out = vec![];
    for t in v["server_types"].as_array().cloned().unwrap_or_default() {
        if t["deprecated"].as_bool().unwrap_or(false) || !t["deprecation"].is_null() {
            continue;
        }
        for p in t["prices"].as_array().cloned().unwrap_or_default() {
            let price = p["price_monthly"]["gross"]
                .as_str()
                .and_then(|x| x.parse::<f64>().ok())
                .filter(|x| x.is_finite() && *x >= 0.0);
            let (Some(price), Some(loc)) = (price, p["location"].as_str()) else { continue };
            out.push(Offer {
                provider: "hetzner".into(),
                size: t["name"].as_str().unwrap_or_default().into(),
                location: loc.into(),
                cpus: t["cores"].as_f64().unwrap_or(1.0),
                memory_mb: (t["memory"].as_f64().unwrap_or(0.0) * 1024.0) as u64,
                disk_gb: t["disk"].as_u64().unwrap_or(0),
                arch: t["architecture"].as_str().unwrap_or("x86").into(),
                price,
            });
        }
    }
    out
}

/// Parse DigitalOcean's /sizes into offers (one per size and region).
pub fn do_offers(v: &Value) -> Vec<Offer> {
    let mut out = vec![];
    for s in v["sizes"].as_array().cloned().unwrap_or_default() {
        if !s["available"].as_bool().unwrap_or(true) {
            continue;
        }
        let slug = s["slug"].as_str().unwrap_or_default();
        if slug.contains("gpu") {
            continue;
        }
        let Some(price) = s["price_monthly"].as_f64().filter(|x| x.is_finite() && *x >= 0.0) else {
            continue;
        };
        for r in s["regions"].as_array().cloned().unwrap_or_default() {
            let Some(r) = r.as_str() else { continue };
            out.push(Offer {
                provider: "digitalocean".into(),
                size: slug.into(),
                location: r.into(),
                cpus: s["vcpus"].as_f64().unwrap_or(1.0),
                memory_mb: s["memory"].as_u64().unwrap_or(0),
                disk_gb: s["disk"].as_u64().unwrap_or(0),
                arch: "x86".into(),
                price,
            });
        }
    }
    out
}

/// Everything a provider sells right now, with prices.
pub async fn catalog(provider: &str, token: &str) -> Result<Vec<Offer>> {
    let http = reqwest::Client::new();
    match provider {
        "hetzner" => {
            let list = hetzner_paginated(&http, token, "https://api.hetzner.cloud/v1/server_types", "server_types").await?;
            Ok(hetzner_offers(&json!({"server_types": list})))
        }
        "digitalocean" => {
            let list = do_paginated(&http, token, "https://api.digitalocean.com/v2/sizes", "sizes").await?;
            Ok(do_offers(&json!({"sizes": list})))
        }
        other => bail!("unknown provider '{other}'"),
    }
}

/// The cheapest offer with at least this much memory/CPU. At equal price it
/// prefers the given locations (where the cluster already is), then more memory.
pub fn cheapest<'a>(
    offers: &'a [Offer],
    min_memory_mb: u64,
    min_cpus: f64,
    arch: &str,
    prefer: &[String],
    max_price: Option<f64>,
) -> Option<&'a Offer> {
    offers
        .iter()
        .filter(|o| o.price.is_finite() && o.price >= 0.0)
        .filter(|o| o.arch == arch && o.memory_mb >= min_memory_mb && o.cpus >= min_cpus)
        .filter(|o| max_price.map(|m| o.price <= m + 1e-9).unwrap_or(true))
        .min_by(|a, b| {
            a.price
                .total_cmp(&b.price)
                .then((!prefer.contains(&a.location)).cmp(&!prefer.contains(&b.location)))
                .then(b.memory_mb.cmp(&a.memory_mb))
        })
}

/// "x86_64"/"aarch64" -> the providers' "x86"/"arm".
pub fn provider_arch(arch: &str) -> &'static str {
    match arch {
        "aarch64" | "arm64" | "arm" => "arm",
        _ => "x86",
    }
}

/// Server state at the provider ("running", "off", ...), or None if it no longer exists.
pub async fn server_status(p: &ProviderRef, token: &str) -> Result<Option<String>> {
    let id = validate_provider_id(&p.id)?;
    let http = reqwest::Client::new();
    let (url, field) = match p.provider.as_str() {
        "hetzner" => (format!("https://api.hetzner.cloud/v1/servers/{id}"), "server"),
        "digitalocean" => (format!("https://api.digitalocean.com/v2/droplets/{id}"), "droplet"),
        other => bail!("unknown provider '{other}'"),
    };
    match api(&http, reqwest::Method::GET, &url, token, None).await {
        Ok(v) => Ok(v[field]["status"].as_str().map(String::from)),
        Err(e) => {
            if let Some(api_err) = e.downcast_ref::<ProviderApiError>() {
                if api_err.status == reqwest::StatusCode::NOT_FOUND {
                    return Ok(None);
                }
            }
            Err(e)
        }
    }
}

/// Hard-reboot a server through the provider API.
pub async fn reboot(p: &ProviderRef, token: &str) -> Result<()> {
    let id = validate_provider_id(&p.id)?;
    let http = reqwest::Client::new();
    match p.provider.as_str() {
        "hetzner" => {
            let url = format!("https://api.hetzner.cloud/v1/servers/{id}/actions/reset");
            api(&http, reqwest::Method::POST, &url, token, None).await?;
        }
        "digitalocean" => {
            let url = format!("https://api.digitalocean.com/v2/droplets/{id}/actions");
            api(&http, reqwest::Method::POST, &url, token, Some(json!({"type": "power_cycle"}))).await?;
        }
        other => bail!("unknown provider '{other}'"),
    }
    Ok(())
}

/// Print available sizes with monthly prices.
pub async fn sizes(provider: &str, token: &str) -> Result<()> {
    let http = reqwest::Client::new();
    let mut rows = vec![];
    let price_col = match provider {
        "hetzner" => {
            let list = hetzner_paginated(&http, token, "https://api.hetzner.cloud/v1/server_types", "server_types").await?;
            for t in list {
                if t["deprecated"].as_bool().unwrap_or(false) || !t["deprecation"].is_null() {
                    continue;
                }
                let prices = t["prices"].as_array().cloned().unwrap_or_default();
                let price = prices
                    .first()
                    .and_then(|p| p["price_monthly"]["gross"].as_str())
                    .and_then(|p| p.parse::<f64>().ok())
                    .filter(|p| p.is_finite() && *p >= 0.0)
                    .unwrap_or(0.0);
                let locs: Vec<String> = prices.iter().filter_map(|p| p["location"].as_str().map(String::from)).collect();
                rows.push((
                    price,
                    vec![
                        t["name"].as_str().unwrap_or("").into(),
                        t["cores"].to_string(),
                        format!("{} GB", t["memory"]),
                        format!("{} GB", t["disk"]),
                        t["architecture"].as_str().unwrap_or("").into(),
                        format!("{price:.2}"),
                        locs.join(","),
                    ],
                ));
            }
            "EUR/MONTH"
        }
        "digitalocean" => {
            let list = do_paginated(&http, token, "https://api.digitalocean.com/v2/sizes", "sizes").await?;
            for s in list {
                if !s["available"].as_bool().unwrap_or(true) {
                    continue;
                }
                let price = s["price_monthly"]
                    .as_f64()
                    .filter(|p| p.is_finite() && *p >= 0.0)
                    .unwrap_or(0.0);
                let regions: Vec<String> = s["regions"]
                    .as_array()
                    .map(|r| r.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                rows.push((
                    price,
                    vec![
                        s["slug"].as_str().unwrap_or("").into(),
                        s["vcpus"].to_string(),
                        format!("{} GB", s["memory"].as_f64().unwrap_or(0.0) / 1024.0),
                        format!("{} GB", s["disk"]),
                        "x86".into(),
                        format!("{price:.2}"),
                        regions.join(","),
                    ],
                ));
            }
            "USD/MONTH"
        }
        other => bail!("unknown provider '{other}'"),
    };
    rows.sort_by(|a, b| a.0.total_cmp(&b.0));
    print_table(
        &["SIZE", "CPUS", "MEMORY", "DISK", "ARCH", price_col, "REGIONS"],
        rows.into_iter().map(|r| r.1).take(40).collect(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_newest_lts_hetzner() {
        let v = json!({"images": [
            {"name": "ubuntu-24.04", "os_flavor": "ubuntu", "os_version": "24.04", "architecture": "x86", "deprecated": null, "status": "available"},
            {"name": "ubuntu-26.04", "os_flavor": "ubuntu", "os_version": "26.04", "architecture": "x86", "deprecated": null, "status": "available"},
            {"name": "ubuntu-26.10", "os_flavor": "ubuntu", "os_version": "26.10", "architecture": "x86", "deprecated": null, "status": "available"},
            {"name": "ubuntu-28.04-arm", "os_flavor": "ubuntu", "os_version": "28.04", "architecture": "arm", "deprecated": null, "status": "available"},
            {"name": "ubuntu-22.04", "os_flavor": "ubuntu", "os_version": "22.04", "architecture": "x86", "deprecated": "2027-01-01", "status": "available"},
            {"name": "debian-13", "os_flavor": "debian", "os_version": "13", "architecture": "x86", "deprecated": null, "status": "available"}
        ]});
        assert_eq!(pick_hetzner_ubuntu(&v, "x86").as_deref(), Some("ubuntu-26.04"));
        assert_eq!(pick_hetzner_ubuntu(&v, "arm").as_deref(), Some("ubuntu-28.04-arm"));
    }

    #[test]
    fn generates_a_key_when_the_user_has_none() {
        let dir = std::env::temp_dir().join(format!("latrix-keytest-{}", random_id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let own = dir.join("cfg").join("id_ed25519");
        let (pubkey, path) = ssh_key_in(None, Some(&dir), &own).unwrap();
        assert!(pubkey.starts_with("ssh-ed25519 "));
        assert_eq!(path.as_deref(), Some(own.to_str().unwrap()));
        // second call reuses it
        assert_eq!(ssh_key_in(None, Some(&dir), &own).unwrap().0, pubkey);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn offers_and_cheapest() {
        let h = json!({"server_types": [
            {"name": "cx23", "cores": 2, "memory": 4.0, "disk": 40, "architecture": "x86", "deprecated": false, "deprecation": null,
             "prices": [{"location": "fsn1", "price_monthly": {"gross": "4.8500"}}, {"location": "ash", "price_monthly": {"gross": "5.9900"}}]},
            {"name": "cax11", "cores": 2, "memory": 4.0, "disk": 40, "architecture": "arm", "deprecated": false, "deprecation": null,
             "prices": [{"location": "fsn1", "price_monthly": {"gross": "4.4900"}}]},
            {"name": "cx33", "cores": 4, "memory": 8.0, "disk": 80, "architecture": "x86", "deprecated": false, "deprecation": null,
             "prices": [{"location": "fsn1", "price_monthly": {"gross": "7.9900"}}, {"location": "nbg1", "price_monthly": {"gross": "7.9900"}}]},
            {"name": "cx11", "cores": 1, "memory": 2.0, "disk": 20, "architecture": "x86", "deprecated": true, "deprecation": {},
             "prices": [{"location": "fsn1", "price_monthly": {"gross": "3.0000"}}]}
        ]});
        let offers = hetzner_offers(&h);
        assert_eq!(offers.len(), 5, "deprecated types skipped");
        let c = cheapest(&offers, 2048, 1.0, "x86", &[], None).unwrap();
        assert_eq!((c.size.as_str(), c.location.as_str()), ("cx23", "fsn1"));
        let c = cheapest(&offers, 6000, 1.0, "x86", &["nbg1".into()], None).unwrap();
        assert_eq!((c.size.as_str(), c.location.as_str()), ("cx33", "nbg1"), "same price: prefer existing location");
        assert!(cheapest(&offers, 6000, 1.0, "x86", &[], Some(5.0)).is_none(), "budget respected");
        assert_eq!(cheapest(&offers, 2048, 1.0, "arm", &[], None).unwrap().size, "cax11");

        let d = json!({"sizes": [
            {"slug": "s-1vcpu-1gb", "memory": 1024, "vcpus": 1, "disk": 25, "price_monthly": 6.0, "regions": ["fra1", "nyc3"], "available": true},
            {"slug": "s-1vcpu-2gb", "memory": 2048, "vcpus": 1, "disk": 50, "price_monthly": 12.0, "regions": ["fra1"], "available": true},
            {"slug": "gpu-h100x1", "memory": 245760, "vcpus": 20, "disk": 720, "price_monthly": 2500.0, "regions": ["nyc2"], "available": true}
        ]});
        let offers = do_offers(&d);
        assert_eq!(offers.len(), 3);
        assert_eq!(cheapest(&offers, 2048, 1.0, "x86", &[], None).unwrap().size, "s-1vcpu-2gb");
    }

    #[test]
    fn picks_newest_lts_digitalocean() {
        let v = json!({"images": [
            {"slug": "ubuntu-24-04-x64"}, {"slug": "ubuntu-26-04-x64"}, {"slug": "ubuntu-25-10-x64"},
            {"slug": "debian-13-x64"}, {"slug": null}
        ]});
        assert_eq!(pick_do_ubuntu(&v).as_deref(), Some("ubuntu-26-04-x64"));
    }
}
