//! Optional: create servers on Hetzner Cloud or DigitalOcean and add them to
//! the cluster in one step. Tokens come from `latrix provider set` or the
//! HCLOUD_TOKEN / DIGITALOCEAN_TOKEN environment variables.

use super::profile::CliConfig;
use crate::state::ProviderRef;
use crate::util::{print_table, random_id};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, Instant};

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

pub fn token(cfg: &CliConfig, provider: &str) -> Result<String> {
    let p = canonical(provider)?;
    let env = if p == "hetzner" { "HCLOUD_TOKEN" } else { "DIGITALOCEAN_TOKEN" };
    std::env::var(env)
        .ok()
        .or_else(|| cfg.providers.get(p).cloned())
        .ok_or_else(|| anyhow!("no API token for {p}: run `latrix provider set {p} <token>` or set {env}"))
}

pub fn defaults(provider: &str) -> (&'static str, &'static str, &'static str) {
    // (size, region, image)
    match provider {
        "hetzner" => ("cx22", "fsn1", "ubuntu-24.04"),
        _ => ("s-1vcpu-1gb", "fra1", "ubuntu-24-04-x64"),
    }
}

pub fn local_pubkey(key: Option<&str>) -> Result<String> {
    let candidates: Vec<PathBuf> = match key {
        Some(k) => vec![PathBuf::from(format!("{k}.pub"))],
        None => {
            let home = dirs::home_dir().unwrap_or_default().join(".ssh");
            ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"]
                .iter()
                .map(|f| home.join(f))
                .collect()
        }
    };
    for c in &candidates {
        if let Ok(k) = std::fs::read_to_string(c) {
            return Ok(k.trim().to_string());
        }
    }
    bail!("no SSH public key found (looked for {:?}); create one with ssh-keygen -t ed25519", candidates)
}

fn same_key(a: &str, b: &str) -> bool {
    let f = |s: &str| s.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    f(a) == f(b)
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
        bail!("{url}: {status}: {}", text.chars().take(400).collect::<String>());
    }
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_str(&text)?)
}

pub async fn create(
    provider: &str,
    token: &str,
    name: &str,
    size: &str,
    region: &str,
    image: &str,
    pubkey: &str,
) -> Result<Created> {
    let http = reqwest::Client::new();
    use reqwest::Method as M;
    match provider {
        "hetzner" => {
            let base = "https://api.hetzner.cloud/v1";
            let keys = api(&http, M::GET, &format!("{base}/ssh_keys?per_page=50"), token, None).await?;
            let key_id = match keys["ssh_keys"]
                .as_array()
                .and_then(|a| a.iter().find(|k| same_key(k["public_key"].as_str().unwrap_or(""), pubkey)))
            {
                Some(k) => k["id"].clone(),
                None => {
                    let k = api(
                        &http,
                        M::POST,
                        &format!("{base}/ssh_keys"),
                        token,
                        Some(json!({"name": format!("latrix-{}", random_id(5)), "public_key": pubkey})),
                    )
                    .await?;
                    k["ssh_key"]["id"].clone()
                }
            };
            let res = api(
                &http,
                M::POST,
                &format!("{base}/servers"),
                token,
                Some(json!({
                    "name": name, "server_type": size, "image": image, "location": region,
                    "ssh_keys": [key_id], "start_after_create": true,
                    "labels": {"managed-by": "latrix"}
                })),
            )
            .await?;
            let id = res["server"]["id"].as_i64().context("no server id in response")?;
            let start = Instant::now();
            loop {
                let s = api(&http, M::GET, &format!("{base}/servers/{id}"), token, None).await?;
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
                        provider: ProviderRef {
                            provider: "hetzner".into(),
                            id: id.to_string(),
                            size: size.into(),
                            region: region.into(),
                        },
                    });
                }
                if start.elapsed() > Duration::from_secs(300) {
                    bail!("server {id} did not start within 5 minutes");
                }
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        }
        _ => {
            let base = "https://api.digitalocean.com/v2";
            let keys = api(&http, M::GET, &format!("{base}/account/keys?per_page=200"), token, None).await?;
            let key_id = match keys["ssh_keys"]
                .as_array()
                .and_then(|a| a.iter().find(|k| same_key(k["public_key"].as_str().unwrap_or(""), pubkey)))
            {
                Some(k) => k["id"].clone(),
                None => {
                    let k = api(
                        &http,
                        M::POST,
                        &format!("{base}/account/keys"),
                        token,
                        Some(json!({"name": format!("latrix-{}", random_id(5)), "public_key": pubkey})),
                    )
                    .await?;
                    k["ssh_key"]["id"].clone()
                }
            };
            let res = api(
                &http,
                M::POST,
                &format!("{base}/droplets"),
                token,
                Some(json!({
                    "name": name, "region": region, "size": size, "image": image,
                    "ssh_keys": [key_id], "tags": ["latrix"]
                })),
            )
            .await?;
            let id = res["droplet"]["id"].as_i64().context("no droplet id in response")?;
            let start = Instant::now();
            loop {
                let d = api(&http, M::GET, &format!("{base}/droplets/{id}"), token, None).await?;
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
                        provider: ProviderRef {
                            provider: "digitalocean".into(),
                            id: id.to_string(),
                            size: size.into(),
                            region: region.into(),
                        },
                    });
                }
                if start.elapsed() > Duration::from_secs(300) {
                    bail!("droplet {id} did not become active within 5 minutes");
                }
                tokio::time::sleep(Duration::from_secs(4)).await;
            }
        }
    }
}

pub async fn destroy(p: &ProviderRef, token: &str) -> Result<()> {
    let http = reqwest::Client::new();
    let url = match p.provider.as_str() {
        "hetzner" => format!("https://api.hetzner.cloud/v1/servers/{}", p.id),
        "digitalocean" => format!("https://api.digitalocean.com/v2/droplets/{}", p.id),
        other => bail!("unknown provider {other}"),
    };
    api(&http, reqwest::Method::DELETE, &url, token, None).await?;
    Ok(())
}

/// Print available sizes with monthly prices.
pub async fn sizes(provider: &str, token: &str) -> Result<()> {
    let http = reqwest::Client::new();
    let mut rows = vec![];
    match provider {
        "hetzner" => {
            let v = api(&http, reqwest::Method::GET, "https://api.hetzner.cloud/v1/server_types?per_page=50", token, None).await?;
            for t in v["server_types"].as_array().cloned().unwrap_or_default() {
                if t["deprecated"].as_bool().unwrap_or(false) {
                    continue;
                }
                let prices = t["prices"].as_array().cloned().unwrap_or_default();
                let price = prices
                    .first()
                    .and_then(|p| p["price_monthly"]["gross"].as_str())
                    .and_then(|p| p.parse::<f64>().ok())
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
        }
        _ => {
            let v = api(&http, reqwest::Method::GET, "https://api.digitalocean.com/v2/sizes?per_page=200", token, None).await?;
            for s in v["sizes"].as_array().cloned().unwrap_or_default() {
                if !s["available"].as_bool().unwrap_or(true) {
                    continue;
                }
                let price = s["price_monthly"].as_f64().unwrap_or(0.0);
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
        }
    }
    rows.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    print_table(
        &["SIZE", "CPUS", "MEMORY", "DISK", "ARCH", "$/MONTH", "REGIONS"],
        rows.into_iter().map(|r| r.1).take(40).collect(),
    );
    Ok(())
}
