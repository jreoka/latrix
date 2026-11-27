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

pub fn defaults(provider: &str) -> (&'static str, &'static str) {
    // (size, region)
    match provider {
        "hetzner" => ("cx22", "fsn1"),
        _ => ("s-1vcpu-1gb", "fra1"),
    }
}

/// Fallback when the provider's image list can't be read.
fn fallback_image(provider: &str) -> &'static str {
    match provider {
        "hetzner" => "ubuntu-24.04",
        _ => "ubuntu-24-04-x64",
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
            api(&http, M::GET, &format!("{base}/images?type=system&per_page=50"), token, None)
                .await
                .ok()
                .and_then(|v| pick_hetzner_ubuntu(&v, &arch))
        }
        _ => api(&http, M::GET, "https://api.digitalocean.com/v2/images?type=distribution&per_page=200", token, None)
            .await
            .ok()
            .and_then(|v| pick_do_ubuntu(&v)),
    };
    found.unwrap_or_else(|| {
        let f = fallback_image(provider);
        println!("    (could not list {provider} images; using {f}, pass --image to choose)");
        f.to_string()
    })
}

/// The SSH key used for servers latrix creates: (public key, private key
/// path to use, or None for ssh's defaults). Uses --key or your usual key
/// (~/.ssh/id_ed25519 etc.); if you have none, latrix creates and manages
/// its own key next to its config, so you don't need to set anything up.
pub fn ssh_key(key: Option<&str>) -> Result<(String, Option<String>)> {
    if let Some(k) = key {
        let pub_path = format!("{k}.pub");
        let pubkey = std::fs::read_to_string(&pub_path)
            .with_context(|| format!("reading {pub_path} (the public half of --key)"))?;
        return Ok((pubkey.trim().to_string(), Some(k.to_string())));
    }
    let home = dirs::home_dir().unwrap_or_default().join(".ssh");
    for f in ["id_ed25519", "id_ecdsa", "id_rsa"] {
        if let Ok(k) = std::fs::read_to_string(home.join(format!("{f}.pub"))) {
            return Ok((k.trim().to_string(), None));
        }
    }
    let own = managed_key_path();
    let own_pub = PathBuf::from(format!("{}.pub", own.display()));
    if !own_pub.exists() {
        if let Some(dir) = own.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "latrix", "-f"])
            .arg(&own)
            .stdin(std::process::Stdio::null())
            .status()
            .context("could not run ssh-keygen (is OpenSSH installed?)")?;
        if !st.success() {
            bail!("ssh-keygen failed");
        }
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
        // Only this test touches HOME / LATRIX_CONFIG.
        std::env::set_var("HOME", &dir);
        std::env::set_var("LATRIX_CONFIG", dir.join("cfg/config.toml"));
        let (pubkey, path) = ssh_key(None).unwrap();
        assert!(pubkey.starts_with("ssh-ed25519 "));
        assert_eq!(path.as_deref(), Some(dir.join("cfg/id_ed25519").to_str().unwrap()));
        // second call reuses it
        assert_eq!(ssh_key(None).unwrap().0, pubkey);
        let _ = std::fs::remove_dir_all(dir);
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
