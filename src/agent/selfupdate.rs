//! Automatic upgrades of latrix itself.
//!
//! The leader checks GitHub for a newer release every 6 hours (or right away
//! when asked by `latrix self-update`) and upgrades machines one at a time,
//! itself last. Each machine downloads the build for its own CPU, checks that
//! it runs, swaps it in and restarts its agent; containers keep running.

use super::Agent;
use crate::util::{self, API_PORT};
use anyhow::{bail, Context, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub const REPO: &str = "jreoka/latrix";

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    let mut it = v.split('.').map(|p| p.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("").parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

pub fn newer(a: &str, b: &str) -> bool {
    matches!((parse_version(a), parse_version(b)), (Some(x), Some(y)) if x > y)
}

/// The newest published version ("0.1.9"), via the releases/latest redirect
/// (no GitHub API rate limits).
pub async fn latest_version() -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let r = client.get(format!("https://github.com/{REPO}/releases/latest")).send().await?;
    let loc = r
        .headers()
        .get("location")
        .and_then(|l| l.to_str().ok())
        .context("no release found")?
        .to_string();
    let tag = loc.rsplit('/').next().unwrap_or("").to_string();
    if parse_version(&tag).is_none() {
        bail!("unexpected release tag '{tag}'");
    }
    Ok(tag.trim_start_matches('v').to_string())
}

pub fn asset_url(version: &str, asset: &str) -> String {
    let base = std::env::var("LATRIX_RELEASE_BASE")
        .unwrap_or_else(|_| format!("https://github.com/{REPO}/releases/download/v{version}"));
    format!("{base}/{asset}")
}

/// Download `version`, check it runs, and swap it in at /usr/local/bin/latrix.
pub async fn install(version: &str) -> Result<()> {
    let url = asset_url(version, &format!("latrix-{}-unknown-linux-musl", std::env::consts::ARCH));
    let bytes = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(300))
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("downloading {url}"))?
        .bytes()
        .await?;
    let target = std::path::Path::new("/usr/local/bin/latrix");
    let tmp = target.with_extension("new");
    std::fs::write(&tmp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    let out = super::cmd(&tmp.display().to_string(), &["--version"]).await?;
    if !out.contains(version) {
        let _ = std::fs::remove_file(&tmp);
        bail!("downloaded binary reports '{}', expected {version}", out.trim());
    }
    std::fs::rename(&tmp, target)?;
    Ok(())
}

/// POST /v1/local/self-update {"version": "x.y.z"}: install, then restart.
pub async fn handle(
    axum::extract::State(agent): axum::extract::State<Arc<Agent>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(v) = body["version"].as_str().filter(|v| parse_version(v).is_some()).map(String::from) else {
        return (axum::http::StatusCode::BAD_REQUEST, "version required").into_response();
    };
    if agent.dev {
        return (axum::http::StatusCode::BAD_REQUEST, "the local dev cluster runs your own binary").into_response();
    }
    if let Err(e) = install(&v).await {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response();
    }
    restart_soon();
    axum::Json(true).into_response()
}

fn restart_soon() {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = super::cmd("systemctl", &["restart", "latrix"]).await;
    });
}

async fn upgrade_machine(agent: &Arc<Agent>, id: u32, version: &str) -> Result<()> {
    let ip = agent.ip_of(id).context("unknown machine")?;
    let r = agent
        .http
        .post(format!("http://{ip}:{API_PORT}/v1/local/self-update"))
        .bearer_auth(&agent.me.token)
        .timeout(Duration::from_secs(330))
        .json(&serde_json::json!({ "version": version }))
        .send()
        .await?;
    if !r.status().is_success() {
        bail!("{}", r.text().await.unwrap_or_default());
    }
    // Wait for it to come back on the new version.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(240) {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let back = agent
            .reports
            .lock()
            .unwrap()
            .get(&id)
            .map(|(at, r)| at.elapsed() < Duration::from_secs(8) && r.agent_version == version)
            .unwrap_or(false);
        if back {
            return Ok(());
        }
    }
    bail!("did not come back on {version} within 4 minutes")
}

async fn upgrade_cluster(agent: &Arc<Agent>) -> Result<()> {
    let latest = latest_version().await?;
    if !newer(&latest, util::VERSION) {
        let s = agent.snapshot();
        let outdated = agent
            .reports
            .lock()
            .unwrap()
            .iter()
            .any(|(m, (_, r))| s.machines.contains_key(m) && newer(util::VERSION, &r.agent_version));
        if !outdated {
            return Ok(());
        }
    }
    let target = if newer(&latest, util::VERSION) { latest.clone() } else { util::VERSION.to_string() };
    let s = agent.snapshot();
    let others: Vec<(u32, String, String)> = {
        let reports = agent.reports.lock().unwrap();
        s.machines
            .values()
            .filter(|m| m.id != agent.me.machine_id && agent.alive_set().contains(&m.id))
            .filter_map(|m| {
                let v = reports.get(&m.id).map(|(_, r)| r.agent_version.clone()).unwrap_or_default();
                newer(&target, &v).then(|| (m.id, m.name.clone(), v))
            })
            .collect()
    };
    for (id, name, from) in others {
        info!("upgrading {name} from {from} to {target}");
        match upgrade_machine(agent, id, &target).await {
            Ok(()) => agent.event("info", format!("{name} upgraded to latrix {target}")),
            Err(e) => {
                agent.event("warn", format!("automatic upgrade of {name} to latrix {target} failed: {e:#}"));
                return Ok(());
            }
        }
    }
    if newer(&target, util::VERSION) {
        agent.event("info", format!("upgrading this machine (the leader) to latrix {target}"));
        install(&target).await?;
        restart_soon();
    }
    Ok(())
}

pub async fn run(agent: Arc<Agent>) {
    if agent.dev {
        return;
    }
    tokio::time::sleep(Duration::from_secs(300)).await;
    loop {
        if agent.is_leader() && agent.snapshot().settings.auto_upgrade {
            if let Err(e) = upgrade_cluster(&agent).await {
                warn!("automatic upgrade check: {e:#}");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(6 * 3600)) => {},
            _ = agent.upgrade_now.notified() => {},
        }
    }
}

/// POST /v1/upgrade-now (leader): check for a new release right away.
pub async fn handle_now(axum::extract::State(agent): axum::extract::State<Arc<Agent>>) -> axum::Json<bool> {
    agent.upgrade_now.notify_one();
    axum::Json(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert!(newer("0.1.10", "0.1.9"));
        assert!(newer("v1.0.0", "0.9.9"));
        assert!(!newer("0.1.8", "0.1.8"));
        assert!(!newer("0.1.7", "0.1.8"));
        assert!(!newer("garbage", "0.1.8"));
        assert_eq!(parse_version("latrix 0.2.3"), None);
        assert_eq!(parse_version("0.2.3-rc1"), Some((0, 2, 3)));
    }
}
