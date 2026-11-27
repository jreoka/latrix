//! Replicated volumes.
//!
//! A volume lives on its primary machine (where the app runs) and is copied
//! with rsync over the WireGuard mesh to `copies - 1` replica machines every
//! `sync` interval. On a planned move (drain, maintenance, OS updates) the app
//! is stopped first and a final sync runs before it starts on the replica, so
//! nothing is lost. If the primary dies unexpectedly, the freshest replica is
//! promoted (you lose at most one sync interval of writes).

use super::{cmd, set_private, Agent};
use crate::state::{Volume, VolumeReport};
use crate::util::{now, RSYNC_PORT};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

#[derive(Default)]
pub struct VolumeState {
    reports: Mutex<HashMap<String, VolumeReport>>,
    last_running: Mutex<HashMap<String, u64>>,
    sized_at: Mutex<HashMap<String, u64>>,
    kick: Notify,
}

impl VolumeState {
    pub fn reports(&self) -> Vec<VolumeReport> {
        self.reports.lock().unwrap().values().cloned().collect()
    }
    /// Wake the sync loop (e.g. right after a container stopped).
    pub fn kick(&self) {
        self.kick.notify_one();
    }
}

fn password(agent: &Agent) -> String {
    agent.me.token.chars().take(24).collect()
}

fn volumes_dir(agent: &Agent) -> PathBuf {
    agent.data.join("volumes")
}

pub async fn run(agent: Arc<Agent>) {
    let _ = std::fs::create_dir_all(volumes_dir(&agent));
    if !agent.dev {
        tokio::spawn(rsync_daemon(agent.clone()));
    }
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {},
            _ = agent.vols.kick.notified() => {},
        }
        if let Err(e) = sync_once(&agent).await {
            warn!("volume sync: {e:#}");
        }
    }
}

async fn rsync_daemon(agent: Arc<Agent>) {
    let conf = agent.data.join("rsyncd.conf");
    let secrets = agent.data.join("rsyncd.secrets");
    let text = format!(
        "uid = root\ngid = root\nuse chroot = yes\nmax connections = 16\naddress = {ip}\nport = {RSYNC_PORT}\n\
         log file = {log}\n\n[volumes]\n    path = {path}\n    read only = no\n    auth users = latrix\n    \
         secrets file = {secrets}\n    hosts allow = 10.77.0.0/16\n",
        ip = agent.me.overlay_ip,
        log = agent.data.join("rsyncd.log").display(),
        path = volumes_dir(&agent).display(),
        secrets = secrets.display(),
    );
    if std::fs::write(&conf, text).is_err() || std::fs::write(&secrets, format!("latrix:{}\n", password(&agent))).is_err() {
        warn!("cannot write rsync config");
        return;
    }
    set_private(&secrets);
    loop {
        let child = tokio::process::Command::new("rsync")
            .args(["--daemon", "--no-detach", &format!("--config={}", conf.display())])
            .kill_on_drop(true)
            .spawn();
        match child {
            Ok(mut c) => {
                let st = c.wait().await;
                debug!("rsync daemon exited: {st:?}");
            }
            Err(e) => warn!("cannot start rsync daemon (is rsync installed?): {e}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn rsync_to(agent: &Agent, vol: &Volume, ip: &str) -> Result<()> {
    let src = format!("{}/", volumes_dir(agent).join(&vol.id).display());
    let dst = format!("rsync://latrix@{ip}:{RSYNC_PORT}/volumes/{}/", vol.id);
    let out = tokio::process::Command::new("rsync")
        .args(["-a", "--delete", "--numeric-ids", "--partial", "--timeout=120", &src, &dst])
        .env("RSYNC_PASSWORD", password(agent))
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
    if !out.status.success() {
        bail!("rsync to {ip} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

async fn sync_once(agent: &Arc<Agent>) -> Result<()> {
    let s = agent.snapshot();
    let me = agent.me.machine_id;
    let t = now();
    let mut seen = vec![];
    for vol in s.volumes.values().filter(|v| v.primary == me) {
        seen.push(vol.id.clone());
        let dir = volumes_dir(agent).join(&vol.id);
        let _ = std::fs::create_dir_all(&dir);
        let running = agent.rt.running_container(&vol.app);
        if running.is_some() {
            agent.vols.last_running.lock().unwrap().insert(vol.id.clone(), t);
        }
        let last_running = agent.vols.last_running.lock().unwrap().get(&vol.id).copied().unwrap_or(0);
        let mut rep = agent
            .vols
            .reports
            .lock()
            .unwrap()
            .get(&vol.id)
            .cloned()
            .unwrap_or_else(|| VolumeReport {
                id: vol.id.clone(),
                ..Default::default()
            });
        rep.synced.retain(|m, _| vol.replicas.contains(m));
        rep.synced_version.retain(|m, _| vol.replicas.contains(m));
        let idle_needed = running.is_none()
            && (rep.idle_synced_at <= last_running
                || rep.idle_synced_at == 0
                || (vol.moving_to.is_some() && rep.idle_synced_version < vol.moving_version));
        let version_at_start = s.version;
        let due: Vec<u32> = vol
            .replicas
            .iter()
            .copied()
            .filter(|r| idle_needed || t.saturating_sub(rep.synced.get(r).copied().unwrap_or(0)) >= vol.sync_secs)
            .collect();

        if !due.is_empty() {
            // Let the app write a consistent snapshot first, if it asked to.
            if let Some(ctr) = &running {
                let pre = s
                    .apps
                    .get(&vol.app)
                    .and_then(|a| a.config())
                    .and_then(|c| c.volumes.iter().find(|v| v.name == vol.name))
                    .and_then(|v| v.pre_sync.clone());
                if let Some(pre) = pre {
                    if let Err(e) = tokio::time::timeout(
                        Duration::from_secs(120),
                        cmd("docker", &["exec", ctr, "sh", "-c", &pre]),
                    )
                    .await
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out")))
                    {
                        warn!("pre_sync for {} failed: {e}", vol.id);
                    }
                }
            }
            let mut all_ok = true;
            for r in &due {
                let Some(ip) = agent.ip_of(*r) else { continue };
                match rsync_to(agent, vol, &ip).await {
                    Ok(()) => {
                        rep.synced.insert(*r, now());
                        rep.synced_version.insert(*r, version_at_start);
                        rep.error = None;
                    }
                    Err(e) => {
                        all_ok = false;
                        rep.error = Some(format!("{e:#}"));
                    }
                }
            }
            if idle_needed && all_ok && agent.rt.running_container(&vol.app).is_none() {
                rep.idle_synced_at = now();
                rep.idle_synced_version = version_at_start;
                info!("final sync of volume {} complete", vol.id);
            }
        } else if idle_needed && vol.replicas.is_empty() {
            rep.idle_synced_at = now();
            rep.idle_synced_version = version_at_start;
        }

        let sized = agent.vols.sized_at.lock().unwrap().get(&vol.id).copied().unwrap_or(0);
        if t.saturating_sub(sized) > 300 {
            if let Ok(out) = cmd("du", &["-sm", &dir.display().to_string()]).await {
                rep.size_mb = out.split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(0);
            }
            agent.vols.sized_at.lock().unwrap().insert(vol.id.clone(), t);
        }
        agent.vols.reports.lock().unwrap().insert(vol.id.clone(), rep);
    }
    agent.vols.reports.lock().unwrap().retain(|k, _| seen.contains(k));

    // Volumes destroyed with --purge-volumes.
    for id in s.tombstones.keys() {
        if id.contains('/') || id.contains("..") {
            continue;
        }
        let dir = volumes_dir(agent).join(id);
        if dir.exists() && !s.volumes.contains_key(id) {
            info!("purging volume data {}", dir.display());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
    Ok(())
}
