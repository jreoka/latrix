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
    /// Volume dirs on this machine that no app uses: id -> (first seen, size MB).
    unused: Mutex<HashMap<String, (u64, u64)>>,
    unused_loaded: std::sync::atomic::AtomicBool,
}

/// Volume data on a machine that no app uses (any more).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnusedVolume {
    pub volume: String,
    pub size_mb: u64,
    pub unused_since: u64,
    /// When it is deleted automatically (0 = never).
    pub delete_at: u64,
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
    {
        let agent = agent.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(90)).await;
            loop {
                if let Err(e) = snapshot_due(&agent).await {
                    warn!("volume snapshots: {e:#}");
                }
                tokio::time::sleep(Duration::from_secs(600)).await;
            }
        });
    }
    {
        let agent = agent.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            loop {
                if let Err(e) = scan_unused(&agent).await {
                    warn!("unused volume scan: {e:#}");
                }
                tokio::time::sleep(Duration::from_secs(600)).await;
            }
        });
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
        let snaps = snapshots_dir(agent).join(id);
        if snaps.exists() && !s.volumes.contains_key(id) {
            let _ = std::fs::remove_dir_all(&snaps);
        }
    }
    Ok(())
}

fn unused_file(agent: &Agent) -> PathBuf {
    agent.data.join("unused-volumes.json")
}

fn load_unused(agent: &Agent) {
    if agent.vols.unused_loaded.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    if let Ok(t) = std::fs::read_to_string(unused_file(agent)) {
        if let Ok(m) = serde_json::from_str::<HashMap<String, (u64, u64)>>(&t) {
            *agent.vols.unused.lock().unwrap() = m;
        }
    }
}

fn save_unused(agent: &Agent) {
    let m = agent.vols.unused.lock().unwrap().clone();
    if let Ok(b) = serde_json::to_vec(&m) {
        let _ = crate::util::write_atomic(&unused_file(agent), &b);
    }
}

/// Is this volume dir used on this machine (as the live copy or a replica)?
fn in_use(s: &crate::state::ClusterState, me: u32, id: &str) -> bool {
    s.volumes
        .get(id)
        .map(|v| v.primary == me || v.replicas.contains(&me) || v.moving_to == Some(me))
        .unwrap_or(false)
}

/// Only judge data unused when this machine's view of the cluster is current.
fn state_is_current(agent: &Agent) -> bool {
    let s = agent.snapshot();
    agent.leader().is_some()
        && s.machines.contains_key(&agent.me.machine_id)
        && s.version >= agent.max_seen_version.load(std::sync::atomic::Ordering::SeqCst)
        && agent.started.elapsed() > Duration::from_secs(120)
}

pub fn retention_secs(s: &crate::state::ClusterState) -> u64 {
    (s.settings.volume_retention_days.max(0.0) * 86400.0) as u64
}

/// Find volume data no app uses on this machine; after the retention period
/// delete it. Also clears temporary leftovers of restores.
pub async fn scan_unused(agent: &Arc<Agent>) -> Result<()> {
    load_unused(agent);
    if !state_is_current(agent) {
        return Ok(());
    }
    let s = agent.snapshot();
    let me = agent.me.machine_id;
    let t = now();
    let retention = retention_secs(&s);
    let base = volumes_dir(agent);
    let mut seen = vec![];
    for entry in std::fs::read_dir(&base)?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            // half-finished restores; remove after a day
            let old = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|m| m.elapsed().unwrap_or_default() > Duration::from_secs(86400))
                .unwrap_or(false);
            if old {
                let _ = std::fs::remove_dir_all(entry.path()).or_else(|_| std::fs::remove_file(entry.path()));
            }
            continue;
        }
        if !entry.path().is_dir() {
            continue;
        }
        if in_use(&s, me, &name) {
            continue;
        }
        seen.push(name.clone());
        let first = agent.vols.unused.lock().unwrap().get(&name).map(|x| x.0);
        match first {
            None => {
                let size = cmd("du", &["-sm", &entry.path().display().to_string()])
                    .await
                    .ok()
                    .and_then(|o| o.split_whitespace().next().and_then(|n| n.parse().ok()))
                    .unwrap_or(0);
                agent.vols.unused.lock().unwrap().insert(name.clone(), (t, size));
                if retention > 0 {
                    agent.event(
                        "info",
                        format!(
                            "volume data {name} ({size} MB) isn't used by any app here; it will be deleted in {} \
                             (deploy the app again to keep it, or `latrix volumes prune` to delete it now)",
                            crate::util::human_duration(retention)
                        ),
                    );
                }
            }
            Some(since) if t.saturating_sub(since) >= retention => {
                info!("deleting unused volume data {name}");
                std::fs::remove_dir_all(entry.path())?;
                let _ = std::fs::remove_dir_all(snapshots_dir(agent).join(&name));
                let size = agent.vols.unused.lock().unwrap().remove(&name).map(|x| x.1).unwrap_or(0);
                agent.event("info", format!("deleted unused volume data {name} ({size} MB)"));
            }
            Some(_) => {}
        }
    }
    agent.vols.unused.lock().unwrap().retain(|k, _| seen.contains(k));
    save_unused(agent);
    Ok(())
}

pub fn unused_list(agent: &Agent) -> Vec<UnusedVolume> {
    load_unused(agent);
    let retention = retention_secs(&agent.snapshot());
    let mut v: Vec<UnusedVolume> = agent
        .vols
        .unused
        .lock()
        .unwrap()
        .iter()
        .map(|(k, (since, size))| UnusedVolume {
            volume: k.clone(),
            size_mb: *size,
            unused_since: *since,
            delete_at: since + retention,
        })
        .collect();
    v.sort_by(|a, b| a.volume.cmp(&b.volume));
    v
}

/// GET: unused volume data on this machine. DELETE ?volume=: delete one now.
pub async fn handle_unused(
    axum::extract::State(agent): axum::extract::State<Arc<Agent>>,
    method: axum::http::Method,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if method == axum::http::Method::DELETE {
        let Some(id) = q.get("volume").filter(|v| !v.is_empty() && !v.contains('/') && !v.contains("..") && !v.starts_with('.')) else {
            return (axum::http::StatusCode::BAD_REQUEST, "volume= required").into_response();
        };
        if in_use(&agent.snapshot(), agent.me.machine_id, id) {
            return (axum::http::StatusCode::CONFLICT, format!("{id} is in use")).into_response();
        }
        let dir = volumes_dir(&agent).join(id);
        if dir.is_dir() {
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }
        agent.vols.unused.lock().unwrap().remove(id);
        save_unused(&agent);
        agent.event("info", format!("deleted unused volume data {id}"));
        return axum::Json(true).into_response();
    }
    // Refresh first so the list is current.
    let _ = scan_unused(&agent).await;
    axum::Json(unused_list(&agent)).into_response()
}

// ---------------------------------------------------------------------------
// Daily snapshots: point-in-time copies of each volume, kept on the machine
// holding the live copy. Unchanged files are hard links to the previous
// snapshot, so a week of snapshots costs little more than one copy.

fn snapshots_dir(agent: &Agent) -> PathBuf {
    agent.data.join("snapshots")
}

/// Snapshot names (newest last) for a volume on this machine.
fn list_snapshots(agent: &Agent, id: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(snapshots_dir(agent).join(id))
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|n| !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Keep only the newest `keep` snapshots of every volume.
pub fn trim_snapshots(agent: &Agent, keep: usize) {
    let Ok(rd) = std::fs::read_dir(snapshots_dir(agent)) else { return };
    for e in rd.flatten() {
        let id = e.file_name().to_string_lossy().to_string();
        let snaps = list_snapshots(agent, &id);
        if snaps.len() > keep {
            for old in &snaps[..snaps.len() - keep] {
                let _ = std::fs::remove_dir_all(snapshots_dir(agent).join(&id).join(old));
            }
        }
    }
}

/// Take a snapshot of one volume now (runs the app's pre_sync hook first).
pub async fn take_snapshot(agent: &Agent, vol: &crate::state::Volume) -> Result<String> {
    let s = agent.snapshot();
    if let Some(ctr) = agent.rt.running_container(&vol.app) {
        let pre = s
            .apps
            .get(&vol.app)
            .and_then(|a| a.config())
            .and_then(|c| c.volumes.iter().find(|v| v.name == vol.name))
            .and_then(|v| v.pre_sync.clone());
        if let Some(pre) = pre {
            let _ = cmd("docker", &["exec", &ctr, "sh", "-c", &pre]).await;
        }
    }
    let dir = snapshots_dir(agent).join(&vol.id);
    std::fs::create_dir_all(&dir)?;
    let name = crate::cli::backup::stamp(now());
    let prev = list_snapshots(agent, &vol.id).into_iter().last();
    let src = format!("{}/", volumes_dir(agent).join(&vol.id).display());
    let tmp = dir.join(format!(".{name}"));
    let mut args = vec!["-a".to_string(), "--delete".into()];
    if let Some(p) = &prev {
        if p != &name {
            args.push(format!("--link-dest={}", dir.join(p).display()));
        }
    }
    args.push(src);
    args.push(format!("{}/", tmp.display()));
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    cmd("rsync", &refs).await?;
    let final_dir = dir.join(&name);
    let _ = std::fs::remove_dir_all(&final_dir);
    std::fs::rename(&tmp, &final_dir)?;
    let keep = s.settings.volume_snapshots.max(1) as usize;
    let snaps = list_snapshots(agent, &vol.id);
    if snaps.len() > keep {
        for old in &snaps[..snaps.len() - keep] {
            let _ = std::fs::remove_dir_all(dir.join(old));
        }
    }
    info!("snapshot {name} of volume {}", vol.id);
    Ok(name)
}

/// Daily snapshot of every volume whose live copy is here.
async fn snapshot_due(agent: &Arc<Agent>) -> Result<()> {
    let s = agent.snapshot();
    if s.settings.volume_snapshots == 0 {
        return Ok(());
    }
    for vol in s.volumes.values().filter(|v| v.primary == agent.me.machine_id && v.moving_to.is_none()) {
        let newest = std::fs::read_dir(snapshots_dir(agent).join(&vol.id))
            .ok()
            .and_then(|rd| rd.flatten().filter_map(|e| e.metadata().ok()?.modified().ok()).max());
        let due = newest.map(|t| t.elapsed().unwrap_or_default() > Duration::from_secs(86400 - 600)).unwrap_or(true);
        if due {
            take_snapshot(agent, vol).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotInfo {
    pub name: String,
    /// Space this snapshot adds on top of the previous ones.
    pub size_mb: u64,
}

/// GET ?volume= lists snapshots; POST ?volume=&action=take|restore[&snapshot=]
pub async fn handle_snapshots(
    axum::extract::State(agent): axum::extract::State<Arc<Agent>>,
    method: axum::http::Method,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let bad = |m: &str| (StatusCode::BAD_REQUEST, axum::Json(crate::api_types::ApiErrorBody { error: m.into() })).into_response();
    let Some(id) = q.get("volume").filter(|v| !v.is_empty() && !v.contains('/') && !v.contains("..")).cloned() else {
        return bad("volume= required");
    };
    if method == axum::http::Method::GET {
        let snaps = list_snapshots(&agent, &id);
        // `du` counts hard-linked files once, so each line is that snapshot's own cost.
        let dir = snapshots_dir(&agent).join(&id);
        let mut sizes: HashMap<String, u64> = HashMap::new();
        if !snaps.is_empty() {
            let mut args = vec!["-sm".to_string()];
            args.extend(snaps.iter().map(|n| dir.join(n).display().to_string()));
            let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            if let Ok(out) = cmd("du", &refs).await {
                for line in out.lines() {
                    let mut it = line.split_whitespace();
                    if let (Some(n), Some(p)) = (it.next(), it.next()) {
                        let name = p.rsplit('/').next().unwrap_or("").to_string();
                        sizes.insert(name, n.parse().unwrap_or(0));
                    }
                }
            }
        }
        let list: Vec<SnapshotInfo> = snaps
            .into_iter()
            .map(|n| SnapshotInfo { size_mb: sizes.get(&n).copied().unwrap_or(0), name: n })
            .collect();
        return axum::Json(list).into_response();
    }
    let s = agent.snapshot();
    let Some(vol) = s.volumes.get(&id).cloned() else { return bad("unknown volume") };
    match q.get("action").map(|a| a.as_str()) {
        Some("take") => match take_snapshot(&agent, &vol).await {
            Ok(name) => axum::Json(serde_json::json!({ "snapshot": name })).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
        },
        Some("restore") => {
            let Some(snap) = q.get("snapshot").filter(|n| list_snapshots(&agent, &id).contains(n)).cloned() else {
                return bad("unknown snapshot");
            };
            if agent.rt.running_container(&vol.app).is_some() {
                return (StatusCode::CONFLICT, format!("{} is running here; scale it to 0 first", vol.app)).into_response();
            }
            let src = format!("{}/", snapshots_dir(&agent).join(&id).join(&snap).display());
            let dst = format!("{}/", volumes_dir(&agent).join(&id).display());
            let _ = std::fs::create_dir_all(volumes_dir(&agent).join(&id));
            match cmd("rsync", &["-a", "--delete", &src, &dst]).await {
                Ok(_) => {
                    agent.vols.kick();
                    agent.event("info", format!("volume {id} rolled back to snapshot {snap}"));
                    axum::Json(true).into_response()
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
            }
        }
        _ => bad("action must be take or restore"),
    }
}
