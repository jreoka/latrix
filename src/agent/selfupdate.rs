//! Automatic upgrades of latrix itself.
//!
//! The leader checks GitHub for a newer release every 6 hours (or right away
//! when asked by `latrix self-update`) and upgrades machines one at a time,
//! itself last. Each machine downloads the build for its own CPU, checks that
//! it runs, swaps it in and restarts its agent; containers keep running.

use super::{cmd_timeout, Agent};
use crate::util::{self, API_PORT};
use anyhow::{bail, Context, Result};
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub const REPO: &str = "jreoka/latrix";
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;

fn install_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn manual_flag() -> &'static AtomicBool {
    static FLAG: OnceLock<AtomicBool> = OnceLock::new();
    FLAG.get_or_init(|| AtomicBool::new(false))
}

/// Validate a release version strictly (prevents URL path traversal like `0.1.0/../../other/repo`)
/// and return the canonical version string without a leading `v`.
pub fn validate_version(v: &str) -> Result<String> {
    let raw = v.trim();
    let s = raw.strip_prefix('v').unwrap_or(raw);
    if s.is_empty()
        || s.len() > 64
        || s.contains(['/', '\\', '?', '#', ' ', '\t', '\r', '\n'])
        || s.contains("..")
    {
        bail!("invalid version '{v}'");
    }
    let (core, pre) = match s.split_once('-') {
        Some((c, p)) => {
            if p.is_empty()
                || !p
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')
            {
                bail!("invalid prerelease in version '{v}'");
            }
            (c, Some(p))
        }
        None => (s, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) || p.parse::<u64>().is_err())
    {
        bail!("invalid semver '{v}'");
    }
    Ok(match pre {
        Some(p) => format!("{}-{p}", parts.join(".")),
        None => parts.join("."),
    })
}

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let canon = validate_version(v).ok()?;
    let core = canon.split('-').next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

fn cmp_prerelease(a: Option<&str>, b: Option<&str>) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater, // stable > prerelease
        (Some(_), None) => Ordering::Less,
        (Some(pa), Some(pb)) => {
            for (ia, ib) in pa.split('.').zip(pb.split('.')) {
                let ord = match (ia.parse::<u64>(), ib.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    _ => ia.cmp(ib),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            pa.split('.').count().cmp(&pb.split('.').count())
        }
    }
}

pub fn newer(a: &str, b: &str) -> bool {
    let (Ok(ca), Ok(cb)) = (validate_version(a), validate_version(b)) else {
        return false;
    };
    let (Some(va), Some(vb)) = (parse_version(&ca), parse_version(&cb)) else {
        return false;
    };
    let pa = ca.split_once('-').map(|(_, p)| p);
    let pb = cb.split_once('-').map(|(_, p)| p);
    va.cmp(&vb).then_with(|| cmp_prerelease(pa, pb)) == std::cmp::Ordering::Greater
}

/// The newest published version ("0.1.9"), via the releases/latest redirect
/// (no GitHub API rate limits).
pub async fn latest_version() -> Result<String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let r = client.get(format!("https://github.com/{REPO}/releases/latest")).send().await?;
    if !r.status().is_redirection() {
        bail!("unexpected HTTP {} checking latest release", r.status());
    }
    let loc = r
        .headers()
        .get("location")
        .and_then(|l| l.to_str().ok())
        .context("no release found")?
        .to_string();
    let path_only = loc.split(['?', '#']).next().unwrap_or(&loc);
    let tag = path_only.rsplit('/').next().unwrap_or("");
    validate_version(tag).with_context(|| format!("unexpected release tag '{tag}'"))
}

pub fn asset_url(version: &str, asset: &str) -> String {
    let clean_ver = validate_version(version).unwrap_or_else(|_| version.trim_start_matches('v').to_string());
    let base = std::env::var("LATRIX_RELEASE_BASE")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("https://github.com/{REPO}/releases/download/v{clean_ver}"));
    format!("{base}/{asset}")
}

fn validate_download_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid release URL '{url}'"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let local = matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
            if local {
                Ok(())
            } else {
                bail!("refusing insecure non-HTTPS release URL '{url}'");
            }
        }
        other => bail!("unsupported release URL scheme '{other}'"),
    }
}

/// Optional SHA-256 verification against a release `SHA256SUMS` file if published.
pub async fn fetch_expected_sha256(client: &reqwest::Client, version: &str, asset: &str) -> Result<Option<String>> {
    let sums_url = asset_url(version, "SHA256SUMS");
    if validate_download_url(&sums_url).is_err() {
        return Ok(None);
    }
    let resp = match client.get(&sums_url).timeout(Duration::from_secs(15)).send().await {
        Ok(r) if r.status().is_success() => r,
        _ => return Ok(None),
    };
    let text = resp.text().await.unwrap_or_default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(hash), Some(name)) = (parts.next(), parts.next()) {
            let clean = name.trim_start_matches('*').rsplit('/').next().unwrap_or(name);
            if clean == asset && hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(Some(hash.to_ascii_lowercase()));
            }
        }
    }
    Ok(None)
}

/// Download `version`, verify checksum (when published), check it runs, and swap it in at /usr/local/bin/latrix.
pub async fn install(version: &str) -> Result<()> {
    let _guard = install_lock().lock().await;
    let version = validate_version(version)?;
    let asset = format!("latrix-{}-unknown-linux-musl", std::env::consts::ARCH);
    let url = asset_url(&version, &asset);
    validate_download_url(&url)?;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("too many redirects");
            }
            if attempt.url().scheme() != "https"
                && !matches!(attempt.url().host_str(), Some("127.0.0.1" | "localhost" | "::1"))
            {
                return attempt.error("refusing HTTPS to HTTP downgrade redirect");
            }
            attempt.follow()
        }))
        .connect_timeout(Duration::from_secs(10))
        .build()?;

    let expected_sha = fetch_expected_sha256(&client, &version, &asset).await?;

    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(300))
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("downloading {url}"))?;

    let target = std::path::Path::new("/usr/local/bin/latrix");
    let tmp = target.with_file_name(format!(".latrix-new-{}", util::random_id(8)));
    struct RemoveOnDrop(std::path::PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let tmp_guard = RemoveOnDrop(tmp.clone());

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let c = chunk.with_context(|| format!("reading {url}"))?;
        total = total.saturating_add(c.len() as u64);
        if total > MAX_BINARY_BYTES {
            bail!("downloaded binary exceeds {} MB limit", MAX_BINARY_BYTES / (1024 * 1024));
        }
        hasher.update(&c);
        file.write_all(&c)?;
    }
    file.sync_all()?;
    drop(file);

    if let Some(expected) = expected_sha {
        let actual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if actual != expected {
            bail!("SHA-256 mismatch for {asset}: expected {expected}, got {actual}");
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    let out = cmd_timeout(&tmp.display().to_string(), &["--version"], Duration::from_secs(10)).await?;
    if !out.split_whitespace().any(|tok| tok.trim_start_matches('v') == version) {
        bail!("downloaded binary reports '{}', expected {version}", out.trim());
    }
    std::fs::rename(&tmp, target)?;
    std::mem::forget(tmp_guard);
    Ok(())
}

/// POST /v1/local/self-update {"version": "x.y.z"}: install, then restart.
pub async fn handle(
    axum::extract::State(agent): axum::extract::State<Arc<Agent>>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(v) = body["version"].as_str().and_then(|v| validate_version(v).ok()) else {
        return (axum::http::StatusCode::BAD_REQUEST, "valid semver version required").into_response();
    };
    if agent.dev {
        return (axum::http::StatusCode::BAD_REQUEST, "the local dev cluster runs your own binary").into_response();
    }
    if !newer(&v, util::VERSION) && v != util::VERSION {
        return (axum::http::StatusCode::BAD_REQUEST, format!("refusing downgrade from {} to {v}", util::VERSION)).into_response();
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
        if let Err(e) = cmd_timeout("systemctl", &["restart", "latrix"], Duration::from_secs(30)).await {
            warn!("restarting latrix after self-update failed: {e:#}");
        }
    });
}

async fn upgrade_machine(agent: &Arc<Agent>, id: u32, version: &str) -> Result<()> {
    let ip = agent.ip_of(id).context("unknown machine")?;
    let r = agent
        .http
        .post(super::host_port_url(&ip, API_PORT, "/v1/local/self-update"))
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
    // Fall back to the leader's own version if GitHub is temporarily unreachable
    // so lagging followers can still catch up.
    let latest = match latest_version().await {
        Ok(v) => v,
        Err(e) => {
            warn!("could not check latest latrix release ({e:#}); checking if followers match leader {}", util::VERSION);
            util::VERSION.to_string()
        }
    };
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
        if agent.rt.builds_running.load(Ordering::SeqCst) > 0 {
            info!("deferring leader self-update until active builds finish");
            return Ok(());
        }
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
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(300)) => {},
        _ = agent.upgrade_now.notified() => {},
    }
    loop {
        let manual = manual_flag().swap(false, Ordering::AcqRel);
        if agent.is_leader() && (manual || agent.snapshot().settings.auto_upgrade) {
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

/// POST /v1/upgrade-now (leader): check for a new release right away (even if auto_upgrade=false).
pub async fn handle_now(axum::extract::State(agent): axum::extract::State<Arc<Agent>>) -> axum::Json<bool> {
    manual_flag().store(true, Ordering::Release);
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
        // Prerelease ordering: final > prerelease, rc2 > rc1
        assert!(newer("0.2.0", "0.2.0-rc1"));
        assert!(!newer("0.2.0-rc1", "0.2.0"));
        assert!(newer("0.2.0-rc2", "0.2.0-rc1"));
        // Version path traversal validation
        assert!(validate_version("0.1.18").is_ok());
        assert!(validate_version("v1.2.3-rc1").is_ok());
        assert!(validate_version("../evil").is_err());
        assert!(validate_version("0.1.18/../../x").is_err());
        assert!(validate_version("").is_err());
    }
}
