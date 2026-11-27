//! WireGuard mesh: every machine gets an overlay IP (10.77.x.y) and a direct
//! encrypted tunnel to every other machine. All cluster traffic (state
//! replication, image pulls, volume sync, proxying to instances) uses it.
//!
//! Each app also gets a virtual IP (10.78.x.y) bound on every machine; the
//! local proxy listens there so `<app>.internal` works from any container.

use super::{cmd, set_private, Agent};
use crate::util::{OVERLAY_PREFIX, WG_PORT};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

pub const WG_IFACE: &str = "latrix0";
pub const VIP_IFACE: &str = "latrix-vip";

pub fn overlay_ip(id: u32) -> String {
    let n = id.saturating_sub(1);
    format!("{OVERLAY_PREFIX}.{}.{}", (n / 254) % 255, n % 254 + 1)
}

/// Returns (private key, public key), generating the key on first use.
pub async fn keypair(data: &Path) -> Result<(String, String)> {
    std::fs::create_dir_all(data)?;
    let path = data.join("wg.key");
    if !path.exists() {
        let key = cmd("wg", &["genkey"]).await.context("generating a WireGuard key (is wireguard-tools installed?)")?;
        std::fs::write(&path, key.trim())?;
        set_private(&path);
    }
    let private = std::fs::read_to_string(&path)?.trim().to_string();
    let mut child = tokio::process::Command::new("wg")
        .arg("pubkey")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(private.as_bytes()).await?;
    let out = child.wait_with_output().await?;
    Ok((private, String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

pub async fn sync(agent: &Arc<Agent>) -> Result<()> {
    let s = agent.snapshot();
    let (private, _) = keypair(&agent.data).await?;
    if cmd("ip", &["link", "show", WG_IFACE]).await.is_err() {
        cmd("ip", &["link", "add", WG_IFACE, "type", "wireguard"]).await?;
        info!("created WireGuard interface {WG_IFACE}");
    }
    let mut conf = format!("[Interface]\nPrivateKey = {private}\nListenPort = {WG_PORT}\n");
    for m in s.machines.values() {
        if m.id == agent.me.machine_id || m.wg_pubkey.is_empty() {
            continue;
        }
        let endpoint = if m.public_ip.contains(':') {
            format!("[{}]:{WG_PORT}", m.public_ip)
        } else {
            format!("{}:{WG_PORT}", m.public_ip)
        };
        conf.push_str(&format!(
            "\n[Peer]\n# {}\nPublicKey = {}\nEndpoint = {endpoint}\nAllowedIPs = {}/32\nPersistentKeepalive = 25\n",
            m.name, m.wg_pubkey, m.overlay_ip
        ));
    }
    let path = agent.data.join("wg.conf");
    std::fs::write(&path, conf)?;
    set_private(&path);
    cmd("wg", &["syncconf", WG_IFACE, &path.display().to_string()]).await?;
    let addrs = cmd("ip", &["-4", "-o", "addr", "show", "dev", WG_IFACE]).await.unwrap_or_default();
    if !addrs.contains(&format!("inet {}/", agent.me.overlay_ip)) {
        cmd("ip", &["addr", "add", &format!("{}/16", agent.me.overlay_ip), "dev", WG_IFACE]).await?;
    }
    cmd("ip", &["link", "set", WG_IFACE, "up"]).await?;

    harden(agent).await;

    // App virtual IPs, on a dummy interface (or loopback on kernels without
    // the dummy module).
    let mut iface = VIP_IFACE;
    if cmd("ip", &["link", "show", VIP_IFACE]).await.is_err()
        && cmd("ip", &["link", "add", VIP_IFACE, "type", "dummy"]).await.is_err()
    {
        iface = "lo";
    }
    let _ = cmd("ip", &["link", "set", iface, "up"]).await;
    let want: HashSet<String> = s.apps.values().map(|a| a.vip.clone()).collect();
    let out = cmd("ip", &["-4", "-o", "addr", "show", "dev", iface]).await.unwrap_or_default();
    let have: HashSet<String> = out
        .split_whitespace()
        .filter_map(|t| t.strip_suffix("/32"))
        .filter(|t| t.starts_with(crate::util::VIP_PREFIX))
        .map(|t| t.to_string())
        .collect();
    for v in want.difference(&have) {
        if let Err(e) = cmd("ip", &["addr", "add", &format!("{v}/32"), "dev", iface]).await {
            warn!("could not add VIP {v}: {e}");
        }
    }
    for v in have.difference(&want) {
        let _ = cmd("ip", &["addr", "del", &format!("{v}/32"), "dev", iface]).await;
    }
    Ok(())
}

/// Containers must not reach the mesh's internal services (agent API, image
/// registry, volume sync) — only DNS and app VIPs. Best effort: skipped when
/// iptables isn't available.
async fn harden(agent: &Agent) {
    let me = format!("{}/32", agent.me.overlay_ip);
    let ports = format!("{},{},{}", crate::util::API_PORT, crate::util::REGISTRY_PORT, crate::util::RSYNC_PORT);
    let rules: Vec<(&str, Vec<&str>)> = vec![
        // Local: only the host itself (lo) and other machines (latrix0) may connect.
        ("INPUT", vec!["-d", &me, "-p", "tcp", "-m", "multiport", "--dports", &ports, "!", "-i", "lo", "-j", "LATRIX-GUARD"]),
        // Forwarded: containers may not talk to other machines' mesh IPs at all.
        // (NEW only: replies to connections other machines open to local
        // containers must still flow.)
        ("DOCKER-USER", vec!["-d", "10.77.0.0/16", "!", "-i", WG_IFACE, "-m", "conntrack", "--ctstate", "NEW", "-j", "REJECT"]),
    ];
    if cmd("iptables", &["-L", "LATRIX-GUARD", "-n"]).await.is_err() {
        if cmd("iptables", &["-N", "LATRIX-GUARD"]).await.is_err() {
            return;
        }
        let _ = cmd("iptables", &["-A", "LATRIX-GUARD", "-i", WG_IFACE, "-j", "RETURN"]).await;
        let _ = cmd("iptables", &["-A", "LATRIX-GUARD", "-j", "REJECT"]).await;
    }
    for (chain, rule) in rules {
        let mut check = vec!["-C", chain];
        check.extend(rule.iter());
        if cmd("iptables", &check).await.is_ok() {
            continue;
        }
        let mut insert = vec!["-I", chain];
        insert.extend(rule.iter());
        if let Err(e) = cmd("iptables", &insert).await {
            tracing::debug!("firewall rule on {chain} not applied: {e}");
        }
    }
}

pub async fn sync_loop(agent: Arc<Agent>) {
    let mut rx = agent.changed.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(20));
    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = rx.changed() => {},
        }
        if let Err(e) = sync(&agent).await {
            warn!("mesh sync: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn overlay_ips() {
        assert_eq!(super::overlay_ip(1), "10.77.0.1");
        assert_eq!(super::overlay_ip(254), "10.77.0.254");
        assert_eq!(super::overlay_ip(255), "10.77.1.1");
    }
}
