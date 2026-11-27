//! Managed swap.
//!
//! Memory-heavy services can push a machine into OOM kills long before its
//! disk is full. latrix keeps a swap file on every machine so memory pressure
//! spills into swap instead of killing containers. The size is
//! `settings.swap`: "auto" (half of RAM, clamped to 1–8 GB), "off", or an
//! explicit size like "2GB". `settings.swappiness` sets vm.swappiness while
//! latrix manages swap.
//!
//! Only latrix's own swap file is managed: swap set up by the machine's owner
//! (a swap partition, zram, ...) is respected and left alone.

use super::{cmd_timeout, Agent};
use crate::util;
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// The one file latrix creates and manages.
pub const SWAP_FILE: &str = "/etc/latrix.swap";
const SYSCTL_FILE: &str = "/etc/sysctl.d/90-latrix-swap.conf";
/// Marks the fstab line and the sysctl drop-in as ours.
const MARKER: &str = "latrix-swap";
const FSTAB: &str = "/etc/fstab";

/// What swap size (MB) a `settings.swap` value asks for on a machine with
/// `mem_mb` of RAM: `None` = no swap, `Some` = the size of latrix's swap file.
pub fn desired_mb(setting: &str, mem_mb: u64) -> Result<Option<u64>> {
    match setting.trim().to_ascii_lowercase().as_str() {
        "" | "off" | "none" | "no" | "false" | "0" => Ok(None),
        "auto" => Ok(Some((mem_mb / 2).clamp(1024, 8192))),
        _ => {
            let mb = util::parse_size_mb(setting).with_context(|| {
                format!(
                    "invalid swap size '{setting}' (use \"auto\", \"off\" or a size like \"2GB\")"
                )
            })?;
            if mb < 64 {
                bail!("swap size must be at least 64MB");
            }
            Ok(Some(mb))
        }
    }
}

/// Swap currently active: our file's size in MB (if any) and whether some
/// other (foreign) swap is active. Read from /proc/swaps: sizes are in KB.
fn active_swap() -> (Option<u64>, bool) {
    let text = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    let mut managed = None;
    let mut foreign = false;
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let Some(name) = cols.next() else { continue };
        let kb: u64 = cols.nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        if name == SWAP_FILE {
            managed = Some(kb / 1024);
        } else {
            foreign = true;
        }
    }
    (managed, foreign)
}

fn mem_total_mb() -> u64 {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    text.lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

/// Swap usage in MB (total, used). (0, 0) when there is no swap.
pub fn swap_used_mb() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let get = |k: &str| {
        text.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            / 1024
    };
    let total = get("SwapTotal:");
    (total, total.saturating_sub(get("SwapFree:")))
}

async fn set_swappiness(value: u32) -> Result<()> {
    let want = format!("vm.swappiness={value}\n");
    let current = std::fs::read_to_string(SYSCTL_FILE).unwrap_or_default();
    if current != want {
        util::write_atomic(Path::new(SYSCTL_FILE), want.as_bytes())
            .with_context(|| format!("writing {SYSCTL_FILE}"))?;
    }
    // Apply now as well; the drop-in covers future boots.
    let _ = cmd_timeout(
        "sysctl",
        &["-w", &format!("vm.swappiness={value}")],
        Duration::from_secs(5),
    )
    .await;
    Ok(())
}

/// Keep exactly one marked fstab line for our swap file (or none when off).
fn sync_fstab(enable: bool) -> Result<()> {
    let current = std::fs::read_to_string(FSTAB).unwrap_or_default();
    let mut out: Vec<&str> = current
        .lines()
        .filter(|l| !l.contains(MARKER) && !l.contains(SWAP_FILE))
        .collect();
    if enable {
        out.push("# managed by latrix latrix-swap");
        out.push("/etc/latrix.swap none swap sw 0 0");
    }
    let mut text = out.join("\n");
    text.push('\n');
    if text != current {
        util::write_atomic(Path::new(FSTAB), text.as_bytes())
            .with_context(|| format!("writing {FSTAB}"))?;
    }
    Ok(())
}

/// Make the machine match `settings.swap` and `settings.swappiness`.
/// Idempotent: does nothing when everything is already in place.
pub async fn ensure(swap: &str, swappiness: u32) -> Result<()> {
    let (managed, foreign) = active_swap();
    let want = desired_mb(swap, mem_total_mb())?;

    let Some(want_mb) = want else {
        // Off: remove what we manage, leave anything else alone.
        if managed.is_some() {
            info!("swap: disabling latrix swap file");
            cmd_timeout("swapoff", &[SWAP_FILE], Duration::from_secs(120))
                .await
                .context("swapoff")?;
        }
        if Path::new(SWAP_FILE).exists() {
            std::fs::remove_file(SWAP_FILE).with_context(|| format!("removing {SWAP_FILE}"))?;
        }
        sync_fstab(false)?;
        if Path::new(SYSCTL_FILE).exists() {
            std::fs::remove_file(SYSCTL_FILE).ok();
        }
        return Ok(());
    };

    // Never fight swap the machine's owner set up.
    if foreign && managed.is_none() {
        info!("swap: machine already has swap of its own; leaving it alone");
        return Ok(());
    }

    set_swappiness(swappiness).await?;

    if managed != Some(want_mb) {
        if managed.is_some() {
            info!("swap: resizing latrix swap file to {want_mb}MB");
            cmd_timeout("swapoff", &[SWAP_FILE], Duration::from_secs(120))
                .await
                .context("swapoff (swap is in use; try again later)")?;
        } else {
            info!("swap: creating a {want_mb}MB swap file");
        }
        if Path::new(SWAP_FILE).exists() {
            std::fs::remove_file(SWAP_FILE).ok();
        }
        // fallocate is instant and keeps the file unfragmented; dd where it
        // is not supported (some filesystems).
        let size = format!("{want_mb}M");
        if cmd_timeout(
            "fallocate",
            &["-l", &size, SWAP_FILE],
            Duration::from_secs(60),
        )
        .await
        .is_err()
        {
            cmd_timeout(
                "dd",
                &[
                    "if=/dev/zero",
                    &format!("of={SWAP_FILE}"),
                    "bs=1M",
                    &format!("count={want_mb}"),
                ],
                Duration::from_secs(30 * 60),
            )
            .await
            .context("creating the swap file")?;
        }
        cmd_timeout("chmod", &["600", SWAP_FILE], Duration::from_secs(5)).await?;
        cmd_timeout("mkswap", &[SWAP_FILE], Duration::from_secs(60))
            .await
            .context("mkswap")?;
        cmd_timeout("swapon", &[SWAP_FILE], Duration::from_secs(60))
            .await
            .context("swapon")?;
    }
    sync_fstab(true)?;
    Ok(())
}

pub async fn run(agent: Arc<Agent>) {
    let mut last_warn: Option<Instant> = None;
    tokio::time::sleep(Duration::from_secs(45)).await;
    loop {
        let s = agent.snapshot();
        let (swap, swappiness) = (s.settings.swap.clone(), s.settings.swappiness);
        drop(s);
        if let Err(e) = ensure(&swap, swappiness).await {
            warn!("swap: could not apply '{swap}': {e:#}");
        }
        // Say something before machines grind to a halt on a full swap file.
        let (total, used) = swap_used_mb();
        if total > 0
            && used * 100 >= total * 95
            && last_warn
                .map(|t| t.elapsed() > Duration::from_secs(3600))
                .unwrap_or(true)
        {
            last_warn = Some(Instant::now());
            agent.event(
                "warn",
                format!(
                    "swap is {:.0}% full ({} of {}MB); this machine needs more memory (or a bigger swap setting)",
                    used as f64 / total as f64 * 100.0,
                    used,
                    total
                ),
            );
        }
        tokio::time::sleep(Duration::from_secs(15 * 60)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_values() {
        for v in ["", "off", "OFF", "none", "no", "false", "0", "  off  "] {
            assert_eq!(desired_mb(v, 8192).unwrap(), None, "{v}");
        }
    }

    #[test]
    fn auto_scales_with_ram() {
        assert_eq!(desired_mb("auto", 512).unwrap(), Some(1024)); // floor
        assert_eq!(desired_mb("auto", 4096).unwrap(), Some(2048)); // half of RAM
        assert_eq!(desired_mb("auto", 65536).unwrap(), Some(8192)); // cap
    }

    #[test]
    fn explicit_sizes() {
        assert_eq!(desired_mb("2GB", 4096).unwrap(), Some(2048));
        assert_eq!(desired_mb("512MB", 4096).unwrap(), Some(512));
        assert!(desired_mb("32MB", 4096).is_err()); // too small
        assert!(desired_mb("banana", 4096).is_err()); // not a size
    }
}
