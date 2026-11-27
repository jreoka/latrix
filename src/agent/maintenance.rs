//! Automatic OS maintenance.
//!
//! Every machine checks for package updates periodically and reports them.
//! The leader picks one machine at a time (inside the update window), drains
//! it — moving every instance elsewhere first — and flips it to
//! `maintenance`. The machine then installs updates, reboots if the OS says
//! so, and reports back; the leader returns it to service and the rebalancer
//! moves work back onto it.

use super::{sh, Agent};
use crate::state::{MachineStatus, UpdateInfo};
use crate::util::now;
use anyhow::{bail, Result};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

const DONE_FILE: &str = "maintenance-done";

pub fn read_done_marker(data: &Path) -> Option<String> {
    std::fs::read_to_string(data.join(DONE_FILE))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn package_manager() -> Option<&'static str> {
    for pm in ["apt-get", "dnf", "yum", "zypper", "pacman"] {
        if sh(&format!("command -v {pm}")).await.is_ok() {
            return Some(pm);
        }
    }
    None
}

pub async fn check_updates() -> Result<UpdateInfo> {
    let Some(pm) = package_manager().await else { bail!("no supported package manager found") };
    let count_script = match pm {
        "apt-get" => "apt-get update -qq >/dev/null 2>&1; apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep -c '^Inst ' || true",
        "dnf" => "dnf -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\\.[A-Za-z0-9_]+ ' || true",
        "yum" => "yum -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\\.[A-Za-z0-9_]+ ' || true",
        "zypper" => "zypper -n -q list-updates 2>/dev/null | grep -c '^v ' || true",
        _ => "pacman -Sy >/dev/null 2>&1; pacman -Qu 2>/dev/null | wc -l",
    };
    let pending = sh(count_script).await.unwrap_or_default().trim().parse().unwrap_or(0);
    Ok(UpdateInfo {
        pending,
        reboot_required: reboot_required(pm).await,
        checked_at: now(),
        package_manager: pm.into(),
    })
}

pub async fn reboot_required(pm: &str) -> bool {
    if Path::new("/var/run/reboot-required").exists() || Path::new("/run/reboot-needed").exists() {
        return true;
    }
    let by_tool = match pm {
        "dnf" => sh("dnf needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ]").await.is_ok(),
        "yum" => sh("needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ]").await.is_ok(),
        "zypper" => sh("zypper needs-rebooting >/dev/null 2>&1; [ $? -eq 102 ]").await.is_ok(),
        _ => false,
    };
    // Generic: the running kernel's modules were removed by an upgrade.
    by_tool || sh("[ ! -d /lib/modules/$(uname -r) ] && [ -d /lib/modules ]").await.is_ok()
}

async fn apply_updates() -> Result<()> {
    let Some(pm) = package_manager().await else { bail!("no supported package manager found") };
    let script = match pm {
        "apt-get" => "export DEBIAN_FRONTEND=noninteractive; apt-get update -q && apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade && apt-get -y -q autoremove",
        "dnf" => "dnf -y upgrade --refresh",
        "yum" => "yum -y update",
        "zypper" => "zypper -n refresh && zypper -n update -y --auto-agree-with-licenses",
        _ => "pacman -Syu --noconfirm",
    };
    sh(script).await?;
    Ok(())
}

pub async fn run(agent: Arc<Agent>) {
    let running = Arc::new(AtomicBool::new(false));
    // Periodic update check.
    {
        let agent = agent.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(90)).await;
            loop {
                match check_updates().await {
                    Ok(info) => *agent.updates.lock().unwrap() = info,
                    Err(e) => warn!("update check failed: {e:#}"),
                }
                tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
            }
        });
    }
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        let s = agent.snapshot();
        let Some(m) = s.machines.get(&agent.me.machine_id) else { continue };
        let Some(task) = m.maintenance.clone() else { continue };
        if m.status != MachineStatus::Maintenance || task.kind != "updates" {
            continue;
        }
        if agent.maintenance_done.lock().unwrap().as_deref() == Some(task.id.as_str()) {
            continue;
        }
        if running.swap(true, Ordering::SeqCst) {
            continue;
        }
        let agent = agent.clone();
        let running = running.clone();
        tokio::spawn(async move {
            info!("maintenance {}: installing OS updates", task.id);
            if let Err(e) = apply_updates().await {
                warn!("maintenance {}: updates failed: {e:#}", task.id);
            }
            let _ = std::fs::write(agent.data.join(DONE_FILE), &task.id);
            *agent.maintenance_done.lock().unwrap() = Some(task.id.clone());
            let pm = package_manager().await.unwrap_or("");
            if reboot_required(pm).await {
                info!("maintenance {}: rebooting", task.id);
                tokio::time::sleep(Duration::from_secs(3)).await;
                if sh("systemctl reboot || reboot").await.is_err() {
                    warn!("reboot command failed");
                }
            } else if let Ok(info) = check_updates().await {
                *agent.updates.lock().unwrap() = info;
            }
            running.store(false, Ordering::SeqCst);
        });
    }
}
