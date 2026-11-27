//! Automatic OS maintenance.
//!
//! Every machine checks for package updates periodically and reports them.
//! The leader picks one machine at a time (inside the update window), drains
//! it — moving every instance elsewhere first — and flips it to
//! `maintenance`. The machine then installs updates, reboots if the OS says
//! so, and reports back; the leader returns it to service and the rebalancer
//! moves work back onto it.

use super::{cmd_timeout, Agent};
use crate::state::{MachineStatus, UpdateInfo};
use crate::util::{self, now};
use anyhow::{bail, Result};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{info, warn};

const DONE_FILE: &str = "maintenance-done";

fn pkg_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn sh_timeout(script: &str, timeout: Duration) -> Result<String> {
    cmd_timeout("sh", &["-c", script], timeout).await
}

pub fn read_done_marker(data: &Path) -> Option<String> {
    std::fs::read_to_string(data.join(DONE_FILE))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn package_manager() -> Option<&'static str> {
    for pm in ["apt-get", "dnf", "yum", "zypper", "pacman"] {
        if sh_timeout(&format!("command -v {pm}"), Duration::from_secs(10)).await.is_ok() {
            return Some(pm);
        }
    }
    None
}

pub async fn check_updates() -> Result<UpdateInfo> {
    let _guard = pkg_lock().lock().await;
    let Some(pm) = package_manager().await else { bail!("no supported package manager found") };
    let count_script = match pm {
        "apt-get" => "apt-get -o DPkg::Lock::Timeout=60 update -qq >/dev/null 2>&1 && apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep -c '^Inst ' || true",
        "dnf" => "dnf -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\\.[A-Za-z0-9_]+ ' || true",
        "yum" => "yum -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\\.[A-Za-z0-9_]+ ' || true",
        "zypper" => "zypper -n -q list-updates 2>/dev/null | grep -c '^v ' || true",
        // Never run `pacman -Sy` on the live DB (causes partial-upgrade breakage on Arch).
        _ => "if command -v checkupdates >/dev/null 2>&1; then checkupdates 2>/dev/null | wc -l; else tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT; cp -a /var/lib/pacman/local \"$tmp/\" 2>/dev/null && pacman --dbpath \"$tmp\" -Sy >/dev/null 2>&1 && pacman --dbpath \"$tmp\" -Qu 2>/dev/null | wc -l; fi",
    };
    let pending = sh_timeout(count_script, Duration::from_secs(300))
        .await?
        .trim()
        .parse()
        .unwrap_or(0);
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
        // Verify `dnf needs-restarting` plugin is installed so exit 1 ("unknown command")
        // doesn't trigger an infinite daily reboot loop.
        "dnf" => sh_timeout(
            "dnf needs-restarting --help >/dev/null 2>&1 && { dnf needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ]; }",
            Duration::from_secs(30),
        )
        .await
        .is_ok(),
        "yum" => sh_timeout(
            "command -v needs-restarting >/dev/null 2>&1 && { needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ]; }",
            Duration::from_secs(30),
        )
        .await
        .is_ok(),
        "zypper" => sh_timeout("zypper needs-rebooting >/dev/null 2>&1; [ $? -eq 102 ]", Duration::from_secs(30))
            .await
            .is_ok(),
        _ => false,
    };
    // Generic: only trigger when /lib/modules actually contains kernel dirs (not custom/cloud kernels without module dirs).
    by_tool
        || sh_timeout(
            "[ -d /lib/modules ] && [ -n \"$(ls -A /lib/modules 2>/dev/null)\" ] && [ ! -d \"/lib/modules/$(uname -r)\" ]",
            Duration::from_secs(10),
        )
        .await
        .is_ok()
}

async fn apply_updates() -> Result<()> {
    let _guard = pkg_lock().lock().await;
    let Some(pm) = package_manager().await else { bail!("no supported package manager found") };
    let script = match pm {
        "apt-get" => "export DEBIAN_FRONTEND=noninteractive UCF_FORCE_CONFOLD=1 NEEDRESTART_SUSPEND=1; apt-get -o DPkg::Lock::Timeout=120 update -q && apt-get -o DPkg::Lock::Timeout=120 -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold dist-upgrade && apt-get -o DPkg::Lock::Timeout=120 -y -q autoremove",
        "dnf" => "dnf -y upgrade --refresh",
        "yum" => "yum -y update",
        "zypper" => "zypper -n refresh && zypper -n update -y --auto-agree-with-licenses",
        _ => "pacman -Syu --noconfirm",
    };
    sh_timeout(script, Duration::from_secs(45 * 60)).await?;
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
                agent.event("warn", format!("OS maintenance failed: {e:#}"));
            }
            let pm = package_manager().await.unwrap_or("");
            let need_reboot = reboot_required(pm).await;
            if let Err(e) = util::write_atomic(&agent.data.join(DONE_FILE), task.id.as_bytes()) {
                agent.event("warn", format!("could not write maintenance done marker: {e:#}"));
                if need_reboot {
                    // Don't reboot without persisting the marker (would cause an infinite reboot loop).
                    *agent.maintenance_done.lock().unwrap() = Some(task.id.clone());
                    running.store(false, Ordering::SeqCst);
                    return;
                }
            }
            if need_reboot {
                // Do NOT set in-memory `maintenance_done` before rebooting, or the
                // leader will mark this node Ready and schedule live containers
                // onto it right before `systemctl reboot` fires! After reboot,
                // startup reads `DONE_FILE` via `read_done_marker`.
                info!("maintenance {}: rebooting", task.id);
                tokio::time::sleep(Duration::from_secs(3)).await;
                if sh_timeout("systemctl reboot || reboot", Duration::from_secs(30)).await.is_err() {
                    warn!("reboot command failed");
                    agent.event("warn", "reboot command failed after OS updates; returning machine to service");
                    *agent.maintenance_done.lock().unwrap() = Some(task.id.clone());
                }
            } else {
                *agent.maintenance_done.lock().unwrap() = Some(task.id.clone());
                if let Ok(info) = check_updates().await {
                    *agent.updates.lock().unwrap() = info;
                }
            }
            running.store(false, Ordering::SeqCst);
        });
    }
}
