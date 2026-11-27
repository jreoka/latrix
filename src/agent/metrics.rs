//! Machine metrics from /proc (with graceful fallbacks on other systems).

use super::Agent;
use crate::state::Metrics;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
pub struct Sampler {
    latest: Mutex<Metrics>,
    prev_cpu: Mutex<Option<(u64, u64)>>,
}

impl Sampler {
    pub fn latest(&self) -> Metrics {
        self.latest.lock().unwrap().clone()
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Facts {
    pub os: String,
    pub arch: String,
    pub cpus: f64,
    pub memory_mb: u64,
}

pub fn os_name() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

fn cpus() -> f64 {
    std::thread::available_parallelism().map(|n| n.get() as f64).unwrap_or(1.0)
}

fn meminfo() -> (u64, u64) {
    let text = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let get = |k: &str| {
        text.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let total = get("MemTotal:") / 1024;
    let avail = get("MemAvailable:") / 1024;
    (total, total.saturating_sub(avail))
}

pub async fn local_facts() -> Facts {
    Facts {
        os: os_name(),
        arch: std::env::consts::ARCH.to_string(),
        cpus: cpus(),
        memory_mb: meminfo().0,
    }
}

fn cpu_times() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?;
    let vals: Vec<u64> = line.split_whitespace().skip(1).filter_map(|v| v.parse().ok()).collect();
    if vals.len() < 4 {
        return None;
    }
    let idle = vals[3] + vals.get(4).copied().unwrap_or(0);
    Some((vals.iter().take(8).sum(), idle))
}

async fn disk(path: &std::path::Path) -> (f64, f64) {
    let p = if path.exists() { path.display().to_string() } else { "/".into() };
    let Ok(out) = super::cmd("df", &["-Pk", &p]).await else { return (0.0, 0.0) };
    let Some(line) = out.lines().nth(1) else { return (0.0, 0.0) };
    let cols: Vec<&str> = line.split_whitespace().collect();
    let kb = |i: usize| cols.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    (kb(1) / 1048576.0, kb(2) / 1048576.0)
}

pub async fn run(agent: Arc<Agent>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tick.tick().await;
        let (total, used) = meminfo();
        let cpu_pct = match cpu_times() {
            Some((t, i)) => {
                let mut prev = agent.sampler.prev_cpu.lock().unwrap();
                let pct = match *prev {
                    Some((pt, pi)) if t > pt => 100.0 * (1.0 - (i.saturating_sub(pi)) as f64 / (t - pt) as f64),
                    _ => 0.0,
                };
                *prev = Some((t, i));
                pct.clamp(0.0, 100.0)
            }
            None => 0.0,
        };
        let load1 = std::fs::read_to_string("/proc/loadavg")
            .ok()
            .and_then(|t| t.split_whitespace().next().and_then(|v| v.parse().ok()))
            .unwrap_or(0.0);
        let uptime_secs = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|t| t.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()))
            .unwrap_or(0.0) as u64;
        let (dt, du) = disk(&agent.data).await;
        *agent.sampler.latest.lock().unwrap() = Metrics {
            cpus: cpus(),
            cpu_pct,
            mem_total_mb: total,
            mem_used_mb: used,
            disk_total_gb: dt,
            disk_used_gb: du,
            load1,
            uptime_secs,
        };
    }
}
