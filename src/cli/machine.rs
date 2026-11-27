//! `latrix machine ...` — adding servers to the mesh and managing them.

use super::client::Client;
use super::profile::{CliConfig, ClusterProfile, MachineSsh};
use super::providers;
use super::ssh::Ssh;
use crate::agent::metrics::Facts;
use crate::api_types::*;
use crate::state::ProviderRef;
use crate::util::{self, print_table, shell_quote, validate_name};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BOOTSTRAP: &str = include_str!("bootstrap.sh");

#[derive(Serialize, Deserialize)]
pub struct InitFirst {
    pub cluster: String,
    pub token: String,
    pub name: String,
    pub public_ip: String,
    pub wg_pubkey: String,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub provider: Option<ProviderRef>,
    #[serde(default)]
    pub monthly_cost: Option<f64>,
}

#[derive(Serialize, Deserialize)]
pub struct WriteJoin {
    pub identity: crate::agent::NodeIdentity,
    pub state: crate::state::ClusterState,
}

pub struct AddOptions {
    pub target: String,
    pub name: Option<String>,
    pub port: u16,
    pub key: Option<String>,
    pub region: Option<String>,
    pub public_ip: Option<String>,
    pub agent_binary: Option<PathBuf>,
    pub provider: Option<ProviderRef>,
    pub monthly_cost: Option<f64>,
}

fn step(n: usize, total: usize, msg: &str) {
    println!("[{n}/{total}] {msg}");
}

fn normalize_arch(a: &str) -> &str {
    match a.trim() {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        other => other,
    }
}

fn default_name(host: &str) -> String {
    let base = if host.parse::<std::net::IpAddr>().is_ok() {
        format!("node-{}", host.replace(['.', ':'], "-"))
    } else {
        host.split('.').next().unwrap_or(host).to_string()
    };
    base.to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(40)
        .collect()
}

/// Copy (or download) a Linux build of latrix onto the machine.
pub async fn install_binary(ssh: &Ssh, explicit: Option<&Path>) -> Result<()> {
    let arch = ssh.run("uname -m").await?;
    let arch = normalize_arch(&arch).to_string();
    let explicit = explicit
        .map(|p| p.to_path_buf())
        .or_else(|| std::env::var("LATRIX_AGENT_BINARY").ok().map(PathBuf::from));
    let local = match explicit {
        Some(p) => Some(p),
        None if cfg!(target_os = "linux") && normalize_arch(std::env::consts::ARCH) == arch => {
            Some(std::env::current_exe()?)
        }
        None => None,
    };
    let tmp = format!("/tmp/latrix-upload-{}", util::random_id(6));
    match local {
        Some(path) => {
            ssh.upload(&path, &tmp).await.context("uploading latrix")?;
        }
        None => {
            let base = std::env::var("LATRIX_RELEASE_BASE")
                .unwrap_or_else(|_| format!("https://github.com/jreoka/latrix/releases/download/v{}", util::VERSION));
            let file = format!("latrix-{arch}-unknown-linux-musl");
            let url = format!("{base}/{file}");
            let latest = format!("https://github.com/jreoka/latrix/releases/latest/download/{file}");
            println!("      downloading {url}");
            let exact = ssh.run(&format!("curl -fsSL {} -o {tmp}", shell_quote(&url))).await;
            if exact.is_err() {
                println!("      not published for this version, trying the latest release");
                ssh.run(&format!("curl -fsSL {} -o {tmp}", shell_quote(&latest)))
                    .await
                    .with_context(|| {
                        format!(
                            "could not download a Linux build of latrix for {arch} (no GitHub release found).\n  \
                             Build one with `cargo build --release --target {arch}-unknown-linux-musl` on Linux/WSL \
                             and pass --agent-binary <path>"
                        )
                    })?;
            }
        }
    }
    ssh.run(&format!("install -m 0755 {tmp} /usr/local/bin/latrix && rm -f {tmp}"))
        .await?;
    let v = ssh.run("/usr/local/bin/latrix --version").await.map_err(|e| {
        anyhow!(
            "the uploaded latrix binary does not run on this machine ({e}).\n  \
             Use a static build: cargo build --release --target {arch}-unknown-linux-musl, then pass --agent-binary"
        )
    })?;
    println!("      installed {}", v.trim());
    Ok(())
}

async fn resolve_ip(host: &str) -> Result<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(host.to_string());
    }
    let mut addrs = tokio::net::lookup_host(format!("{host}:22")).await?;
    addrs
        .find(|a| a.is_ipv4())
        .map(|a| a.ip().to_string())
        .ok_or_else(|| anyhow!("could not resolve {host}"))
}

pub async fn add(cfg: &mut CliConfig, cluster: Option<&str>, opts: AddOptions) -> Result<()> {
    let ssh = Ssh::new(&opts.target, opts.port, opts.key.clone());
    let name = opts.name.clone().unwrap_or_else(|| default_name(ssh.host()));
    validate_name("machine", &name)?;

    // Which cluster? An existing one, or a brand new one.
    let cluster_name = match cluster {
        Some(c) => c.to_string(),
        None => cfg
            .cluster_name(None)
            .ok()
            .filter(|c| !cfg.clusters[c].local)
            .unwrap_or_else(|| "default".into()),
    };
    let mut profile = cfg.clusters.get(&cluster_name).cloned().unwrap_or_else(|| ClusterProfile {
        token: util::random_token(),
        local: false,
        machines: vec![],
        kubernetes: None,
    });
    if profile.kubernetes.is_some() {
        bail!("'{cluster_name}' is a Kubernetes target; its nodes are managed by Kubernetes (use --cluster to pick or create another cluster)");
    }
    if profile.local {
        bail!("'{cluster_name}' is the local dev cluster; use --cluster <name> to create a real one");
    }
    let first = profile.machines.iter().all(|m| m.name == name);
    let total = 5;

    step(1, total, &format!("connecting to {}", ssh.target));
    let os = ssh.run("cat /etc/os-release 2>/dev/null | grep ^PRETTY_NAME= | cut -d= -f2 | tr -d '\"'; uname -m").await?;
    println!("      {}", os.lines().collect::<Vec<_>>().join(" "));
    let client = if first {
        None
    } else {
        Some(Client::connect(&profile).await.context("the cluster must be reachable to add a machine")?)
    };

    step(2, total, "installing latrix");
    install_binary(&ssh, opts.agent_binary.as_deref()).await?;

    step(3, total, "setting up the machine (Docker, WireGuard, firewall, systemd)");
    ssh.stream_script(BOOTSTRAP, "      ").await?;

    step(4, total, &format!("joining cluster '{cluster_name}'"));
    let pubkey = ssh.run("/usr/local/bin/latrix agent keygen").await?.trim().to_string();
    let public_ip = match &opts.public_ip {
        Some(ip) => ip.clone(),
        None => match resolve_ip(ssh.host()).await {
            Ok(ip) => ip,
            // e.g. a Host alias from ~/.ssh/config: ask the machine itself.
            Err(_) => ssh
                .run("ip -4 route get 1.1.1.1 | sed -n 's/.* src \\([0-9.]*\\).*/\\1/p'")
                .await?
                .trim()
                .to_string(),
        },
    };
    if public_ip.is_empty() {
        bail!("could not determine the machine's public IP; pass --public-ip");
    }
    if first {
        let init = InitFirst {
            cluster: cluster_name.clone(),
            token: profile.token.clone(),
            name: name.clone(),
            public_ip: public_ip.clone(),
            wg_pubkey: pubkey,
            region: opts.region.clone(),
            provider: opts.provider.clone(),
            monthly_cost: opts.monthly_cost,
        };
        ssh.run_input("/usr/local/bin/latrix agent init-first", Some(&serde_json::to_vec(&init)?)).await?;
    } else {
        let facts: Facts = serde_json::from_str(&ssh.run("/usr/local/bin/latrix agent facts").await?)?;
        let join: JoinResponse = client
            .as_ref()
            .unwrap()
            .post(
                "/v1/machines/join",
                &JoinRequest {
                    name: name.clone(),
                    public_ip: public_ip.clone(),
                    wg_pubkey: pubkey,
                    os: facts.os,
                    arch: facts.arch,
                    cpus: facts.cpus,
                    memory_mb: facts.memory_mb,
                    region: opts.region.clone(),
                    provider: opts.provider.clone(),
                    monthly_cost: opts.monthly_cost,
                },
            )
            .await?;
        let wj = WriteJoin {
            identity: join.identity,
            state: join.state,
        };
        ssh.run_input("/usr/local/bin/latrix agent write-join", Some(&serde_json::to_vec(&wj)?)).await?;
    }
    ssh.run("systemctl enable latrix >/dev/null 2>&1; systemctl restart latrix").await?;

    profile.machines.retain(|m| m.name != name);
    profile.machines.push(MachineSsh {
        name: name.clone(),
        ssh: ssh.target.clone(),
        port: opts.port,
        key: opts.key.clone(),
    });
    cfg.clusters.insert(cluster_name.clone(), profile.clone());
    if cfg.current.is_none() || cfg.clusters.get(cfg.current.as_deref().unwrap_or("")).map(|c| c.local).unwrap_or(true) {
        cfg.current = Some(cluster_name.clone());
    }
    cfg.save()?;

    step(5, total, "waiting for the machine to come online");
    let start = Instant::now();
    let mut last_err = String::new();
    while start.elapsed() < Duration::from_secs(90) {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let res: Result<StatusView> = async {
            let c = Client::connect(&profile).await?;
            c.get("/v1/status").await
        }
        .await;
        match res {
            Ok(st) => {
                if let Some(mv) = st.machines.iter().find(|m| m.machine.name == name) {
                    if mv.alive {
                        println!(
                            "\n✓ {name} is part of cluster '{cluster_name}' ({} machine{}, overlay IP {})",
                            st.machines.len(),
                            if st.machines.len() == 1 { "" } else { "s" },
                            mv.machine.overlay_ip
                        );
                        if first {
                            println!("\nNext steps:\n  cd your-app && latrix launch   # create latrix.toml\n  latrix deploy                   # build & run it on the cluster\n  latrix dashboard                # open the web dashboard");
                        }
                        return Ok(());
                    }
                }
            }
            Err(e) => last_err = format!("{e:#}"),
        }
    }
    bail!(
        "{name} did not come online within 90s. Check `latrix machine ssh {name}` then `journalctl -u latrix -n 50`.{}",
        if last_err.is_empty() { String::new() } else { format!("\n  last error: {last_err}") }
    )
}

pub async fn list(client: &Client) -> Result<()> {
    let st: StatusView = client.get("/v1/status").await?;
    let rows = st
        .machines
        .iter()
        .map(|m| {
            let met = m.metrics.clone().unwrap_or_default();
            let status = if !m.alive {
                "DOWN".to_string()
            } else {
                m.machine.status.to_string()
            };
            let updates = match &m.updates {
                Some(u) if u.checked_at > 0 => {
                    let mut s = format!("{}", u.pending);
                    if u.reboot_required {
                        s.push_str(" +reboot");
                    }
                    s
                }
                _ => "-".into(),
            };
            vec![
                format!("{}{}", m.machine.name, if m.leader { " *" } else { "" }),
                status,
                m.machine.public_ip.clone(),
                m.machine.overlay_ip.clone(),
                format!("{:.0}%/{:.0}", met.cpu_pct, met.cpus),
                format!("{}/{}M", met.mem_used_mb, met.mem_total_mb),
                format!("{:.0}/{:.0}G", met.disk_used_gb, met.disk_total_gb),
                m.instances.to_string(),
                updates,
                m.machine
                    .monthly_cost
                    .map(|c| format!("{c:.2}"))
                    .unwrap_or_else(|| "-".into()),
                m.machine.os.clone(),
            ]
        })
        .collect();
    print_table(
        &["NAME", "STATUS", "PUBLIC IP", "MESH IP", "CPU", "MEM", "DISK", "INST", "UPDATES", "$/MO", "OS"],
        rows,
    );
    println!("\n* = leader");
    Ok(())
}

pub async fn action(client: &Client, name: &str, action: &str) -> Result<()> {
    let m: crate::state::Machine = client
        .post(
            &format!("/v1/machines/{name}/action"),
            &MachineAction { action: action.into() },
        )
        .await?;
    match action {
        "drain" => println!("{} is draining — instances move to other machines first, then it is cordoned.", m.name),
        "update" => println!("{} will drain, install OS updates (rebooting if needed), then rejoin automatically.", m.name),
        "cordon" => println!("{} is cordoned: keeps running what it has, gets nothing new.", m.name),
        _ => println!("{} is {}", m.name, m.status),
    }
    Ok(())
}

pub async fn wait_status(client: &Client, name: &str, want: &[&str], timeout: Duration) -> Result<()> {
    let start = Instant::now();
    let mut last = String::new();
    loop {
        let st: StatusView = client.get("/v1/status").await?;
        let Some(m) = st.machines.iter().find(|m| m.machine.name == name) else {
            bail!("machine '{name}' not found");
        };
        let s = m.machine.status.to_string();
        let line = format!("      {name}: {s}, {} instance(s) left", m.instances);
        if line != last {
            println!("{line}");
            last = line;
        }
        if want.contains(&s.as_str()) {
            return Ok(());
        }
        if start.elapsed() > timeout {
            bail!("timed out waiting for {name} (status {s})");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

pub async fn remove(cfg: &mut CliConfig, cluster: Option<&str>, name: &str, force: bool, destroy: bool) -> Result<()> {
    let (cname, profile) = cfg.profile(cluster)?;
    let client = Client::connect(&profile).await?;
    let st: StatusView = client.get("/v1/status").await?;
    let mv = st
        .machines
        .iter()
        .find(|m| m.machine.name == name)
        .ok_or_else(|| anyhow!("machine '{name}' not found"))?
        .clone();
    if !force && mv.instances > 0 && mv.alive {
        println!("==> draining {name}");
        if !matches!(mv.machine.status, crate::state::MachineStatus::Draining | crate::state::MachineStatus::Cordoned) {
            action(&client, name, "drain").await?;
        }
        wait_status(&client, name, &["cordoned"], Duration::from_secs(900)).await?;
    }
    drop(client);
    // Reconnect through a different machine if possible.
    let mut others = profile.clone();
    others.machines.retain(|m| m.name != name);
    let client = if others.machines.is_empty() {
        Client::connect(&profile).await?
    } else {
        Client::connect(&others).await?
    };
    let _: crate::state::Machine = client
        .delete(&format!("/v1/machines/{name}?force={}", force || !mv.alive || mv.instances == 0))
        .await?;
    println!("==> removed {name} from the cluster");
    if let Some(m) = profile.machines.iter().find(|m| m.name == name) {
        let ssh = Ssh::new(&m.ssh, m.port, m.key.clone());
        let cleanup = "systemctl disable --now latrix >/dev/null 2>&1; \
            ids=$(docker ps -aq --filter label=latrix.instance); [ -n \"$ids\" ] && docker rm -f $ids >/dev/null; \
            docker rm -f latrix-registry >/dev/null 2>&1; ip link del latrix0 2>/dev/null; ip link del latrix-vip 2>/dev/null; \
            rm -f /var/lib/latrix/node.json /var/lib/latrix/state.json; true";
        match ssh.run(cleanup).await {
            Ok(_) => println!("==> stopped the agent and containers on {name} (volume data left in /var/lib/latrix/volumes)"),
            Err(e) => println!("    (could not clean up {name} over ssh: {e})"),
        }
    }
    if destroy {
        match &mv.machine.provider {
            Some(p) => {
                let token = providers::token(cfg, &p.provider)?;
                providers::destroy(p, &token).await?;
                println!("==> destroyed {} server {}", p.provider, p.id);
            }
            None => println!("    --destroy: {name} was not created by latrix, so it was left running"),
        }
    }
    if let Some(p) = cfg.clusters.get_mut(&cname) {
        p.machines.retain(|m| m.name != name);
    }
    cfg.save()?;
    Ok(())
}

pub fn find_ssh(cfg: &CliConfig, cluster: Option<&str>, name: &str) -> Result<Ssh> {
    let (_, p) = cfg.profile(cluster)?;
    let m = p
        .machines
        .iter()
        .find(|m| m.name == name)
        .ok_or_else(|| anyhow!("no SSH details for machine '{name}' in your local config"))?;
    Ok(Ssh::new(&m.ssh, m.port, m.key.clone()))
}

/// Upload this latrix build to every machine (one at a time) and restart agents.
/// Containers keep running while agents restart.
pub async fn upgrade_agents(cfg: &CliConfig, cluster: Option<&str>, only: Option<&str>, binary: Option<&Path>) -> Result<()> {
    let (_, profile) = cfg.profile(cluster)?;
    if profile.local {
        bail!("the local cluster runs this binary directly; just restart `latrix dev`");
    }
    for m in profile.machines.iter().filter(|m| only.map(|o| o == m.name).unwrap_or(true)) {
        println!("==> {}", m.name);
        let ssh = Ssh::new(&m.ssh, m.port, m.key.clone());
        install_binary(&ssh, binary).await?;
        ssh.run("systemctl restart latrix").await?;
        let start = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let ok = async {
                let c = Client::connect(&profile).await?;
                let st: StatusView = c.get("/v1/status").await?;
                Ok::<bool, anyhow::Error>(
                    st.machines
                        .iter()
                        .any(|x| x.machine.name == m.name && x.alive && x.agent_version == util::VERSION),
                )
            }
            .await
            .unwrap_or(false);
            if ok {
                println!("    {} runs latrix {}", m.name, util::VERSION);
                break;
            }
            if start.elapsed() > Duration::from_secs(90) {
                bail!("{} did not come back after the upgrade", m.name);
            }
        }
    }
    Ok(())
}
