//! Command implementations.

use super::client::{Client, Tunnel};
use super::profile::{CliConfig, ClusterProfile};
use super::*;
use crate::agent;
use crate::api_types::*;
use crate::util::{self, ago, human_duration, print_table};
use anyhow::{anyhow, bail, Context, Result};
use futures::StreamExt;
use std::io::{BufRead, Read, Write};
use std::path::Path;
use std::time::Duration;

fn read_stdin_json<T: serde::de::DeserializeOwned>() -> Result<T> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(serde_json::from_str(&s)?)
}

async fn connect(cfg: &CliConfig, cluster: Option<&str>) -> Result<(String, ClusterProfile, Client)> {
    let (name, p) = cfg.profile(cluster)?;
    let c = Client::connect(&p).await?;
    if !p.local {
        let _ = sync_machines(&name, &c).await;
    }
    Ok((name, p, c))
}

/// The autopilot adds and removes servers on its own; keep the local list of
/// machines (used to reach the cluster over SSH) in step with the cluster.
/// Returns the names of machines forgotten because the cluster no longer has them.
pub async fn sync_machines(cluster: &str, c: &Client) -> Result<Vec<String>> {
    let st: StatusView = c.get("/v1/status").await?;
    let mut cfg = CliConfig::load()?;
    let Some(p) = cfg.clusters.get_mut(cluster) else { return Ok(vec![]) };
    let names: Vec<String> = st.machines.iter().map(|m| m.machine.name.clone()).collect();
    let mut changed = false;
    let mut forgotten = vec![];
    // Only forget machines the cluster removed when we still know some others.
    if names.iter().any(|n| p.machines.iter().any(|m| &m.name == n)) {
        forgotten = p.machines.iter().filter(|m| !names.contains(&m.name)).map(|m| m.name.clone()).collect();
        p.machines.retain(|m| names.contains(&m.name));
        changed |= !forgotten.is_empty();
    }
    for m in &st.machines {
        if m.machine.provider.is_some() && !p.machines.iter().any(|x| x.name == m.machine.name) {
            p.machines.push(super::profile::MachineSsh {
                name: m.machine.name.clone(),
                ssh: format!("root@{}", m.machine.public_ip),
                port: 22,
                key: p.default_key.clone(),
            });
            changed = true;
        }
    }
    if changed {
        cfg.save()?;
    }
    Ok(forgotten)
}

pub struct CreateOptions {
    pub provider: Option<String>,
    pub size: Option<String>,
    pub region: Option<String>,
    pub min_memory: String,
    pub image: Option<String>,
    pub name: Option<String>,
    pub key: Option<String>,
    pub agent_binary: Option<std::path::PathBuf>,
}

/// Providers to use: the one asked for, or every provider with a token.
fn providers_with_tokens(cfg: &CliConfig, only: Option<&str>) -> Result<Vec<(String, String)>> {
    let names: Vec<&str> = match only {
        Some(p) => vec![providers::canonical(p)?],
        None => vec!["hetzner", "digitalocean"],
    };
    let found: Vec<(String, String)> = names
        .into_iter()
        .filter_map(|p| providers::token(cfg, p).ok().map(|t| (p.to_string(), t)))
        .collect();
    if found.is_empty() {
        bail!(
            "no cloud provider token yet. Add one:\n  latrix provider set hetzner <token>        (console.hetzner.cloud → Security → API tokens)\n  latrix provider set digitalocean <token>   (cloud.digitalocean.com → API)"
        );
    }
    Ok(found)
}

/// Buy a server and add it. Picks the cheapest offer that fits unless a
/// size/region was given; always the newest Ubuntu LTS unless --image.
pub async fn create_machine(cfg: &mut CliConfig, cl: Option<&str>, o: CreateOptions) -> Result<()> {
    let candidates = providers_with_tokens(cfg, o.provider.as_deref())?;
    let min_mb = util::parse_size_mb(&o.min_memory)?;
    // Servers run the same CPU type as the binary we install on them.
    let arch = providers::provider_arch(if cfg!(target_os = "linux") { std::env::consts::ARCH } else { "x86_64" });
    let mut offers = vec![];
    for (p, t) in &candidates {
        match providers::catalog(p, t).await {
            Ok(list) => offers.extend(list),
            Err(e) => println!("    ({p}: could not read prices: {e:#})"),
        }
    }
    let filtered: Vec<providers::Offer> = offers
        .into_iter()
        .filter(|x| o.size.as_ref().map(|s| &x.size == s).unwrap_or(true))
        .filter(|x| o.region.as_ref().map(|r| &x.location == r).unwrap_or(true))
        .collect();
    let min = if o.size.is_some() { 0 } else { min_mb };
    let offer = providers::cheapest(&filtered, min, 1.0, arch, &[], None)
        .or_else(|| providers::cheapest(&filtered, min, 1.0, if arch == "x86" { "arm" } else { "x86" }, &[], None))
        .cloned()
        .ok_or_else(|| anyhow!("no matching server type found (check --type / --region, or `latrix provider sizes <provider>`)"))?;
    let token = candidates.iter().find(|(p, _)| *p == offer.provider).map(|(_, t)| t.clone()).unwrap();
    let image = match o.image {
        Some(i) => i,
        None => providers::latest_ubuntu(&offer.provider, &token, &offer.size).await,
    };
    let name = o
        .name
        .unwrap_or_else(|| format!("{}-{}", offer.location.to_ascii_lowercase(), util::random_id(4)));
    util::validate_name("machine", &name)?;
    let (pubkey, key) = providers::ssh_key(o.key.as_deref())?;
    println!(
        "==> {} {} in {} ({} vCPU, {} GB RAM) — {:.2}/month{}",
        offer.provider,
        offer.size,
        offer.location,
        offer.cpus,
        offer.memory_mb / 1024,
        offer.price,
        if o.size.is_none() && o.region.is_none() { ", the cheapest that fits" } else { "" }
    );
    println!("==> creating server '{name}' with {image}");
    let created = providers::create(&offer.provider, &token, &name, &offer.size, &offer.location, &image, std::slice::from_ref(&pubkey)).await?;
    println!("==> server is up at {}", created.ip);
    let created_provider = created.provider.clone();
    let setup: Result<()> = async {
        let ssh = ssh::Ssh::new(&format!("root@{}", created.ip), 22, key.clone());
        ssh.forget_host_key(); // cloud IPs get reused
        print!("==> waiting for SSH");
        let start = std::time::Instant::now();
        loop {
            if ssh.run("true").await.is_ok() {
                println!();
                break;
            }
            if start.elapsed() > Duration::from_secs(240) {
                println!();
                bail!("SSH to {} never became available", created.ip);
            }
            print!(".");
            std::io::stdout().flush()?;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        machine::add(
            cfg,
            cl,
            machine::AddOptions {
                target: format!("root@{}", created.ip),
                name: Some(name),
                port: 22,
                key: key.clone(),
                region: Some(offer.location.clone()),
                public_ip: Some(created.ip.clone()),
                agent_binary: o.agent_binary,
                provider: Some(created.provider),
                monthly_cost: created.monthly_cost.or(Some(offer.price)),
            },
        )
        .await
    }
    .await;
    if let Err(e) = setup {
        eprintln!(
            "==> setup failed; deleting newly created server ({}:{}) so it doesn't keep billing...",
            created_provider.provider, created_provider.id
        );
        if let Err(de) = providers::destroy(&created_provider, &token).await {
            eprintln!(
                "    warning: could not delete {}:{} automatically: {de:#}",
                created_provider.provider, created_provider.id
            );
        }
        return Err(e);
    }
    // Remember the key for servers the autopilot adds later.
    let mut fresh = CliConfig::load()?;
    if let Ok(cname) = fresh.cluster_name(cl) {
        if let Some(p) = fresh.clusters.get_mut(&cname) {
            if p.default_key.is_none() {
                p.default_key = key;
                fresh.save()?;
            }
        }
    }
    *cfg = fresh;
    Ok(())
}

async fn autopilot_on(cfg: &CliConfig, cl: Option<&str>, budget: Option<f64>, min: Option<u32>, max: Option<u32>, only: &[String]) -> Result<()> {
    if let Some(b) = budget {
        if !b.is_finite() || b < 0.0 {
            bail!("--budget must be a finite non-negative number");
        }
    }
    if let (Some(lo), Some(hi)) = (min, max) {
        if lo > hi {
            bail!("--min-machines ({lo}) must be <= --max-machines ({hi})");
        }
    }
    let tokens: std::collections::BTreeMap<String, String> = if only.is_empty() {
        providers_with_tokens(cfg, None)?.into_iter().collect()
    } else {
        let mut m = std::collections::BTreeMap::new();
        for p in only {
            for (k, v) in providers_with_tokens(cfg, Some(p))? {
                m.insert(k, v);
            }
        }
        m
    };
    let (name, p, c) = connect(cfg, cl).await?;
    if p.kubernetes.is_some() || p.local {
        bail!("the autopilot manages latrix's own servers; '{name}' isn't one of those clusters");
    }
    // Your SSH key goes on new servers too, so this computer can always reach them.
    let (pubkey, key) = providers::ssh_key(p.default_key.as_deref())?;
    let v: AutopilotView = c
        .post(
            "/v1/autopilot",
            &AutopilotRequest {
                enabled: Some(true),
                budget,
                min_machines: min,
                max_machines: max,
                tokens: tokens.clone(),
                ssh_keys: vec![pubkey],
            },
        )
        .await?;
    let mut fresh = CliConfig::load()?;
    if let Some(prof) = fresh.clusters.get_mut(&name) {
        if prof.default_key.is_none() {
            prof.default_key = key;
            fresh.save()?;
        }
    }
    println!(
        "✓ autopilot on for '{name}' — budget {}, {}–{} machines, providers: {}",
        if v.budget > 0.0 { format!("{:.2}/month", v.budget) } else { "unlimited".into() },
        v.min_machines,
        v.max_machines,
        tokens.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    println!("  latrix now buys the cheapest server that fits when apps need room, removes ones it");
    println!("  doesn't need, replaces oversized ones, and reboots/replaces dead ones.");
    println!("  Machines you added yourself are never touched. See `latrix autopilot status`.");
    Ok(())
}

fn print_autopilot(v: &AutopilotView) {
    let c = &v.status.capacity;
    println!(
        "autopilot {} · budget {} · {}–{} machines",
        if v.enabled { "ON" } else { "off" },
        if v.budget > 0.0 { format!("{:.2}/month", v.budget) } else { "unlimited".into() },
        v.min_machines,
        v.max_machines
    );
    if c.machines > 0 || c.req_mem_mb > 0.0 {
        println!(
            "capacity: {} machine(s), apps want {:.1} of {:.1} GB and {:.1} of {:.1} CPUs ({:.0}% used), {:.2}/month",
            c.machines,
            c.req_mem_mb / 1024.0,
            c.cap_mem_mb / 1024.0,
            c.req_cpu,
            c.cap_cpu,
            if c.utilization.is_finite() { c.utilization * 100.0 } else { 100.0 },
            c.monthly_cost
        );
    }
    if !v.status.providers.is_empty() {
        println!("providers: {}", v.status.providers.join(", "));
    }
    if let Some(o) = &v.status.cheapest {
        println!("cheapest server now: {} {} in {} ({} GB) at {:.2}/month", o.provider, o.size, o.location, o.memory_mb / 1024, o.price);
    }
    if let Some(w) = &v.status.working_on {
        println!("working on: {w}");
    }
    if !v.status.last_decision.is_empty() {
        println!("last decision ({}): {}", ago(v.status.last_check), v.status.last_decision);
    }
}

fn parse_pairs(pairs: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            p.split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.to_string()))
                .ok_or_else(|| anyhow!("expected KEY=value, got '{p}'"))
        })
        .collect()
}

async fn app_health_timeout(c: &Client, app: &str) -> u64 {
    c.get::<AppView>(&format!("/v1/apps/{app}"))
        .await
        .ok()
        .and_then(|v| v.config.map(|cfg| cfg.deploy.health_timeout_secs()))
        .unwrap_or(120)
}

pub async fn run(cli: Cli) -> Result<()> {
    let cl = cli.cluster.as_deref().map(str::trim).filter(|s| !s.is_empty());
    match cli.cmd {
        Cmd::Agent(a) => return agent_cmd(a).await,
        Cmd::Launch { name, image, port, force } => return deploy::launch(name, image, port, force),
        Cmd::Dev { data } => return dev(data).await,
        Cmd::Compose(ComposeCmd::Convert { file, write }) => return compose_convert(&file, write),
        Cmd::Cluster(ClusterCmd::Connect { target, port, key }) => return cluster_connect(&target, port, key).await,
        Cmd::Cluster(c) => return cluster_cmd(c),
        Cmd::Provider(p) => return provider_cmd(p, cl).await,
        Cmd::K8s(k) => return k8s::k8s_cmd(cl, k).await,
        Cmd::Rexctl { action: Some(RexctlCmd::Inspect { file, skip_verify }) } => {
            return rexctl::inspect(&file, skip_verify);
        }
        Cmd::SelfUpdate => return update::self_update(&CliConfig::load()?, cl).await,
        _ => {}
    }
    update::notice().await;
    let mut cfg = CliConfig::load()?;
    if let Ok((name, p)) = cfg.profile(cl) {
        if let Some(t) = p.kubernetes {
            return Box::pin(k8s::dispatch(&cfg, &name, t, cli.cmd)).await;
        }
    }
    match cli.cmd {
        Cmd::Deploy(args) => Box::pin(deploy_cmd(&cfg, cl, args)).await,
        Cmd::Status => Box::pin(status(&cfg, cl)).await,
        Cmd::Apps { all, action } => match action {
            None => Box::pin(apps(&cfg, cl, all)).await,
            Some(AppsCmd::List { all: list_all }) => Box::pin(apps(&cfg, cl, all || list_all)).await,
            Some(AppsCmd::Show { app }) => Box::pin(ps(&cfg, cl, &app)).await,
            Some(AppsCmd::Destroy(a)) => Box::pin(destroy(&cfg, cl, a)).await,
        },
        Cmd::Ps { app } => Box::pin(ps(&cfg, cl, &app)).await,
        Cmd::Logs { app, follow, tail, instance } => Box::pin(logs(&cfg, cl, &app, follow, tail, instance)).await,
        Cmd::Scale { app, count, min, max, cpu, memory } => {
            util::validate_name("app", &app)?;
            if count.is_none() && min.is_none() && max.is_none() && cpu.is_none() && memory.is_none() {
                bail!("nothing to change: pass a count (latrix scale {app} 3) or --min/--max/--cpu/--memory");
            }
            if let Some(c_val) = cpu {
                if !c_val.is_finite() || c_val <= 0.0 {
                    bail!("--cpu must be a finite positive number");
                }
            }
            if let (Some(lo), Some(hi)) = (min, max) {
                if lo > hi {
                    bail!("--min ({lo}) must be <= --max ({hi})");
                }
            }
            let (_, _, c) = connect(&cfg, cl).await?;
            let v: AppView = c
                .post(&format!("/v1/apps/{app}/scale"), &ScaleRequest { count, min, max, cpu, memory: memory.clone() })
                .await?;
            if v.autoscale {
                println!("{app}: autoscaling between {} and {} (now {})", v.min, v.max, v.count);
            } else {
                println!("{app}: {} instance(s), {} CPU, {} each", v.count, v.cpu, v.memory);
            }
            if (cpu.is_some() || memory.is_some())
                && v.release_status == Some(crate::state::ReleaseStatus::Deploying)
            {
                let timeout = v.config.as_ref().map(|cfg| cfg.deploy.health_timeout_secs()).unwrap_or(120);
                deploy::watch(&c, &app, v.current, timeout).await?;
            }
            Ok(())
        }
        Cmd::Restart { app } => {
            util::validate_name("app", &app)?;
            let (_, _, c) = connect(&cfg, cl).await?;
            let timeout = app_health_timeout(&c, &app).await;
            let r: DeployResponse = c.post(&format!("/v1/apps/{app}/restart"), &serde_json::json!({})).await?;
            deploy::watch(&c, &app, r.version, timeout).await
        }
        Cmd::Rollback { app, version } => {
            util::validate_name("app", &app)?;
            let (_, _, c) = connect(&cfg, cl).await?;
            let timeout = app_health_timeout(&c, &app).await;
            let r: DeployResponse = c.post(&format!("/v1/apps/{app}/rollback"), &RollbackRequest { version }).await?;
            deploy::watch(&c, &app, r.version, timeout).await
        }
        Cmd::Releases { app } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
            print_releases(&v);
            Ok(())
        }
        Cmd::Destroy(a) => destroy(&cfg, cl, a).await,
        Cmd::Secrets(s) => secrets(&cfg, cl, s).await,
        Cmd::Console { app, cmd } => console(&cfg, cl, &app, cmd).await,
        Cmd::Machine(m) => Box::pin(machine_cmd(&mut cfg, cl, m)).await,
        Cmd::Volumes { action } => match action {
            None | Some(VolumesCmd::List) => volumes(&cfg, cl).await,
            Some(VolumesCmd::Prune { yes }) => prune_volumes(&cfg, cl, yes).await,
            Some(VolumesCmd::Snapshots { app }) => snapshots_list(&cfg, cl, &app).await,
            Some(VolumesCmd::Snapshot { app }) => snapshot_now(&cfg, cl, &app).await,
            Some(VolumesCmd::Rollback { app, snapshot, volume, yes }) => {
                snapshot_rollback(&cfg, cl, &app, &snapshot, volume.as_deref(), yes).await
            }
        },
        Cmd::Doctor { machine } => Box::pin(doctor::doctor(&cfg, cl, machine.as_deref())).await,
        Cmd::Backup { apps, all, out, no_image, stop } => Box::pin(backup::backup(&cfg, cl, apps, all, out, no_image, stop)).await,
        Cmd::Restore { file, as_name } => Box::pin(backup::restore(&cfg, cl, &file, as_name)).await,
        Cmd::Import(ImportCmd::Fly { app, as_name, no_data, no_secrets, from_source }) => {
            Box::pin(fly::import(&cfg, cl, fly::ImportOptions { fly_app: app, name: as_name, no_data, no_secrets, from_source })).await
        }
        Cmd::Rexctl { action } => Box::pin(rexctl::run_cmd(&cfg, cl, action)).await,
        Cmd::Certs { .. } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let st: StatusView = c.get("/v1/status").await?;
            let now = util::now();
            let rows = st
                .certs
                .iter()
                .map(|x| {
                    vec![
                        x.domain.clone(),
                        ago(x.issued_at),
                        format!("in {}", human_duration(x.not_after.saturating_sub(now))),
                        if x.unused_since == 0 {
                            "in use (renewed 30 days before expiry)".into()
                        } else {
                            format!(
                                "unused, removed in {}",
                                human_duration((x.unused_since + 7 * 86400).saturating_sub(now))
                            )
                        },
                    ]
                })
                .collect();
            if !st.certs.is_empty() {
                print_table(&["DOMAIN", "ISSUED", "EXPIRES", "STATUS"], rows);
            }
            if !st.certs_pending.is_empty() {
                if !st.certs.is_empty() {
                    println!();
                }
                println!("WAITING FOR A CERTIFICATE");
                let rows = st
                    .certs_pending
                    .iter()
                    .map(|p| {
                        vec![
                            p.domain.clone(),
                            if p.retry_at <= now { "now".into() } else { format!("in {}", human_duration(p.retry_at - now)) },
                            p.reason.chars().take(110).collect(),
                        ]
                    })
                    .collect();
                print_table(&["DOMAIN", "NEXT TRY", "WHY"], rows);
            }
            if st.certs.is_empty() && st.certs_pending.is_empty() {
                println!("(no certificates yet — add [http] domains to an app and point DNS at any machine)");
            }
            Ok(())
        }
        Cmd::Dns { action } => dns_cmd(&cfg, cl, action.unwrap_or(DnsCmd::Status { app: None })).await,
        Cmd::Events { .. } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let ev: Vec<crate::state::Event> = c.get("/v1/events").await?;
            for e in ev {
                println!("{:>8}  {:<4}  {}", ago(e.ts), e.level, e.message);
            }
            Ok(())
        }
        Cmd::Keys { action } => keys_cmd(&cfg, cl, action.unwrap_or(KeysCmd::List)).await,
        Cmd::Settings { pairs } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let s: crate::state::Settings = if pairs.is_empty() {
                c.get("/v1/settings").await?
            } else {
                c.post("/v1/settings", &parse_pairs(&pairs)?).await?
            };
            println!("{}", toml::to_string_pretty(&s)?);
            Ok(())
        }
        Cmd::Dashboard { port, no_open } => dashboard(&cfg, cl, port, no_open).await,
        Cmd::Autopilot(a) => match a {
            AutopilotCmd::On { budget, min_machines, max_machines, provider } => {
                autopilot_on(&cfg, cl, budget, min_machines, max_machines, &provider).await
            }
            AutopilotCmd::Off => {
                let (_, _, c) = connect(&cfg, cl).await?;
                let v: AutopilotView = c
                    .post("/v1/autopilot", &AutopilotRequest { enabled: Some(false), ..Default::default() })
                    .await?;
                print_autopilot(&v);
                Ok(())
            }
            AutopilotCmd::Status => {
                let (_, _, c) = connect(&cfg, cl).await?;
                let v: AutopilotView = c.get("/v1/autopilot").await?;
                print_autopilot(&v);
                Ok(())
            }
        },
        Cmd::Up { budget, provider, max_machines } => {
            if let Some(b) = budget {
                if !b.is_finite() || b < 0.0 {
                    bail!("--budget must be a finite non-negative number");
                }
            }
            let has_cluster = match cfg.profile(cl) {
                Ok((_, p)) => !p.local && p.kubernetes.is_none() && !p.machines.is_empty(),
                Err(e) if cfg.clusters.len() > 1 && cl.is_none() && cfg.current.is_none() => return Err(e),
                Err(_) => false,
            };
            if !has_cluster {
                println!("==> no cluster yet: buying the cheapest server that fits");
                create_machine(
                    &mut cfg,
                    cl,
                    CreateOptions {
                        provider: provider.clone(),
                        size: None,
                        region: None,
                        min_memory: "2GB".into(),
                        image: None,
                        name: None,
                        key: None,
                        agent_binary: None,
                    },
                )
                .await?;
                println!();
            }
            let only: Vec<String> = provider.into_iter().collect();
            autopilot_on(&cfg, cl, budget, None, max_machines, &only).await?;
            println!("\nNext: cd your-app && latrix launch && latrix deploy");
            Ok(())
        }
        Cmd::Upgrade { machine, agent_binary } => {
            machine::upgrade_agents(&cfg, cl, machine.as_deref(), agent_binary.as_deref()).await
        }
        _ => unreachable!(),
    }
}

async fn agent_cmd(a: AgentCmd) -> Result<()> {
    let data = |d: Option<std::path::PathBuf>| d.unwrap_or_else(|| agent::default_data_dir(false));
    match a {
        AgentCmd::Run { dev, data: d } => {
            let dir = d.unwrap_or_else(|| agent::default_data_dir(dev));
            agent::run(dir, dev).await
        }
        AgentCmd::Keygen { data: d } => {
            let (_, public) = agent::mesh::keypair(&data(d)).await?;
            println!("{public}");
            Ok(())
        }
        AgentCmd::Facts => {
            println!("{}", serde_json::to_string(&agent::metrics::local_facts().await)?);
            Ok(())
        }
        AgentCmd::InitFirst { data: d } => {
            let init: machine::InitFirst = read_stdin_json()?;
            let dir = data(d);
            let facts = agent::metrics::local_facts().await;
            agent::init_first(
                &dir,
                &init.cluster,
                &init.token,
                &init.name,
                &init.public_ip,
                &init.wg_pubkey,
                &facts,
                (init.region, init.provider, init.monthly_cost),
                false,
            )
        }
        AgentCmd::WriteJoin { data: d } => {
            let wj: machine::WriteJoin = read_stdin_json()?;
            agent::write_join(&data(d), &wj.identity, &wj.state)
        }
    }
}

async fn dev(data: Option<std::path::PathBuf>) -> Result<()> {
    // Check early before overwriting the saved "local" profile so a second `latrix dev`
    // doesn't clobber an active agent's config only to fail binding the port.
    if std::net::TcpListener::bind(("127.0.0.1", util::API_PORT)).is_err() {
        bail!(
            "port {} is already in use on 127.0.0.1 (is `latrix dev` or another agent already running?)",
            util::API_PORT
        );
    }
    let dir = data.unwrap_or_else(|| agent::default_data_dir(true));
    if !dir.join("node.json").exists() {
        let facts = agent::metrics::local_facts().await;
        agent::init_first(&dir, "local", &util::random_token(), "local", "127.0.0.1", "", &facts, (None, None, None), true)?;
    }
    let id: agent::NodeIdentity = serde_json::from_str(&std::fs::read_to_string(dir.join("node.json"))?)?;
    let mut cfg = CliConfig::load()?;
    cfg.clusters.insert(
        "local".into(),
        ClusterProfile {
            token: id.token,
            local: true,
            machines: vec![],
            default_key: None,
            kubernetes: None,
        },
    );
    if cfg.current.is_none() {
        cfg.current = Some("local".into());
    }
    cfg.save()?;
    let current = cfg.current.clone().unwrap_or_default();
    println!("latrix local cluster starting (data in {})", dir.display());
    println!("  apps:       http://<app>.localhost:{}", util::DEV_HTTP_PORT);
    println!("  dashboard:  http://127.0.0.1:{}/", util::API_PORT);
    if current == "local" {
        println!("  in another terminal: cd your-app && latrix launch && latrix deploy");
    } else {
        println!("  in another terminal: latrix --cluster local deploy   (current cluster is '{current}')");
    }
    println!("  Ctrl-C stops the agent; containers keep running.\n");
    agent::run(dir, true).await
}

fn cluster_cmd(c: ClusterCmd) -> Result<()> {
    let mut cfg = CliConfig::load()?;
    match c {
        ClusterCmd::List => {
            let rows = cfg
                .clusters
                .iter()
                .map(|(n, p)| {
                    vec![
                        format!("{}{}", n, if cfg.current.as_deref() == Some(n) { " *" } else { "" }),
                        if p.local {
                            "local".into()
                        } else if let Some(k) = &p.kubernetes {
                            format!("kubernetes ({}, ns {})", k.context.as_deref().unwrap_or("current context"), k.namespace)
                        } else {
                            format!("{} machine(s)", p.machines.len())
                        },
                        p.machines.iter().map(|m| m.ssh.clone()).collect::<Vec<_>>().join(", "),
                    ]
                })
                .collect();
            print_table(&["CLUSTER", "MACHINES", "SSH"], rows);
        }
        ClusterCmd::Use { name } => {
            if !cfg.clusters.contains_key(&name) {
                bail!("unknown cluster '{name}'");
            }
            cfg.current = Some(name.clone());
            cfg.save()?;
            println!("now using cluster '{name}'");
        }
        ClusterCmd::Forget { name } => {
            cfg.clusters.remove(&name).ok_or_else(|| anyhow!("unknown cluster '{name}'"))?;
            if cfg.current.as_deref() == Some(&name) {
                cfg.current = None;
            }
            cfg.save()?;
            println!("forgot cluster '{name}' (machines untouched)");
        }
        ClusterCmd::Connect { .. } => unreachable!(),
    }
    Ok(())
}

/// Rebuild the local profile of a cluster from one of its machines.
async fn cluster_connect(target: &str, port: u16, key: Option<String>) -> Result<()> {
    let ssh = super::ssh::Ssh::new(target, port, key.clone());
    println!("==> reading the cluster identity from {}", ssh.host());
    let raw = ssh
        .run("cat /var/lib/latrix/node.json")
        .await
        .with_context(|| format!("could not read latrix's identity on {target} (is it a latrix machine, and does this key log in?)"))?;
    let id: crate::agent::NodeIdentity =
        serde_json::from_str(raw.trim()).context("unexpected content in /var/lib/latrix/node.json")?;
    let host = ssh.host().to_string();
    let user = target.split_once('@').map(|(u, _)| u).unwrap_or("root").to_string();
    let first = super::profile::MachineSsh { name: host.clone(), ssh: target.to_string(), port, key: key.clone() };
    let mut profile = ClusterProfile {
        token: id.token.clone(),
        machines: vec![first],
        default_key: key.clone(),
        ..Default::default()
    };
    let c = Client::connect(&profile).await?;
    let st: StatusView = c.get("/v1/status").await?;
    // Every machine, reached the same way (the one we came through first).
    let mut machines = vec![];
    for m in &st.machines {
        let this = m.machine.id == id.machine_id || m.machine.public_ip == host || m.machine.name == host;
        machines.push(super::profile::MachineSsh {
            name: m.machine.name.clone(),
            ssh: if this { target.to_string() } else { format!("{user}@{}", m.machine.public_ip) },
            port: if this { port } else { 22 },
            key: key.clone(),
        });
    }
    machines.sort_by_key(|m| m.ssh != target);
    profile.machines = machines;
    let mut cfg = CliConfig::load()?;
    if let Some(old) = cfg.clusters.get(&id.cluster) {
        if old.token != id.token {
            bail!(
                "a different cluster named '{}' is already saved locally; run `latrix cluster forget {}` first if you want to replace it",
                id.cluster,
                id.cluster
            );
        }
    }
    let n = profile.machines.len();
    cfg.clusters.insert(id.cluster.clone(), profile);
    cfg.current = Some(id.cluster.clone());
    cfg.save()?;
    println!("\n✓ connected to cluster '{}' ({n} machine{}, {} app{})", id.cluster, if n == 1 { "" } else { "s" }, st.apps.len(), if st.apps.len() == 1 { "" } else { "s" });
    for m in &st.machines {
        println!("    {}  {}", m.machine.name, m.machine.public_ip);
    }
    if !st.settings.autopilot {
        println!("\n  `latrix machine create` needs your provider token on this computer again:\n    latrix provider set hetzner <token>");
    }
    println!("\n  Everything else (apps, secrets, volumes, autopilot) lives on the cluster and is unchanged.");
    println!("  Tip: add a backup key so losing this computer's key can't lock you out:\n    latrix keys add <other-key.pub>");
    Ok(())
}

async fn keys_cmd(cfg: &CliConfig, cl: Option<&str>, action: KeysCmd) -> Result<()> {
    use crate::agent::keys::{key_id, short};
    use crate::api_types::{SshKeysRequest, SshKeysView};
    let (_, p, c) = connect(cfg, cl).await?;
    let read_key = |k: &str| -> Result<String> {
        let trimmed = k.trim();
        let looks_like_key = trimmed.starts_with("ssh-")
            || trimmed.starts_with("ecdsa-")
            || trimmed.starts_with("sk-");
        let path = std::path::Path::new(trimmed);
        if !looks_like_key && path.is_file() {
            let text = std::fs::read_to_string(path)?;
            if text.contains("PRIVATE KEY") {
                bail!("{k} is a private key; pass the .pub file");
            }
            Ok(text.trim().to_string())
        } else {
            Ok(trimmed.to_string())
        }
    };
    let v: SshKeysView = match action {
        KeysCmd::List => c.get("/v1/ssh-keys").await?,
        KeysCmd::Add { key } => {
            let k = match key {
                Some(k) => read_key(&k)?,
                None => providers::ssh_key(p.default_key.as_deref())?.0,
            };
            let v: SshKeysView = c.post("/v1/ssh-keys", &SshKeysRequest { add: vec![k.clone()], remove: vec![] }).await?;
            println!("✓ {} can now log in to every machine (new ones too)\n", short(&k));
            v
        }
        KeysCmd::Remove { key } => {
            let selector = key.trim();
            if selector.is_empty() {
                bail!("key selector must not be empty");
            }
            let current: SshKeysView = c.get("/v1/ssh-keys").await?;
            let k = read_key(selector)?;
            let found: Vec<String> = if key_id(&k).is_some() {
                vec![k]
            } else {
                // By comment or the end of the key.
                current
                    .keys
                    .iter()
                    .filter(|x| {
                        x.split_whitespace().skip(2).collect::<Vec<_>>().join(" ") == selector
                            || x.split_whitespace().nth(1).map(|b| b.ends_with(selector)).unwrap_or(false)
                    })
                    .cloned()
                    .collect()
            };
            match found.len() {
                0 => bail!("no key matches '{key}' (see `latrix keys`)"),
                1 => {}
                _ => bail!("'{key}' matches {} keys; pass the whole key or its .pub file", found.len()),
            }
            if let Ok((mine, _)) = providers::ssh_key(p.default_key.as_deref()) {
                if key_id(&mine) == key_id(&found[0]) {
                    println!("    note: that's the key this computer uses; make sure another key works first");
                }
            }
            let v: SshKeysView = c.post("/v1/ssh-keys", &SshKeysRequest { add: vec![], remove: found.clone() }).await?;
            println!("✓ removed {} from every machine\n", short(&found[0]));
            v
        }
    };
    println!("Keys that can log in to every machine:");
    for k in &v.keys {
        println!("  {}", short(k));
    }
    println!("  {}  (the cluster's own key, for servers it sets up)", short(&v.cluster_key));
    Ok(())
}

async fn provider_cmd(p: ProviderCmd, cl: Option<&str>) -> Result<()> {
    let mut cfg = CliConfig::load()?;
    match p {
        ProviderCmd::Set { provider, token } => {
            let token = token.trim().to_string();
            if token.is_empty() {
                bail!("provider token must not be empty");
            }
            let lower = provider.to_ascii_lowercase();
            if lower == "cloudflare" || lower == "cf" {
                cfg.providers.insert("cloudflare".into(), token);
                cfg.save()?;
                println!("saved cloudflare token in {}", CliConfig::path().display());
                println!("next: run `latrix dns cloudflare` to enable automatic DNS on your cluster");
                return Ok(());
            }
            let p = providers::canonical(&provider)?;
            cfg.providers.insert(p.into(), token);
            cfg.save()?;
            println!("saved {p} token in {}", CliConfig::path().display());
        }
        ProviderCmd::Unset { provider } => {
            let lower = provider.to_ascii_lowercase();
            if lower == "cloudflare" || lower == "cf" {
                if cfg.providers.remove("cloudflare").is_some() {
                    cfg.save()?;
                    println!("removed cloudflare token from {}", CliConfig::path().display());
                } else {
                    println!("no cloudflare token saved in {}", CliConfig::path().display());
                }
                println!("note: `latrix dns off` also disables Cloudflare DNS on the cluster");
                return Ok(());
            }
            let p = providers::canonical(&provider)?;
            if cfg.providers.remove(p).is_some() {
                cfg.save()?;
                println!("removed {p} token from {}", CliConfig::path().display());
            } else {
                println!("no {p} token saved in {}", CliConfig::path().display());
            }
            match connect(&cfg, cl).await {
                Ok((_, _, c)) => {
                    let remaining: Vec<String> = c.delete(&format!("/v1/providers/{p}")).await?;
                    println!(
                        "removed {p} token from the cluster (autopilot has tokens for: {})",
                        if remaining.is_empty() { "none".into() } else { remaining.join(", ") }
                    );
                    let st: StatusView = c.get("/v1/status").await?;
                    let on_provider: Vec<&str> = st
                        .machines
                        .iter()
                        .filter(|m| m.machine.provider.as_ref().map(|x| x.provider.as_str()) == Some(p))
                        .map(|m| m.machine.name.as_str())
                        .collect();
                    if !on_provider.is_empty() {
                        println!(
                            "note: still running on {p}: {} — remove them with `latrix machine remove <name> --destroy`\n\
                             (while the token still works at {p}), then revoke the token in the {p} console",
                            on_provider.join(", ")
                        );
                    } else {
                        println!("note: revoke the token in the {p} console to fully disconnect it");
                    }
                    if remaining.is_empty() {
                        println!("note: without a provider token the autopilot can't buy servers");
                    }
                }
                Err(e) => {
                    println!("note: could not reach the cluster ({e}); its copy of the {p} token is still there");
                    println!("      run `latrix provider unset {p}` again when the cluster is reachable");
                }
            }
        }
        ProviderCmd::Sizes { provider } => {
            let p = providers::canonical(&provider)?;
            providers::sizes(p, &providers::token(&cfg, p)?).await?;
        }
    }
    Ok(())
}

fn print_dns_status(v: &DnsStatusView, only_app: Option<&str>) {
    if v.configured {
        println!(
            "Cloudflare DNS: ON · zones: {} · default: {}, TTL {}{}",
            if v.zones.is_empty() { "(none accessible)".into() } else { v.zones.join(", ") },
            if v.proxied_default { "proxied" } else { "DNS only" },
            if v.ttl_default == 1 { "auto".into() } else { format!("{}s", v.ttl_default) },
            if v.last_sync > 0 { format!(" · synced {}", ago(v.last_sync)) } else { String::new() }
        );
    } else {
        println!("Cloudflare DNS: off");
        println!("  enable: latrix dns cloudflare <api-token>   (token needs Zone:Read + Zone:DNS:Edit)");
    }
    if let Some(err) = &v.last_error {
        println!("  ! last error: {err}");
    }
    let records: Vec<&DnsRecordStatus> = v
        .records
        .iter()
        .filter(|r| only_app.map(|a| r.app.as_deref() == Some(a)).unwrap_or(true))
        .collect();
    if records.is_empty() {
        println!(
            "\n(no DNS records{} — add [http] domains or [[dns]] to latrix.toml, or run `latrix dns add <app> <name>`)",
            only_app.map(|a| format!(" for '{a}'")).unwrap_or_default()
        );
        return;
    }
    println!();
    let rows = records
        .iter()
        .map(|r| {
            let status = match r.status.as_str() {
                "synced" => "synced".into(),
                "error" => format!("error: {}", r.error.as_deref().unwrap_or("")),
                "no_zone" => "no matching CF zone".into(),
                other => other.into(),
            };
            vec![
                r.app.clone().unwrap_or_else(|| "(cluster)".into()),
                r.name.clone(),
                r.record_type.clone(),
                r.content.clone(),
                if r.proxied { "yes".into() } else { "no".into() },
                if r.ttl == 1 { "auto".into() } else { format!("{}s", r.ttl) },
                r.source.clone(),
                status,
            ]
        })
        .collect();
    print_table(&["APP", "NAME", "TYPE", "CONTENT", "PROXIED", "TTL", "SOURCE", "STATUS"], rows);
}

async fn dns_cmd(cfg: &CliConfig, cl: Option<&str>, action: DnsCmd) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    match action {
        DnsCmd::Status { app } => {
            let v: DnsStatusView = c.get("/v1/dns").await?;
            print_dns_status(&v, app.as_deref());
        }
        DnsCmd::Cloudflare { token, proxied, no_proxied, ttl } => {
            let prox = if proxied { Some(true) } else if no_proxied { Some(false) } else { None };
            let resolved_token = token
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("CLOUDFLARE_API_TOKEN").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
                .or_else(|| std::env::var("CF_API_TOKEN").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
                .or_else(|| cfg.providers.get("cloudflare").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
            if resolved_token.is_none() && prox.is_none() && ttl.is_none() {
                bail!(
                    "pass a Cloudflare API token:\n  latrix dns cloudflare <token>\n  (or set CLOUDFLARE_API_TOKEN, or run `latrix provider set cloudflare <token>`)\n  Create a token with Zone:Read and Zone:DNS:Edit at https://dash.cloudflare.com/profile/api-tokens"
                );
            }
            let v: DnsStatusView = c
                .post(
                    "/v1/dns/cloudflare",
                    &CloudflareSetupRequest {
                        token: resolved_token,
                        remove: false,
                        proxied: prox,
                        ttl,
                    },
                )
                .await?;
            println!("✓ Cloudflare DNS configured");
            print_dns_status(&v, None);
        }
        DnsCmd::Off => {
            let _: DnsStatusView = c
                .post(
                    "/v1/dns/cloudflare",
                    &CloudflareSetupRequest { remove: true, ..Default::default() },
                )
                .await?;
            println!("✓ Cloudflare DNS disabled (existing records in Cloudflare were left as-is)");
        }
        DnsCmd::Add { app, name, record_type, content, proxied, no_proxied, ttl, priority } => {
            util::validate_name("app", &app)?;
            let prox = if proxied { Some(true) } else if no_proxied { Some(false) } else { None };
            let rec = crate::config::DnsRecordConfig {
                name: name.clone(),
                record_type,
                content,
                proxied: prox,
                ttl,
                priority,
            };
            crate::config::validate_dns_record(&rec)?;
            let v: DnsStatusView = c
                .post(
                    &format!("/v1/apps/{app}/dns"),
                    &AppDnsRequest { add: vec![rec], remove: vec![] },
                )
                .await?;
            println!("✓ saved DNS record '{name}' for {app}");
            print_dns_status(&v, Some(&app));
        }
        DnsCmd::Remove { app, name, record_type, content } => {
            util::validate_name("app", &app)?;
            let v: DnsStatusView = c
                .post(
                    &format!("/v1/apps/{app}/dns"),
                    &AppDnsRequest {
                        add: vec![],
                        remove: vec![DnsRecordRemove { name: name.clone(), record_type, content }],
                    },
                )
                .await?;
            println!("✓ removed DNS record '{name}' from {app}");
            print_dns_status(&v, Some(&app));
        }
        DnsCmd::Sync => {
            let r: DnsSyncResult = c.post("/v1/dns/sync", &serde_json::json!({})).await?;
            if r.created == 0 && r.updated == 0 && r.deleted == 0 && r.errors.is_empty() {
                println!("✓ Cloudflare DNS is already up to date");
            } else {
                println!(
                    "✓ Cloudflare DNS synced: {} created, {} updated, {} deleted{}",
                    r.created,
                    r.updated,
                    r.deleted,
                    if r.errors.is_empty() { String::new() } else { format!(", {} error(s)", r.errors.len()) }
                );
            }
            for e in &r.errors {
                println!("  ! {e}");
            }
            print_dns_status(&r.status, None);
        }
    }
    Ok(())
}

fn compose_convert(file: &Path, write: bool) -> Result<()> {
    for c in compose::convert(file)? {
        let text = toml::to_string_pretty(&c.config)?;
        for w in &c.warnings {
            eprintln!("warning ({}): {w}", c.config.app);
        }
        if write {
            let out = c.base.join(format!("latrix.{}.toml", c.config.service_name()));
            std::fs::write(&out, &text)?;
            println!("wrote {}", out.display());
        } else {
            println!("# ---- {} ----\n{text}", c.config.app);
        }
    }
    Ok(())
}

async fn deploy_cmd(cfg: &CliConfig, cl: Option<&str>, args: DeployArgs) -> Result<()> {
    if let Some(file) = &args.compose {
        let apps = compose::convert(file)?;
        let (_, _, c) = connect(cfg, cl).await?;
        let mut failed = vec![];
        for a in &apps {
            for w in &a.warnings {
                println!("warning ({}): {w}", a.config.app);
            }
            if let Err(e) = deploy::deploy_one(&c, &a.config, &a.base, args.detach, args.message.clone()).await {
                if e.is::<deploy::DeployCancelled>() {
                    return Err(e);
                }
                println!("✗ {}: {e:#}", a.config.app);
                failed.push(a.config.app.clone());
            }
        }
        if !failed.is_empty() {
            bail!("{} service(s) failed: {}", failed.len(), failed.join(", "));
        }
        return Ok(());
    }
    let (app, base) = load_app_for_deploy(&args)?;
    let (_, _, c) = connect(cfg, cl).await?;
    deploy::deploy_one(&c, &app, &base, args.detach, args.message).await
}

/// latrix.toml plus --image / --git overrides, and the directory builds are relative to.
pub fn load_app_for_deploy(args: &DeployArgs) -> Result<(crate::config::AppConfig, std::path::PathBuf)> {
    if !args.config.exists() {
        bail!(
            "{} not found. Run `latrix launch` to create one{}",
            args.config.display(),
            if Path::new("docker-compose.yml").exists() || Path::new("compose.yaml").exists() {
                ", or `latrix deploy --compose docker-compose.yml`"
            } else {
                ""
            }
        );
    }
    let mut app = crate::config::AppConfig::load(&args.config)?;
    if let Some(img) = args.image.clone() {
        app.build.image = Some(img);
        app.build.git = None;
    }
    if let Some(g) = args.git.clone() {
        let (url, branch) = match g.split_once('#') {
            Some((u, b)) => (u.to_string(), Some(b.to_string())),
            None => (g, None),
        };
        app.build.git = Some(url);
        app.build.image = None;
        if branch.is_some() {
            app.build.branch = branch;
        }
    }
    let base = args
        .config
        .parent()
        .map(|p| if p.as_os_str().is_empty() { Path::new(".") } else { p })
        .unwrap_or(Path::new("."))
        .to_path_buf();
    Ok((app, base))
}

fn bar(frac: f64) -> String {
    let n = (frac.clamp(0.0, 1.0) * 10.0).round() as usize;
    format!("{}{}", "█".repeat(n), "░".repeat(10 - n))
}

fn partition_fluxer_apps(
    st: &StatusView,
) -> (Vec<&AppView>, Vec<&AppView>, Option<&FluxerSummary>) {
    let Some(fx) = st.fluxer.as_ref() else {
        return (st.apps.iter().collect(), vec![], None);
    };
    let mut regular = vec![];
    let mut fluxer = vec![];
    for a in &st.apps {
        if a.group.as_deref() == Some(fx.project.as_str()) {
            fluxer.push(a);
        } else {
            regular.push(a);
        }
    }
    (regular, fluxer, Some(fx))
}

fn format_mem_mb(mb: u64) -> String {
    if mb >= 1024 && mb.is_multiple_of(1024) {
        format!("{}GB", mb / 1024)
    } else if mb >= 1024 {
        format!("{:.1}GB", mb as f64 / 1024.0)
    } else {
        format!("{mb}MB")
    }
}

fn fluxer_rollup(fx: &FluxerSummary, apps: &[&AppView]) -> (usize, usize, String, f64, u64, String) {
    let total = apps.len();
    let mut healthy_svcs = 0usize;
    let mut deploying = false;
    let mut failed = false;
    let mut cpu_sum = 0.0f64;
    let mut mem_mb = 0u64;
    for a in apps {
        let h = a
            .instances
            .iter()
            .filter(|i| !i.instance.stopping && i.report.as_ref().map(|r| r.healthy).unwrap_or(false))
            .count();
        if a.count > 0 && h >= a.count as usize {
            healthy_svcs += 1;
        }
        match a.release_status {
            Some(crate::state::ReleaseStatus::Deploying) => deploying = true,
            Some(crate::state::ReleaseStatus::Failed) => failed = true,
            _ => {}
        }
        cpu_sum += a.cpu * a.count.max(1) as f64;
        mem_mb += util::parse_size_mb(&a.memory).unwrap_or(0) * a.count.max(1) as u64;
    }
    let state = if failed {
        "failed"
    } else if deploying {
        "deploying"
    } else if healthy_svcs == total && total > 0 {
        "active"
    } else {
        "degraded"
    };
    let url = apps
        .iter()
        .find_map(|a| a.urls.first().cloned())
        .unwrap_or_else(|| format!("https://{}", fx.domain));
    (healthy_svcs, total, state.into(), cpu_sum, mem_mb, url)
}

async fn status(cfg: &CliConfig, cl: Option<&str>) -> Result<()> {
    let (name, _, c) = connect(cfg, cl).await?;
    let st: StatusView = c.get("/v1/status").await?;
    let leader = st
        .leader
        .and_then(|l| st.machines.iter().find(|m| m.machine.id == l))
        .map(|m| m.machine.name.clone())
        .unwrap_or_else(|| "?".into());
    let (regular_apps, fluxer_apps, fx_meta) = partition_fluxer_apps(&st);
    let visible_apps = regular_apps.len() + usize::from(!fluxer_apps.is_empty());
    let mut head = format!(
        "Cluster '{name}' · leader {leader} · {} machine(s) · {} app(s)",
        st.machines.len(),
        visible_apps
    );
    if st.monthly_cost > 0.0 {
        head.push_str(&format!(" · est. {:.2}/month", st.monthly_cost));
        if st.settings.monthly_budget > 0.0 && st.monthly_cost > st.settings.monthly_budget {
            head.push_str(&format!(" (over budget of {:.2}!)", st.settings.monthly_budget));
        }
    }
    if let Some(d) = &st.dns {
        if d.configured {
            let errs = d.records.iter().filter(|r| r.status == "error").count();
            head.push_str(&format!(
                " · cloudflare DNS ({} record{}{})",
                d.records.len(),
                if d.records.len() == 1 { "" } else { "s" },
                if errs > 0 { format!(", {errs} error(s)") } else { String::new() }
            ));
        }
    }
    println!("{head}\n");
    println!("MACHINES");
    let rows = st
        .machines
        .iter()
        .map(|m| {
            let met = m.metrics.clone().unwrap_or_default();
            let mem = if met.mem_total_mb > 0 { met.mem_used_mb as f64 / met.mem_total_mb as f64 } else { 0.0 };
            let mem_cell = if met.swap_total_mb > 0 {
                format!(
                    "mem {} {:>3.0}% sw {:>2.0}%",
                    bar(mem),
                    mem * 100.0,
                    met.swap_used_mb as f64 / met.swap_total_mb as f64 * 100.0
                )
            } else {
                format!("mem {} {:>3.0}%", bar(mem), mem * 100.0)
            };
            vec![
                format!("{}{}", m.machine.name, if m.leader { " *" } else { "" }),
                if m.alive { m.machine.status.to_string() } else { "DOWN".into() },
                format!("cpu {} {:>3.0}%", bar(met.cpu_pct / 100.0), met.cpu_pct),
                mem_cell,
                format!("{} inst", m.instances),
                m.updates
                    .as_ref()
                    .filter(|u| u.pending > 0 || u.reboot_required)
                    .map(|u| match (u.pending, u.reboot_required) {
                        (0, true) => "reboot required".into(),
                        (n, true) => format!("{n} updates +reboot"),
                        (n, false) => format!("{n} updates"),
                    })
                    .unwrap_or_default(),
            ]
        })
        .collect();
    print_table(&["NAME", "STATUS", "CPU", "MEMORY", "INSTANCES", "UPDATES"], rows);
    println!("\nAPPS");
    if visible_apps == 0 {
        println!("  (none yet — `latrix launch` then `latrix deploy`)");
    } else {
        let mut rows: Vec<Vec<String>> = regular_apps
            .iter()
            .map(|a| {
                let healthy = a
                    .instances
                    .iter()
                    .filter(|i| !i.instance.stopping && i.report.as_ref().map(|r| r.healthy).unwrap_or(false))
                    .count();
                let scale = if a.autoscale { format!("{}/{} ({}-{})", healthy, a.count, a.min, a.max) } else { format!("{}/{}", healthy, a.count) };
                vec![
                    a.name.clone(),
                    format!(
                        "v{} {}",
                        a.current,
                        a.release_status.as_ref().map(|s| format!("{s:?}").to_lowercase()).unwrap_or_default()
                    ),
                    scale,
                    if a.stateful { "stateful".into() } else { "stateless".into() },
                    a.urls.first().cloned().unwrap_or_else(|| a.internal.first().cloned().unwrap_or_default()),
                ]
            })
            .collect();
        if let (Some(fx), false) = (fx_meta, fluxer_apps.is_empty()) {
            let (h, total, state, _, _, url) = fluxer_rollup(fx, &fluxer_apps);
            let rel = if fx.release.is_empty() {
                state
            } else {
                format!("{} {state}", fx.release)
            };
            rows.push(vec![
                fx.project.clone(),
                rel,
                format!("{h}/{total} svc"),
                "fluxer".into(),
                url,
            ]);
            rows.sort_by(|a, b| a[0].cmp(&b[0]));
        }
        print_table(&["NAME", "RELEASE", "HEALTHY", "KIND", "URL"], rows);
    }
    if !st.events.is_empty() {
        println!("\nRECENT EVENTS");
        for e in st.events.iter().take(8) {
            println!("  {:>8}  {}{}", ago(e.ts), if e.level == "warn" { "! " } else { "" }, e.message);
        }
    }
    Ok(())
}

async fn apps(cfg: &CliConfig, cl: Option<&str>, show_all: bool) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    let st: StatusView = c.get("/v1/status").await?;
    let rows: Vec<Vec<String>> = if show_all {
        st.apps
            .iter()
            .map(|a| {
                vec![
                    a.name.clone(),
                    format!("v{}", a.current),
                    a.count.to_string(),
                    format!("{} / {}", a.cpu, a.memory),
                    a.image.clone(),
                ]
            })
            .collect()
    } else {
        let (regular_apps, fluxer_apps, fx_meta) = partition_fluxer_apps(&st);
        let mut r: Vec<Vec<String>> = regular_apps
            .iter()
            .map(|a| {
                vec![
                    a.name.clone(),
                    format!("v{}", a.current),
                    a.count.to_string(),
                    format!("{} / {}", a.cpu, a.memory),
                    a.image.clone(),
                ]
            })
            .collect();
        if let (Some(fx), false) = (fx_meta, fluxer_apps.is_empty()) {
            let (h, total, _, cpu, mem_mb, url) = fluxer_rollup(fx, &fluxer_apps);
            let rel = if fx.release.is_empty() { "fluxer".into() } else { fx.release.clone() };
            r.push(vec![
                fx.project.clone(),
                rel,
                format!("{h}/{total} svc"),
                format!("{cpu:.2} / {}", format_mem_mb(mem_mb)),
                format!("fluxer stack ({url})"),
            ]);
            r.sort_by(|a, b| a[0].cmp(&b[0]));
        }
        r
    };
    if rows.is_empty() {
        println!("(no apps yet — `latrix launch` then `latrix deploy`)");
        return Ok(());
    }
    print_table(&["NAME", "RELEASE", "COUNT", "CPU / MEM", "IMAGE"], rows);
    Ok(())
}

fn print_releases(v: &AppView) {
    let rows = v
        .releases
        .iter()
        .map(|r| {
            vec![
                format!("v{}{}", r.version, if r.version == v.current { " *" } else { "" }),
                format!("{:?}", r.status).to_lowercase(),
                ago(r.created_at),
                r.description.clone(),
                r.image.clone(),
            ]
        })
        .collect();
    print_table(&["VERSION", "STATUS", "CREATED", "DESCRIPTION", "IMAGE"], rows);
}

async fn ps(cfg: &CliConfig, cl: Option<&str>, app: &str) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    let v: AppView = match c.get(&format!("/v1/apps/{app}")).await {
        Ok(v) => v,
        Err(e) => {
            if let Ok(fx) = c.get::<RexctlStatusView>("/v1/rexctl").await {
                if fx.installed && (app == fx.project || app == "fluxer") {
                    return rexctl::status(cfg, cl).await;
                }
            }
            return Err(e);
        }
    };
    println!(
        "{} · v{} ({}) · {}{} instance(s) · {} CPU · {}",
        v.name,
        v.current,
        v.release_status.as_ref().map(|s| format!("{s:?}").to_lowercase()).unwrap_or_default(),
        v.count,
        if v.autoscale { format!(" (autoscale {}-{})", v.min, v.max) } else { String::new() },
        v.cpu,
        v.memory
    );
    for u in &v.urls {
        println!("  {u}");
    }
    if !v.internal.is_empty() {
        println!("  internal: {}", v.internal.join(", "));
    }
    if !v.dns_records.is_empty() {
        let desc: Vec<String> = v
            .dns_records
            .iter()
            .map(|r| match (&r.record_type, &r.content) {
                (Some(t), Some(c)) => format!("{} ({t} -> {c})", r.name),
                (Some(t), None) => format!("{} ({t} auto)", r.name),
                _ => format!("{} (auto)", r.name),
            })
            .collect();
        println!("  dns:      {}", desc.join(", "));
    }
    println!();
    let rows = v
        .instances
        .iter()
        .map(|i| {
            let r = i.report.clone().unwrap_or_default();
            vec![
                i.instance.id.clone(),
                format!("v{}", i.instance.release),
                i.machine_name.clone(),
                if i.instance.stopping { "stopping".into() } else if r.status.is_empty() { "pending".into() } else { r.status.clone() },
                if r.healthy { "✓".into() } else { "✗".into() },
                format!("{:.0}%", r.cpu_pct),
                format!("{:.0}MB", r.mem_mb),
                r.restarts.to_string(),
                ago(i.instance.created_at),
                r.error.unwrap_or_default().chars().take(60).collect(),
            ]
        })
        .collect();
    print_table(&["ID", "REL", "MACHINE", "STATE", "OK", "CPU", "MEM", "RESTARTS", "CREATED", "ERROR"], rows);
    if !v.volumes.is_empty() {
        println!();
        print_volume_rows(&v.volumes);
    }
    println!();
    print_releases(&v);
    Ok(())
}

fn print_volume_rows(vols: &[VolumeView]) {
    let rows = vols
        .iter()
        .map(|v| {
            let r = v.report.clone().unwrap_or_default();
            let last = r.synced.values().copied().min().unwrap_or(0);
            vec![
                format!("{}/{}", v.volume.app, v.volume.name),
                v.volume.path.clone(),
                v.primary_name.clone(),
                if v.replica_names.is_empty() { "-".into() } else { v.replica_names.join(", ") },
                format!("{}MB", r.size_mb),
                if v.volume.replicas.is_empty() { "-".into() } else { ago(last) },
                if v.volume.moving_to.is_some() { "moving".into() } else { r.error.unwrap_or_else(|| "ok".into()) },
            ]
        })
        .collect();
    print_table(&["VOLUME", "PATH", "PRIMARY", "REPLICAS", "SIZE", "LAST SYNC", "STATE"], rows);
}

async fn volumes(cfg: &CliConfig, cl: Option<&str>) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    let st: StatusView = c.get("/v1/status").await?;
    let vols: Vec<VolumeView> = st.apps.iter().flat_map(|a| a.volumes.clone()).collect();
    if vols.is_empty() {
        println!("no volumes in use (add [[volumes]] to an app's latrix.toml)");
    } else {
        print_volume_rows(&vols);
    }
    let unused = unused_volumes(&c, &st).await;
    if !unused.is_empty() {
        println!("\nUNATTACHED DATA (no app uses it; deleted automatically)");
        let now = util::now();
        let rows = unused
            .iter()
            .map(|(m, u)| {
                vec![
                    m.clone(),
                    u.volume.replace("__", "/"),
                    format!("{} MB", u.size_mb),
                    ago(u.unused_since),
                    if u.delete_at == 0 {
                        "never (retention=0)".into()
                    } else if u.delete_at <= now {
                        "on the next scan".into()
                    } else {
                        format!("in {}", human_duration(u.delete_at - now))
                    },
                ]
            })
            .collect();
        print_table(&["MACHINE", "VOLUME", "SIZE", "UNUSED SINCE", "DELETED"], rows);
        println!("delete it now with `latrix volumes prune`; change the delay with `latrix settings volume_retention_days=N`");
    }
    Ok(())
}

async fn unused_volumes(c: &Client, st: &StatusView) -> Vec<(String, crate::agent::volumes::UnusedVolume)> {
    let mut out = vec![];
    for m in st.machines.iter().filter(|m| m.alive) {
        if let Ok(list) = c
            .get::<Vec<crate::agent::volumes::UnusedVolume>>(&format!("/v1/m/{}/unused-volumes", m.machine.id))
            .await
        {
            out.extend(list.into_iter().map(|u| (m.machine.name.clone(), u)));
        }
    }
    out
}

async fn prune_volumes(cfg: &CliConfig, cl: Option<&str>, yes: bool) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    let st: StatusView = c.get("/v1/status").await?;
    let unused = unused_volumes(&c, &st).await;
    if unused.is_empty() {
        println!("nothing to prune: all volume data on the machines belongs to an app");
        return Ok(());
    }
    let total: u64 = unused.iter().map(|(_, u)| u.size_mb).sum();
    for (m, u) in &unused {
        println!("  {m}: {} ({} MB)", u.volume.replace("__", "/"), u.size_mb);
    }
    if !yes {
        print!("Delete this data ({total} MB)? [y/N] ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            bail!("aborted");
        }
    }
    let mut deleted_mb = 0u64;
    let mut failed = 0usize;
    for (m, u) in &unused {
        let Some(id) = st.machines.iter().find(|x| &x.machine.name == m).map(|x| x.machine.id) else {
            eprintln!("  ✗ {m}: machine not found in status");
            failed += 1;
            continue;
        };
        if !util::safe_id(&u.volume) {
            eprintln!("  ✗ {m}: refusing unsafe volume id '{}'", u.volume);
            failed += 1;
            continue;
        }
        let r = c
            .request(reqwest::Method::DELETE, &format!("/v1/m/{id}/unused-volumes?volume={}", u.volume))
            .send()
            .await?;
        if !r.status().is_success() {
            println!("  ✗ {m}: {}: {}", u.volume, r.text().await.unwrap_or_default().trim());
            failed += 1;
        } else {
            deleted_mb += u.size_mb;
        }
    }
    println!("deleted {deleted_mb} MB of unused volume data");
    if failed > 0 {
        bail!("{failed} unused volume(s) could not be deleted");
    }
    Ok(())
}

async fn app_volumes(c: &Client, app: &str) -> Result<Vec<VolumeView>> {
    let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
    if v.volumes.is_empty() {
        bail!("{app} has no volumes");
    }
    Ok(v.volumes)
}

async fn snapshots_list(cfg: &CliConfig, cl: Option<&str>, app: &str) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    for v in app_volumes(&c, app).await? {
        let list: Vec<crate::agent::volumes::SnapshotInfo> = c
            .get(&format!("/v1/m/{}/snapshots?volume={}", v.volume.primary, v.volume.id))
            .await
            .unwrap_or_default();
        println!("{app}/{} (on {}):", v.volume.name, v.primary_name);
        if list.is_empty() {
            println!("  no snapshots yet (one is taken every day; `latrix volumes snapshot {app}` takes one now)");
        }
        for s in list.iter().rev() {
            println!("  {}   +{} MB", s.name, s.size_mb);
        }
    }
    println!("\nroll back with: latrix volumes rollback {app} <snapshot>");
    Ok(())
}

async fn snapshot_now(cfg: &CliConfig, cl: Option<&str>, app: &str) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    for v in app_volumes(&c, app).await? {
        let r: serde_json::Value = c
            .post(&format!("/v1/m/{}/snapshots?volume={}&action=take", v.volume.primary, v.volume.id), &serde_json::json!({}))
            .await?;
        println!("{app}/{}: snapshot {}", v.volume.name, r["snapshot"].as_str().unwrap_or("?"));
    }
    Ok(())
}

async fn snapshot_rollback(cfg: &CliConfig, cl: Option<&str>, app: &str, snap: &str, only: Option<&str>, yes: bool) -> Result<()> {
    util::validate_name("app", app)?;
    if !util::safe_id(snap) {
        bail!("invalid snapshot name '{snap}'");
    }
    let (_, _, c) = connect(cfg, cl).await?;
    let vols: Vec<VolumeView> = app_volumes(&c, app)
        .await?
        .into_iter()
        .filter(|v| only.map(|o| o == v.volume.name).unwrap_or(true))
        .collect();
    if vols.is_empty() {
        bail!("no such volume");
    }
    if !yes {
        print!(
            "Put {} back to snapshot {snap}? Changes made since then are lost (`latrix volumes snapshot {app}` first keeps them). [y/N] ",
            vols.iter().map(|v| format!("{app}/{}", v.volume.name)).collect::<Vec<_>>().join(", ")
        );
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            bail!("aborted");
        }
    }
    let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
    let orig_scale = ScaleRequest {
        count: Some(v.count),
        min: v.autoscale.then_some(v.min),
        max: v.autoscale.then_some(v.max),
        ..Default::default()
    };
    println!("==> stopping {app}");
    let _: AppView = c.post(&format!("/v1/apps/{app}/scale"), &ScaleRequest { count: Some(0), ..Default::default() }).await?;
    let result: Result<()> = async {
        let start = std::time::Instant::now();
        loop {
            let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
            if v.instances.is_empty() {
                break;
            }
            if start.elapsed() > Duration::from_secs(180) {
                bail!("{app} did not stop within 180s");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        for vol in &vols {
            println!("==> restoring {app}/{} from {snap}", vol.volume.name);
            let r = c
                .request(
                    reqwest::Method::POST,
                    &format!("/v1/m/{}/snapshots?volume={}&action=restore&snapshot={snap}", vol.volume.primary, vol.volume.id),
                )
                .send()
                .await?;
            if !r.status().is_success() {
                bail!("{}: {}", vol.volume.name, r.text().await.unwrap_or_default().trim());
            }
        }
        Ok(())
    }
    .await;
    println!("==> starting {app}");
    let restart_res: Result<AppView> = c.post(&format!("/v1/apps/{app}/scale"), &orig_scale).await;
    if let Err(e) = result {
        if let Err(re) = restart_res {
            bail!("{e:#} (and failed to restart {app}: {re:#})");
        }
        return Err(e);
    }
    restart_res?;
    println!("✓ {app} is back on snapshot {snap}");
    Ok(())
}

async fn destroy(cfg: &CliConfig, cl: Option<&str>, a: DestroyArgs) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    let app = a.app.clone();
    let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
    let purge = !a.keep_volumes;
    let vol_desc: Vec<String> = v
        .volumes
        .iter()
        .map(|x| format!("{} ({} MB)", x.volume.name, x.report.as_ref().map(|r| r.size_mb).unwrap_or(0)))
        .collect();
    if !a.yes {
        let what = if vol_desc.is_empty() {
            String::new()
        } else if purge {
            format!(" and DELETE its volume data: {}", vol_desc.join(", "))
        } else {
            format!(" (keeping its volume data: {})", vol_desc.join(", "))
        };
        if !vol_desc.is_empty() && purge {
            println!("tip: `latrix backup {app}` first to keep a copy, or use --keep-volumes");
        }
        print!("Destroy app '{app}'{what}? Type the app name to confirm: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.trim() != app {
            bail!("aborted");
        }
    }
    let _: bool = c.delete(&format!("/v1/apps/{app}?purge_volumes={purge}")).await?;
    let tail = match (vol_desc.is_empty(), purge) {
        (true, _) => String::new(),
        (false, true) => format!(", deleted volume data: {}", vol_desc.join(", ")),
        (false, false) => format!(
            "; kept volume data {} (deploy {app} again to reuse it; otherwise it's deleted automatically after the retention period)",
            vol_desc.join(", ")
        ),
    };
    println!("destroyed {app}{tail}");
    Ok(())
}

async fn logs(cfg: &CliConfig, cl: Option<&str>, app: &str, follow: bool, tail: u32, only: Option<String>) -> Result<()> {
    util::validate_name("app", app)?;
    if let Some(ref o) = only {
        if !util::safe_id(o) {
            bail!("invalid instance id '{o}'");
        }
    }
    let (_, _, c) = connect(cfg, cl).await?;
    let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
    let insts: Vec<&InstanceView> = v
        .instances
        .iter()
        .filter(|i| only.as_ref().map(|o| &i.instance.id == o).unwrap_or(true))
        .collect();
    if insts.is_empty() {
        bail!("{app} has no instances");
    }
    let use_color = deploy::tty_width().is_some() && std::env::var_os("NO_COLOR").is_none();
    let colors = ["36", "35", "33", "32", "34", "31"];
    let mut streams = vec![];
    let mut prefixes: std::collections::HashMap<String, String> = Default::default();
    for (n, i) in insts.iter().enumerate() {
        let path = format!(
            "/v1/m/{}/logs?instance={}&tail={tail}&follow={follow}",
            i.instance.machine, i.instance.id
        );
        let resp = c.request(reqwest::Method::GET, &path).send().await?;
        if !resp.status().is_success() {
            eprintln!("({}: {})", i.instance.id, resp.text().await.unwrap_or_default().trim());
            continue;
        }
        let prefix = if use_color {
            format!("\x1b[{}m{}@{}\x1b[0m", colors[n % colors.len()], i.instance.id, i.machine_name)
        } else {
            format!("{}@{}", i.instance.id, i.machine_name)
        };
        let key = i.instance.id.clone();
        prefixes.insert(key.clone(), prefix);
        streams.push(resp.bytes_stream().map(move |b| (key.clone(), b)).boxed());
    }
    if streams.is_empty() {
        bail!("could not open logs for any instance of {app}");
    }
    let mut all = futures::stream::select_all(streams);
    let mut bufs: std::collections::HashMap<String, Vec<u8>> = Default::default();
    const MAX_LINE_BYTES: usize = 64 * 1024;
    while let Some((key, chunk)) = all.next().await {
        let Ok(chunk) = chunk else { continue };
        let buf = bufs.entry(key.clone()).or_default();
        buf.extend_from_slice(&chunk);
        while let Some(idx) = buf.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = buf.drain(..=idx).collect();
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            let prefix = prefixes.get(&key).map(|s| s.as_str()).unwrap_or(&key);
            println!("{prefix} {}", String::from_utf8_lossy(&line));
        }
        if buf.len() > MAX_LINE_BYTES {
            let prefix = prefixes.get(&key).map(|s| s.as_str()).unwrap_or(&key);
            let line = std::mem::take(buf);
            println!("{prefix} {}", String::from_utf8_lossy(&line));
        }
    }
    for (key, mut rem) in bufs {
        while matches!(rem.last(), Some(b'\n' | b'\r')) {
            rem.pop();
        }
        if !rem.is_empty() {
            let prefix = prefixes.get(&key).map(|s| s.as_str()).unwrap_or(&key);
            println!("{prefix} {}", String::from_utf8_lossy(&rem));
        }
    }
    Ok(())
}

async fn secrets(cfg: &CliConfig, cl: Option<&str>, s: SecretsCmd) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    match s {
        SecretsCmd::Set { app, pairs } => {
            util::validate_name("app", &app)?;
            if pairs.is_empty() {
                bail!("usage: latrix secrets set {app} KEY=value ...");
            }
            let timeout = app_health_timeout(&c, &app).await;
            let r: DeployResponse = c
                .post(&format!("/v1/apps/{app}/secrets"), &SecretsRequest { set: parse_pairs(&pairs)?, unset: vec![] })
                .await?;
            println!("secrets updated; rolling out v{}", r.version);
            deploy::watch(&c, &app, r.version, timeout).await
        }
        SecretsCmd::Unset { app, names } => {
            util::validate_name("app", &app)?;
            if names.is_empty() {
                bail!("usage: latrix secrets unset {app} KEY ...");
            }
            let timeout = app_health_timeout(&c, &app).await;
            let r: DeployResponse = c
                .post(&format!("/v1/apps/{app}/secrets"), &SecretsRequest { set: Default::default(), unset: names })
                .await?;
            println!("secrets removed; rolling out v{}", r.version);
            deploy::watch(&c, &app, r.version, timeout).await
        }
        SecretsCmd::List { app } => {
            util::validate_name("app", &app)?;
            let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
            for n in v.secret_names {
                println!("{n}");
            }
            Ok(())
        }
    }
}

async fn console(cfg: &CliConfig, cl: Option<&str>, app: &str, cmd: Vec<String>) -> Result<()> {
    util::validate_name("app", app)?;
    let (_, profile, c) = connect(cfg, cl).await?;
    let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
    let inst = v
        .instances
        .iter()
        .filter(|i| !i.instance.stopping)
        .max_by_key(|i| i.report.as_ref().map(|r| r.healthy).unwrap_or(false))
        .ok_or_else(|| anyhow!("{app} has no running instances"))?;
    let name = agent::runtime::container_name(app, &inst.instance.id);
    let inner = if cmd.is_empty() { vec!["sh".to_string()] } else { cmd };
    let tty_flag = if std::io::IsTerminal::is_terminal(&std::io::stdin())
        && std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        "-it"
    } else {
        "-i"
    };
    let mut docker = vec!["docker".to_string(), "exec".into(), tty_flag.into(), name];
    docker.extend(inner);
    if profile.local {
        let st = std::process::Command::new(&docker[0]).args(&docker[1..]).status()?;
        std::process::exit(st.code().unwrap_or(1));
    }
    // Reload local config after connect() synced any autopilot-added machines.
    let fresh_cfg = CliConfig::load().unwrap_or_else(|_| cfg.clone());
    let ssh = machine::find_ssh(&fresh_cfg, cl, &inst.machine_name)?;
    let line = docker.iter().map(|a| util::shell_quote(a)).collect::<Vec<_>>().join(" ");
    drop(c);
    let st = ssh.interactive(Some(&line))?;
    std::process::exit(st.code().unwrap_or(1));
}

async fn machine_cmd(cfg: &mut CliConfig, cl: Option<&str>, m: MachineCmd) -> Result<()> {
    match m {
        MachineCmd::Add { target, name, port, key, region, public_ip, agent_binary } => {
            machine::add(
                cfg,
                cl,
                machine::AddOptions { target, name, port, key, region, public_ip, agent_binary, provider: None, monthly_cost: None },
            )
            .await
        }
        MachineCmd::Create { provider, size, region, min_memory, image, name, key, agent_binary } => {
            let opts = CreateOptions { provider, size, region, min_memory, image, name, key, agent_binary };
            create_machine(cfg, cl, opts).await
        }
        MachineCmd::List => {
            let (_, _, c) = connect(cfg, cl).await?;
            machine::list(&c).await
        }
        MachineCmd::Remove { name, force, destroy } => machine::remove(cfg, cl, &name, force, destroy).await,
        MachineCmd::Drain { name } => {
            let (_, _, c) = connect(cfg, cl).await?;
            machine::action(&c, &name, "drain").await?;
            machine::wait_status(&c, &name, &["cordoned"], Duration::from_secs(900)).await
        }
        MachineCmd::Cordon { name } => {
            let (_, _, c) = connect(cfg, cl).await?;
            machine::action(&c, &name, "cordon").await
        }
        MachineCmd::Uncordon { name } => {
            let (_, _, c) = connect(cfg, cl).await?;
            machine::action(&c, &name, "uncordon").await
        }
        MachineCmd::Update { name } => {
            let (_, _, c) = connect(cfg, cl).await?;
            machine::action(&c, &name, "update").await
        }
        MachineCmd::Ssh { name } => {
            let ssh = match machine::find_ssh(cfg, cl, &name) {
                Ok(s) => s,
                Err(_) => {
                    // Sync autopilot-added machines from the cluster and retry once.
                    if let Ok((_, _, c)) = connect(cfg, cl).await {
                        drop(c);
                        if let Ok(fresh) = CliConfig::load() {
                            *cfg = fresh;
                        }
                    }
                    machine::find_ssh(cfg, cl, &name)?
                }
            };
            let st = ssh.interactive(None)?;
            std::process::exit(st.code().unwrap_or(0));
        }
    }
}

async fn dashboard(cfg: &CliConfig, cl: Option<&str>, port: u16, no_open: bool) -> Result<()> {
    let (_, p) = cfg.profile(cl)?;
    let open = |url: &str| {
        if no_open {
            return;
        }
        let opener = if cfg!(target_os = "macos") {
            "open"
        } else if cfg!(target_os = "windows") {
            "explorer"
        } else {
            "xdg-open"
        };
        let _ = std::process::Command::new(opener)
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    };
    if p.local {
        let url = format!("http://127.0.0.1:{}/", util::API_PORT);
        println!("dashboard: {url}");
        open(&url);
        return Ok(());
    }
    let probe = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut last = None;
    for m in &p.machines {
        match Tunnel::open(m, Some(port)) {
            Ok(mut t) => {
                let ping_url = format!("http://127.0.0.1:{}/v1/local/ping", t.port);
                match probe.get(&ping_url).send().await {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) => {
                        last = Some(anyhow!("agent on {} returned HTTP {}", m.name, r.status()));
                        continue;
                    }
                    Err(e) => {
                        last = Some(anyhow!("agent on {} not reachable over tunnel: {e}", m.name));
                        continue;
                    }
                }
                let url = format!("http://127.0.0.1:{}/", t.port);
                println!("dashboard: {url}  (via {}, Ctrl-C to close)", m.name);
                open(&url);
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        res = tokio::signal::ctrl_c() => {
                            res?;
                            break;
                        }
                        _ = tick.tick() => {
                            if let Some(st) = t.exited() {
                                bail!("SSH tunnel to {} closed unexpectedly ({st})", m.name);
                            }
                        }
                    }
                }
                drop(t);
                return Ok(());
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no machines"))).context("could not open a tunnel to any machine")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_app(name: &str, group: Option<&str>, cpu: f64, mem: &str, healthy: bool, url: Option<&str>) -> AppView {
        AppView {
            name: name.into(),
            group: group.map(String::from),
            current: 1,
            release_status: Some(crate::state::ReleaseStatus::Active),
            image: "img:1".into(),
            count: 1,
            min: 1,
            max: 1,
            autoscale: false,
            stateful: false,
            cpu,
            memory: mem.into(),
            urls: url.map(|u| vec![u.into()]).unwrap_or_default(),
            internal: vec![],
            instances: vec![InstanceView {
                instance: crate::state::Instance {
                    id: "i1".into(),
                    app: name.into(),
                    release: 1,
                    machine: 1,
                    created_at: 1,
                    stopping: false,
                    stopping_since: 0,
                    replaces: None,
                },
                machine_name: "m1".into(),
                report: Some(crate::state::InstanceReport {
                    id: "i1".into(),
                    status: "running".into(),
                    healthy,
                    ..Default::default()
                }),
            }],
            releases: vec![],
            volumes: vec![],
            secret_names: vec![],
            config: None,
            dns_records: vec![],
        }
    }

    #[test]
    fn fluxer_services_collapse_into_one_entry() {
        let st = StatusView {
            cluster: "c".into(),
            version: 1,
            leader: Some(1),
            dev: false,
            settings: Default::default(),
            machines: vec![],
            apps: vec![
                mk_app("blog", None, 0.5, "256MB", true, Some("https://blog.example.com")),
                mk_app("fluxer-api", Some("fluxer"), 0.5, "1536MB", true, None),
                mk_app("fluxer-edge", Some("fluxer"), 0.25, "384MB", true, Some("https://chat.example.com")),
                mk_app("fluxer-postgres", Some("fluxer"), 1.0, "2GB", false, None),
            ],
            certs: vec![],
            events: vec![],
            monthly_cost: 0.0,
            autopilot: None,
            certs_pending: vec![],
            dns: None,
            fluxer: Some(FluxerSummary {
                project: "fluxer".into(),
                domain: "chat.example.com".into(),
                release: "2026.1124.80040".into(),
                auto_upgrade: true,
                services: vec!["api".into(), "edge".into(), "postgres".into()],
            }),
        };
        let (regular, fluxer, fx) = partition_fluxer_apps(&st);
        assert_eq!(regular.len(), 1);
        assert_eq!(regular[0].name, "blog");
        assert_eq!(fluxer.len(), 3);
        let (h, total, state, cpu, mem_mb, url) = fluxer_rollup(fx.unwrap(), &fluxer);
        assert_eq!((h, total), (2, 3));
        assert_eq!(state, "degraded");
        assert!((cpu - 1.75).abs() < 0.001);
        assert_eq!(mem_mb, 1536 + 384 + 2048);
        assert_eq!(url, "https://chat.example.com");
        assert_eq!(format_mem_mb(mem_mb), "3.9GB");
    }
}
