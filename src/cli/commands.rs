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
    let name = o.name.unwrap_or_else(|| format!("{}-{}", offer.location, util::random_id(4)));
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
    .await?;
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

pub async fn run(cli: Cli) -> Result<()> {
    let cl = cli.cluster.as_deref();
    match cli.cmd {
        Cmd::Agent(a) => return agent_cmd(a).await,
        Cmd::Launch { name, image, port, force } => return deploy::launch(name, image, port, force),
        Cmd::Dev { data } => return dev(data).await,
        Cmd::Compose(ComposeCmd::Convert { file, write }) => return compose_convert(&file, write),
        Cmd::Cluster(c) => return cluster_cmd(c),
        Cmd::Provider(p) => return provider_cmd(p).await,
        Cmd::K8s(k) => return k8s::k8s_cmd(cl, k).await,
        _ => {}
    }
    let mut cfg = CliConfig::load()?;
    if let Ok((name, p)) = cfg.profile(cl) {
        if let Some(t) = p.kubernetes {
            return k8s::dispatch(&cfg, &name, t, cli.cmd).await;
        }
    }
    match cli.cmd {
        Cmd::Deploy(args) => deploy_cmd(&cfg, cl, args).await,
        Cmd::Status => status(&cfg, cl).await,
        Cmd::Apps { action } => match action {
            None | Some(AppsCmd::List) => apps(&cfg, cl).await,
            Some(AppsCmd::Show { app }) => ps(&cfg, cl, &app).await,
            Some(AppsCmd::Destroy(a)) => destroy(&cfg, cl, a).await,
        },
        Cmd::Ps { app } => ps(&cfg, cl, &app).await,
        Cmd::Logs { app, follow, tail, instance } => logs(&cfg, cl, &app, follow, tail, instance).await,
        Cmd::Scale { app, count, min, max, cpu, memory } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            if count.is_none() && min.is_none() && max.is_none() && cpu.is_none() && memory.is_none() {
                bail!("nothing to change: pass a count (latrix scale {app} 3) or --min/--max/--cpu/--memory");
            }
            let v: AppView = c
                .post(&format!("/v1/apps/{app}/scale"), &ScaleRequest { count, min, max, cpu, memory })
                .await?;
            if v.autoscale {
                println!("{app}: autoscaling between {} and {} (now {})", v.min, v.max, v.count);
            } else {
                println!("{app}: {} instance(s), {} CPU, {} each", v.count, v.cpu, v.memory);
            }
            Ok(())
        }
        Cmd::Restart { app } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let r: DeployResponse = c.post(&format!("/v1/apps/{app}/restart"), &serde_json::json!({})).await?;
            deploy::watch(&c, &app, r.version, 120).await
        }
        Cmd::Rollback { app, version } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let r: DeployResponse = c.post(&format!("/v1/apps/{app}/rollback"), &RollbackRequest { version }).await?;
            deploy::watch(&c, &app, r.version, 120).await
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
        Cmd::Machine(m) => machine_cmd(&mut cfg, cl, m).await,
        Cmd::Volumes { action } => match action {
            None | Some(VolumesCmd::List) => volumes(&cfg, cl).await,
            Some(VolumesCmd::Prune { yes }) => prune_volumes(&cfg, cl, yes).await,
        },
        Cmd::Doctor { machine } => doctor::doctor(&cfg, cl, machine.as_deref()).await,
        Cmd::Backup { apps, all, out, no_image, stop } => backup::backup(&cfg, cl, apps, all, out, no_image, stop).await,
        Cmd::Restore { file, as_name } => backup::restore(&cfg, cl, &file, as_name).await,
        Cmd::Import(ImportCmd::Fly { app, as_name, no_data, no_secrets, from_source }) => {
            fly::import(&cfg, cl, fly::ImportOptions { fly_app: app, name: as_name, no_data, no_secrets, from_source }).await
        }
        Cmd::Certs { .. } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let st: StatusView = c.get("/v1/status").await?;
            let rows = st
                .certs
                .iter()
                .map(|x| {
                    vec![
                        x.domain.clone(),
                        ago(x.issued_at),
                        format!("in {}", human_duration(x.not_after.saturating_sub(util::now()))),
                    ]
                })
                .collect();
            print_table(&["DOMAIN", "ISSUED", "EXPIRES"], rows);
            if st.certs.is_empty() {
                println!("(no certificates yet — add [http] domains to an app and point DNS at any machine)");
            }
            Ok(())
        }
        Cmd::Events { .. } => {
            let (_, _, c) = connect(&cfg, cl).await?;
            let ev: Vec<crate::state::Event> = c.get("/v1/events").await?;
            for e in ev {
                println!("{:>8}  {:<4}  {}", ago(e.ts), e.level, e.message);
            }
            Ok(())
        }
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
            let has_cluster = cfg
                .profile(cl)
                .map(|(_, p)| !p.local && p.kubernetes.is_none() && !p.machines.is_empty())
                .unwrap_or(false);
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
    }
    Ok(())
}

async fn provider_cmd(p: ProviderCmd) -> Result<()> {
    let mut cfg = CliConfig::load()?;
    match p {
        ProviderCmd::Set { provider, token } => {
            let p = providers::canonical(&provider)?;
            cfg.providers.insert(p.into(), token);
            cfg.save()?;
            println!("saved {p} token in {}", CliConfig::path().display());
        }
        ProviderCmd::Sizes { provider } => {
            let p = providers::canonical(&provider)?;
            providers::sizes(p, &providers::token(&cfg, p)?).await?;
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

async fn status(cfg: &CliConfig, cl: Option<&str>) -> Result<()> {
    let (name, _, c) = connect(cfg, cl).await?;
    let st: StatusView = c.get("/v1/status").await?;
    let leader = st
        .leader
        .and_then(|l| st.machines.iter().find(|m| m.machine.id == l))
        .map(|m| m.machine.name.clone())
        .unwrap_or_else(|| "?".into());
    let mut head = format!(
        "Cluster '{name}' · leader {leader} · {} machine(s) · {} app(s)",
        st.machines.len(),
        st.apps.len()
    );
    if st.monthly_cost > 0.0 {
        head.push_str(&format!(" · est. {:.2}/month", st.monthly_cost));
        if st.settings.monthly_budget > 0.0 && st.monthly_cost > st.settings.monthly_budget {
            head.push_str(&format!(" (over budget of {:.2}!)", st.settings.monthly_budget));
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
            vec![
                format!("{}{}", m.machine.name, if m.leader { " *" } else { "" }),
                if m.alive { m.machine.status.to_string() } else { "DOWN".into() },
                format!("cpu {} {:>3.0}%", bar(met.cpu_pct / 100.0), met.cpu_pct),
                format!("mem {} {:>3.0}%", bar(mem), mem * 100.0),
                format!("{} inst", m.instances),
                m.updates
                    .as_ref()
                    .filter(|u| u.pending > 0 || u.reboot_required)
                    .map(|u| format!("{} updates", u.pending))
                    .unwrap_or_default(),
            ]
        })
        .collect();
    print_table(&["NAME", "STATUS", "CPU", "MEMORY", "INSTANCES", "UPDATES"], rows);
    println!("\nAPPS");
    if st.apps.is_empty() {
        println!("  (none yet — `latrix launch` then `latrix deploy`)");
    } else {
        let rows = st
            .apps
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

async fn apps(cfg: &CliConfig, cl: Option<&str>) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    let st: StatusView = c.get("/v1/status").await?;
    let rows = st
        .apps
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
    let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
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
        let rows = unused
            .iter()
            .map(|(m, u)| {
                vec![
                    m.clone(),
                    u.volume.replace("__", "/"),
                    format!("{} MB", u.size_mb),
                    ago(u.unused_since),
                    if u.delete_at <= util::now() {
                        "on the next scan".into()
                    } else {
                        format!("in {}", human_duration(u.delete_at - util::now()))
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
    for (m, u) in &unused {
        let id = st.machines.iter().find(|x| &x.machine.name == m).map(|x| x.machine.id).unwrap_or(0);
        let r = c
            .request(reqwest::Method::DELETE, &format!("/v1/m/{id}/unused-volumes?volume={}", u.volume))
            .send()
            .await?;
        if !r.status().is_success() {
            println!("  ✗ {m}: {}: {}", u.volume, r.text().await.unwrap_or_default());
        }
    }
    println!("deleted {total} MB of unused volume data");
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
    let colors = ["36", "35", "33", "32", "34", "31"];
    let mut streams = vec![];
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
        let prefix = format!("\x1b[{}m{}@{}\x1b[0m", colors[n % colors.len()], i.instance.id, i.machine_name);
        streams.push(resp.bytes_stream().map(move |b| (prefix.clone(), b)).boxed());
    }
    let mut all = futures::stream::select_all(streams);
    let mut bufs: std::collections::HashMap<String, String> = Default::default();
    while let Some((prefix, chunk)) = all.next().await {
        let Ok(chunk) = chunk else { continue };
        let buf = bufs.entry(prefix.clone()).or_default();
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(idx) = buf.find('\n') {
            let line: String = buf.drain(..=idx).collect();
            println!("{prefix} {}", line.trim_end());
        }
    }
    Ok(())
}

async fn secrets(cfg: &CliConfig, cl: Option<&str>, s: SecretsCmd) -> Result<()> {
    let (_, _, c) = connect(cfg, cl).await?;
    match s {
        SecretsCmd::Set { app, pairs } => {
            if pairs.is_empty() {
                bail!("usage: latrix secrets set {app} KEY=value ...");
            }
            let r: DeployResponse = c
                .post(&format!("/v1/apps/{app}/secrets"), &SecretsRequest { set: parse_pairs(&pairs)?, unset: vec![] })
                .await?;
            println!("secrets updated; rolling out v{}", r.version);
            deploy::watch(&c, &app, r.version, 120).await
        }
        SecretsCmd::Unset { app, names } => {
            let r: DeployResponse = c
                .post(&format!("/v1/apps/{app}/secrets"), &SecretsRequest { set: Default::default(), unset: names })
                .await?;
            println!("secrets removed; rolling out v{}", r.version);
            deploy::watch(&c, &app, r.version, 120).await
        }
        SecretsCmd::List { app } => {
            let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
            for n in v.secret_names {
                println!("{n}");
            }
            Ok(())
        }
    }
}

async fn console(cfg: &CliConfig, cl: Option<&str>, app: &str, cmd: Vec<String>) -> Result<()> {
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
    let mut docker = vec!["docker".to_string(), "exec".into(), "-it".into(), name];
    docker.extend(inner);
    if profile.local {
        let st = std::process::Command::new(&docker[0]).args(&docker[1..]).status()?;
        std::process::exit(st.code().unwrap_or(1));
    }
    let ssh = machine::find_ssh(cfg, cl, &inst.machine_name)?;
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
            let ssh = machine::find_ssh(cfg, cl, &name)?;
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
    let mut last = None;
    for m in &p.machines {
        match Tunnel::open(m, Some(port)) {
            Ok(t) => {
                let url = format!("http://127.0.0.1:{}/", t.port);
                println!("dashboard: {url}  (via {}, Ctrl-C to close)", m.name);
                open(&url);
                tokio::signal::ctrl_c().await?;
                drop(t);
                return Ok(());
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no machines"))).context("could not open a tunnel to any machine")
}
