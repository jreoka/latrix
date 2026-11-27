//! `latrix rexctl` — deploy, restore, back up, upgrade and auto-manage a
//! self-hosted Fluxer stack on a latrix cluster.

use super::backup;
use super::client::Client;
use super::deploy;
use super::profile::CliConfig;
use super::{RexctlCmd, RexctlConfigCmd};
use crate::api_types::*;
use crate::fluxer::{self, ServiceSpec};
use crate::state::FluxerStack;
use crate::util::{self, ago, print_table};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn mb(n: u64) -> String {
    format!("{:.1} MB", n as f64 / 1_048_576.0)
}

async fn connect_latrix(cfg: &CliConfig, cl: Option<&str>) -> Result<Client> {
    let (_, p) = cfg.profile(cl)?;
    if p.kubernetes.is_some() {
        bail!("`latrix rexctl` targets latrix clusters (not Kubernetes profiles)");
    }
    Client::connect(&p).await
}

/// Run a shell command inside a running container on `machine` via `/v1/m/{id}/exec`,
/// optionally streaming `stdin_file` to stdin and writing stdout to `stdout_file`.
async fn exec_in_app(
    c: &Client,
    machine: u32,
    app: &str,
    shell_cmd: &str,
    stdin_file: Option<&Path>,
    stdout_file: Option<&Path>,
) -> Result<String> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(shell_cmd.as_bytes());
    let path = format!("/v1/m/{machine}/exec?app={app}");
    let mut rb = c
        .request(reqwest::Method::POST, &path)
        .header("x-latrix-exec", encoded)
        .timeout(Duration::from_secs(1800));
    if let Some(file) = stdin_file {
        let f = tokio::fs::File::open(file).await?;
        rb = rb.body(reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(f)));
    }
    let resp = rb.send().await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<ApiErrorBody>(&body)
            .map(|e| e.error)
            .unwrap_or(body);
        bail!("{status}: {msg}");
    }
    if let Some(dest) = stdout_file {
        let mut f = std::fs::File::create(dest)?;
        let mut s = resp.bytes_stream();
        while let Some(chunk) = s.next().await {
            let chunk = chunk?;
            f.write_all(&chunk)?;
        }
        f.flush()?;
        Ok(String::new())
    } else {
        Ok(resp.text().await.unwrap_or_default())
    }
}

async fn find_running_machine(c: &Client, app: &str) -> Result<u32> {
    let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
    v.instances
        .iter()
        .filter(|i| !i.instance.stopping)
        .max_by_key(|i| i.report.as_ref().map(|r| r.healthy).unwrap_or(false))
        .map(|i| i.instance.machine)
        .ok_or_else(|| anyhow!("{app} has no running instance"))
}

async fn wait_pg_ready(c: &Client, machine: u32, pg_app: &str) -> Result<()> {
    let start = Instant::now();
    loop {
        if exec_in_app(
            c,
            machine,
            pg_app,
            r#"pg_isready -h 127.0.0.1 -U "${POSTGRES_USER:-fluxer}" -d "${POSTGRES_DB:-fluxer}""#,
            None,
            None,
        )
        .await
        .is_ok()
        {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(120) {
            bail!("{pg_app} did not pass pg_isready within 2 minutes");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn wait_app_stopped(c: &Client, name: &str) -> Result<()> {
    let start = Instant::now();
    loop {
        let v: AppView = c.get(&format!("/v1/apps/{name}")).await?;
        if v.instances.is_empty() {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(60) {
            bail!("timed out waiting for existing instances of {name} to stop before volume upload");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

struct RemoveFileGuard(PathBuf);
impl Drop for RemoveFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Deploy one `ServiceSpec`, optionally pre-seeding a backed-up volume before starting.
async fn deploy_service(
    c: &Client,
    spec: &ServiceSpec,
    volume_src_dir: Option<&Path>,
    work_dir: &Path,
    description: &str,
) -> Result<()> {
    let name = &spec.config.app;
    let has_vol_data = volume_src_dir.is_some();
    let needs_staging = has_vol_data || !spec.secrets.is_empty();

    if needs_staging {
        // 1. Create the app stopped so volumes exist and secrets can be set before first start.
        let mut stopped = spec.config.clone();
        stopped.scale.count = Some(0);
        stopped.scale.min = None;
        stopped.scale.max = None;
        let _: DeployResponse = c
            .post(
                &format!("/v1/apps/{name}/deploy"),
                &DeployRequest {
                    config: stopped,
                    image: spec.image.clone(),
                    builder: None,
                    description: format!("{description} (prepare)"),
                },
            )
            .await?;

        // 2. Upload secrets
        if !spec.secrets.is_empty() {
            let _: DeployResponse = c
                .post(
                    &format!("/v1/apps/{name}/secrets"),
                    &SecretsRequest {
                        set: spec.secrets.clone(),
                        unset: vec![],
                    },
                )
                .await?;
        }

        // 3. Upload backed-up volume data onto the primary machine
        if let (Some(src_dir), Some((_, vol_name))) = (volume_src_dir, &spec.backup_volume) {
            wait_app_stopped(c, name).await?;
            let v: AppView = c.get(&format!("/v1/apps/{name}")).await?;
            if let Some(vol) = v.volumes.iter().find(|x| &x.volume.name == vol_name) {
                let tgz = work_dir.join(format!("upload-{name}-{vol_name}.tar.gz"));
                let _rm = RemoveFileGuard(tgz.clone());
                let sz = fluxer::pack_dir_targz(src_dir, &tgz)?;
                println!(
                    "    uploading volume {vol_name} ({}) → {}",
                    mb(sz),
                    vol.primary_name
                );
                backup::upload(
                    c,
                    &format!(
                        "/v1/m/{}/volume-data?volume={}",
                        vol.volume.primary, vol.volume.id
                    ),
                    &tgz,
                )
                .await?;
            }
        }
    }

    // Start for real and watch health.
    let resp: DeployResponse = c
        .post(
            &format!("/v1/apps/{name}/deploy"),
            &DeployRequest {
                config: spec.config.clone(),
                image: spec.image.clone(),
                builder: None,
                description: description.to_string(),
            },
        )
        .await?;
    deploy::watch(c, name, resp.version, spec.config.deploy.health_timeout_secs()).await
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

pub fn inspect(file: &Path, skip_verify: bool) -> Result<()> {
    let ext = fluxer::extract_and_verify_backup(file, !skip_verify)?;
    let res = (|| -> Result<()> {
        let stack = ext.to_stack(None, None, None, true, None, 2)?;
        println!("Fluxer rexctl backup: {}", file.display());
        println!("  format:     {}", ext.manifest.format);
        println!("  project:    {}", stack.project);
        println!("  domain:     {}", stack.domain);
        println!(
            "  release:    {}",
            if stack.release.is_empty() { "(unknown)" } else { &stack.release }
        );
        if !ext.manifest.created_at.is_empty() {
            println!("  created:    {}", ext.manifest.created_at);
        }
        if !ext.manifest.scope.is_empty() {
            println!("  scope:      {}", ext.manifest.scope);
        }
        if let Some(r) = &ext.manifest.reason {
            if !r.is_empty() {
                println!("  reason:     {r}");
            }
        }
        println!("  storage:    {}", fluxer::storage_summary(&stack));
        println!(
            "  voice:      {}",
            if stack.bundled_voice { "bundled LiveKit" } else { "external / disabled" }
        );
        println!(
            "  kv mode:    {}",
            if stack.kv_postgres { "postgres" } else { "valkey" }
        );
        println!(
            "  rust mode:  {}",
            if stack.rust_single { "single (fluxer-server)" } else { "per-service" }
        );
        if ext.is_native {
            println!("  runtime:    native (will be converted to container stack on deploy)");
        }
        if !skip_verify {
            println!("  verified:   {} file(s) matched SHA256", ext.verified_entries);
        }
        if ext.postgres_dump.is_some() {
            println!("  database:   postgres/fluxer.dump ({})", mb(ext.postgres_dump_size));
        } else {
            println!("  database:   (not included in backup)");
        }
        if ext.volumes.is_empty() {
            println!("  volumes:    (none)");
        } else {
            let names: Vec<String> = ext.volumes.keys().cloned().collect();
            println!("  volumes:    {}", names.join(", "));
        }
        println!(
            "  settings:   {} setting(s), {} secret(s)",
            stack.settings.len(),
            stack.secrets.len()
        );
        if ext.manifest.scope == "without-uploads" && !stack.external_object_store {
            println!("\n  note: this backup was created without uploads (external S3/R2 uploads are unaffected).");
        }
        Ok(())
    })();
    ext.cleanup();
    res
}

pub struct DeployBackupOptions {
    pub file: PathBuf,
    pub project: Option<String>,
    pub domain: Option<String>,
    pub release: Option<String>,
    pub auto_upgrade: bool,
    pub copies: u32,
    pub region: Option<String>,
    pub skip_verify: bool,
    pub replace: bool,
    pub dry_run: bool,
}

pub async fn deploy_backup(cfg: &CliConfig, cl: Option<&str>, opts: DeployBackupOptions) -> Result<()> {
    println!(
        "{} Reading {} {}",
        deploy::arrow(),
        opts.file.display(),
        if opts.skip_verify { "(skipping SHA256 verify)" } else { "(verifying SHA256)" }
    );
    let ext = fluxer::extract_and_verify_backup(&opts.file, !opts.skip_verify)?;
    let res = deploy_backup_inner(cfg, cl, opts, &ext).await;
    ext.cleanup();
    res
}

async fn deploy_backup_inner(
    cfg: &CliConfig,
    cl: Option<&str>,
    opts: DeployBackupOptions,
    ext: &fluxer::ExtractedBackup,
) -> Result<()> {
    let mut stack = ext.to_stack(
        opts.project.as_deref(),
        opts.domain.as_deref(),
        opts.release.as_deref(),
        opts.auto_upgrade,
        opts.region.clone(),
        opts.copies,
    )?;

    if ext
        .state
        .as_ref()
        .and_then(|s| s.settings.get("storage.backend"))
        .map(|b| b.eq_ignore_ascii_case("filesystem"))
        .unwrap_or(false)
    {
        println!("    ! warning: backup uses storage.backend=filesystem; multi-machine clusters work best with Cloudflare R2 / S3 or SeaweedFS.");
    }

    // Resolve pinned images from release compose bundle if needed.
    let mut bundle_images = ext.compose_images.clone();
    let want_bundle = opts.release.is_some() || bundle_images.len() < 8;
    if want_bundle {
        let http = reqwest::Client::new();
        let target = if stack.release.is_empty() {
            None
        } else {
            Some(stack.release.as_str())
        };
        println!(
            "{} Resolving Fluxer release {}...",
            deploy::arrow(),
            target.unwrap_or("latest")
        );
        match fluxer::resolve_release(&http, target).await {
            Ok(rel) => {
                if opts.release.is_some() {
                    fluxer::check_upgrade_path(&ext.release(), &rel)?;
                }
                if stack.release.is_empty() || opts.release.is_some() {
                    stack.release = rel.version.clone();
                }
                if !rel.compose_url.is_empty() {
                    println!("    downloading compose manifest for Fluxer {}", rel.version);
                    match fluxer::fetch_compose_bundle(&http, &rel.compose_url).await {
                        Ok(b) => {
                            for (k, v) in b.images {
                                bundle_images.insert(k, v);
                            }
                            if ext.caddyfile.is_none() {
                                if let Some(cf) = b.caddyfile {
                                    stack.caddyfile = cf;
                                    stack.caddyfile_custom = false;
                                }
                            }
                        }
                        Err(e) => {
                            if opts.release.is_some() {
                                return Err(e).context("downloading compose bundle for requested --release");
                            }
                            println!("    ! could not download compose bundle (falling back to defaults): {e:#}");
                        }
                    }
                }
            }
            Err(e) => {
                if opts.release.is_some() {
                    return Err(e);
                }
                println!("    ! release lookup skipped (using backup/default images): {e:#}");
            }
        }
    }
    stack.image_overrides = bundle_images.clone();

    let specs = fluxer::plan_stack(&stack, &bundle_images)?;
    stack.services = fluxer::service_names_from_plan(&specs);

    println!("\nFluxer deployment plan:");
    println!("  project:      {}", stack.project);
    println!("  domain:       https://{}", stack.domain);
    println!(
        "  release:      {}",
        if stack.release.is_empty() { "(default)" } else { &stack.release }
    );
    println!("  storage:      {}", fluxer::storage_summary(&stack));
    let voice_desc = if let Some(lk) = specs.iter().find(|s| s.service == "livekit") {
        let ports: Vec<String> = lk
            .config
            .ports
            .iter()
            .filter(|p| p.public)
            .map(|p| format!("{} {}", p.protocol.to_ascii_uppercase(), p.public_port.unwrap_or(p.port)))
            .collect();
        if ports.is_empty() {
            "bundled LiveKit".into()
        } else {
            format!("bundled LiveKit ({})", ports.join(", "))
        }
    } else {
        "external".into()
    };
    println!("  voice:        {voice_desc}");
    println!(
        "  kv / rust:    {} / {}",
        if stack.kv_postgres { "postgres" } else { "valkey" },
        if stack.rust_single { "single" } else { "per-service" }
    );
    println!(
        "  auto-upgrade: {}",
        if stack.auto_upgrade { "on (cluster leader checks every 6h)" } else { "off" }
    );
    println!(
        "  database:     {}",
        if ext.postgres_dump.is_some() {
            format!("restore postgres/fluxer.dump ({})", mb(ext.postgres_dump_size))
        } else {
            "fresh database".into()
        }
    );
    println!("  services:     {} apps\n", specs.len());

    if opts.dry_run {
        let rows: Vec<Vec<String>> = specs
            .iter()
            .map(|s| {
                vec![
                    format!("T{}", s.tier),
                    s.service.clone(),
                    s.config.app.clone(),
                    s.config.scale.memory.clone(),
                    s.secrets.len().to_string(),
                    s.image.clone(),
                ]
            })
            .collect();
        print_table(&["TIER", "SERVICE", "APP", "MEMORY", "SECRETS", "IMAGE"], rows);
        println!("\n(dry run — nothing was deployed)");
        return Ok(());
    }

    let c = connect_latrix(cfg, cl).await?;
    let existing: RexctlStatusView = c.get("/v1/rexctl").await?;
    if existing.installed {
        if !opts.replace {
            bail!(
                "a Fluxer stack ('{}' on {}) is already managed on this cluster. Pass --replace to replace it, or run `latrix rexctl destroy` first.",
                existing.project,
                existing.domain
            );
        }
        println!("{} Replacing existing Fluxer stack '{}'...", deploy::arrow(), existing.project);
        destroy_apps(&c, &existing, true).await?;
        // Wait briefly for stopped containers and purged volumes to drain before recreating.
        let wait_start = Instant::now();
        while wait_start.elapsed() < Duration::from_secs(60) {
            let Ok(st) = c.get::<StatusView>("/v1/status").await else { break };
            let still_running = st.apps.iter().any(|a| {
                a.config.as_ref().and_then(|c| c.group.as_deref()) == Some(existing.project.as_str())
                    && !a.instances.is_empty()
            });
            if !still_running {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    let desc = format!(
        "rexctl deploy{}",
        if stack.release.is_empty() { String::new() } else { format!(" ({})", stack.release) }
    );

    // Deploy tier by tier so infra & database are restored before apps boot.
    for tier in 1..=4u8 {
        let tier_label = match tier {
            1 => "infrastructure & voice",
            2 => "Rust microservices",
            3 => "Fluxer application services",
            _ => "edge ingress",
        };
        println!("\n{} Tier {tier}: {tier_label}", deploy::arrow());

        for spec in specs.iter().filter(|s| s.tier == tier) {
            let vol_src = spec
                .backup_volume
                .as_ref()
                .and_then(|(short, _)| ext.volumes.get(short))
                .map(|p| p.as_path());

            println!("{} Deploying {} ({})", deploy::arrow(), spec.config.app, spec.service);
            deploy_service(&c, spec, vol_src, &ext.work_dir, &desc).await?;

            // Restore Postgres dump immediately after postgres starts and before any app connects.
            if spec.service == "postgres" {
                let m = find_running_machine(&c, &spec.config.app).await?;
                println!("    waiting for PostgreSQL to accept connections...");
                wait_pg_ready(&c, m, &spec.config.app).await?;
                if let Some(dump) = &ext.postgres_dump {
                    println!(
                        "    restoring postgres/fluxer.dump ({}) into {}...",
                        mb(ext.postgres_dump_size),
                        spec.config.app
                    );
                    exec_in_app(
                        &c,
                        m,
                        &spec.config.app,
                        r#"PGPASSWORD="${POSTGRES_PASSWORD:-}" exec pg_restore -h 127.0.0.1 -U "${POSTGRES_USER:-fluxer}" -d "${POSTGRES_DB:-fluxer}" --no-owner --no-privileges --exit-on-error --single-transaction"#,
                        Some(dump),
                        None,
                    )
                    .await
                    .context("pg_restore failed")?;
                    println!("    ✓ database restored");
                }
            }

            // Initialize SeaweedFS buckets & credentials once if running bundled SeaweedFS.
            if spec.service == "seaweedfs" {
                let m = find_running_machine(&c, &spec.config.app).await?;
                println!("    initializing SeaweedFS buckets and S3 credentials...");
                let eff = fluxer::effective_env(&stack);
                let script = fluxer::seaweedfs_init_script(&eff)?;
                exec_in_app(&c, m, &spec.config.app, &script, None, None)
                    .await
                    .context("seaweedfs-init failed")?;
                println!("    ✓ SeaweedFS buckets ready");
            }
        }
    }

    // Register managed Fluxer stack in cluster state so the leader auto-manages & auto-upgrades it.
    let view: RexctlStatusView = c.post("/v1/rexctl", &stack).await?;

    println!("\n✓ Fluxer is live and managed by latrix!");
    println!("  URL:          https://{}", view.domain);
    println!("  release:      {}", if view.release.is_empty() { "(default)" } else { &view.release });
    println!("  storage:      {}", view.storage);
    if !view.voice_endpoints.is_empty() {
        println!("  voice:        {}", view.voice_endpoints.join(", "));
    }
    println!(
        "  auto-upgrade: {}",
        if view.auto_upgrade {
            format!("ON (leader checks every {}h)", view.upgrade_interval_hours)
        } else {
            "off".into()
        }
    );

    if let Ok(dns) = c.get::<DnsStatusView>("/v1/dns").await {
        if dns.configured {
            println!("  DNS:          Cloudflare DNS is active — {} is being synced automatically", view.domain);
        } else if let Ok(st) = c.get::<StatusView>("/v1/status").await {
            let ips: Vec<String> = st
                .machines
                .iter()
                .filter(|m| m.alive)
                .map(|m| m.machine.public_ip.clone())
                .collect();
            if !ips.is_empty() {
                println!(
                    "  DNS:          point an A record for {} at {} (or run `latrix dns cloudflare <token>`)",
                    view.domain,
                    ips.join(", ")
                );
            }
        }
    }
    println!("\nManage with: `latrix rexctl status`, `latrix rexctl upgrade`, `latrix rexctl backup`, `latrix rexctl logs [service]`");
    Ok(())
}

pub async fn status(cfg: &CliConfig, cl: Option<&str>) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    let v: RexctlStatusView = c.get("/v1/rexctl").await?;
    if !v.installed {
        println!("No Fluxer stack is managed on this cluster yet.");
        println!("Deploy from a rexctl backup with:");
        println!("  latrix rexctl deploy <backup.tar.zst>");
        return Ok(());
    }

    println!("Fluxer stack '{}'", v.project);
    println!(
        "  domain:       https://{}  ({})",
        v.domain,
        if v.cert_ready { "HTTPS cert active" } else { "cert pending" }
    );
    let mut rel_line = if v.release.is_empty() {
        "(unversioned)".to_string()
    } else {
        v.release.clone()
    };
    if let Some(latest) = &v.latest_available {
        if fluxer::is_newer_fluxer(latest, &v.release) {
            rel_line.push_str(&format!("  (update available: {latest} — run `latrix rexctl upgrade`)"));
        } else {
            rel_line.push_str("  (up to date)");
        }
    }
    println!("  release:      {rel_line}");
    if let Some(u) = &v.upgrading {
        println!("  upgrading:    in progress → {u}");
    }
    println!(
        "  auto-upgrade: {}{}",
        if v.auto_upgrade {
            format!("ON (every {}h)", v.upgrade_interval_hours)
        } else {
            "off".into()
        },
        if v.last_check > 0 {
            format!(" · last check {}", ago(v.last_check))
        } else {
            String::new()
        }
    );
    if v.last_upgrade > 0 {
        println!(
            "  last upgrade: {}{}",
            ago(v.last_upgrade),
            v.previous_release
                .as_ref()
                .map(|p| format!(" (from {p})"))
                .unwrap_or_default()
        );
    }
    if let Some(err) = &v.last_error {
        println!("  last error:   {err}");
    }
    println!("  storage:      {}", v.storage);
    println!(
        "  voice:        {}",
        if !v.voice_endpoints.is_empty() {
            v.voice_endpoints.join(", ")
        } else if v.bundled_voice {
            "bundled LiveKit (starting)".into()
        } else {
            "external".into()
        }
    );
    println!("  kv / rust:    {} / {}", v.kv_mode, v.rust_mode);
    println!();

    let rows: Vec<Vec<String>> = v
        .services
        .iter()
        .map(|s| {
            vec![
                s.service.clone(),
                s.status.clone(),
                format!("{}/{}", s.healthy, s.desired),
                if s.machines.is_empty() { "-".into() } else { s.machines.join(",") },
                s.memory.clone(),
                format!("v{}", s.release),
            ]
        })
        .collect();
    print_table(&["SERVICE", "STATUS", "HEALTHY", "MACHINES", "MEMORY", "REL"], rows);
    Ok(())
}

pub async fn upgrade(cfg: &CliConfig, cl: Option<&str>, version: Option<String>, force: bool) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    println!(
        "{} Checking and upgrading Fluxer{}...",
        deploy::arrow(),
        version.as_ref().map(|v| format!(" to {v}")).unwrap_or_default()
    );
    println!("    (the cluster leader takes volume snapshots and rolls out services with automatic rollback on failure)");
    let resp = c
        .request(reqwest::Method::POST, "/v1/rexctl/upgrade")
        .timeout(Duration::from_secs(1800))
        .json(&RexctlUpgradeRequest { version, force })
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        let msg = serde_json::from_str::<ApiErrorBody>(&body)
            .map(|e| e.error)
            .unwrap_or(body);
        bail!("{status}: {msg}");
    }
    let res: RexctlUpgradeResult = serde_json::from_str(&body)?;
    if res.upgraded {
        println!("✓ {}", res.message);
        if !res.updated_services.is_empty() {
            println!("  updated: {}", res.updated_services.join(", "));
        }
    } else {
        println!("✓ {}", res.message);
    }
    Ok(())
}

pub async fn auto_upgrade(
    cfg: &CliConfig,
    cl: Option<&str>,
    mode: Option<String>,
    interval: Option<u64>,
    check_now: bool,
) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    let enabled = match mode.as_deref().map(|s| s.to_ascii_lowercase()).as_deref() {
        None => None,
        Some("on" | "true" | "enable" | "yes" | "1") => Some(true),
        Some("off" | "false" | "disable" | "no" | "0") => Some(false),
        Some(other) => bail!("expected `on` or `off`, got '{other}'"),
    };
    if enabled.is_none() && interval.is_none() && !check_now {
        let v: RexctlStatusView = c.get("/v1/rexctl").await?;
        if !v.installed {
            bail!("no Fluxer stack is managed on this cluster");
        }
        println!(
            "Fluxer auto-upgrade: {} (every {}h){}",
            if v.auto_upgrade { "ON" } else { "off" },
            v.upgrade_interval_hours,
            if v.last_check > 0 { format!(" · last check {}", ago(v.last_check)) } else { String::new() }
        );
        return Ok(());
    }
    let v: RexctlStatusView = c
        .post(
            "/v1/rexctl/auto-upgrade",
            &RexctlAutoUpgradeRequest {
                enabled,
                interval_hours: interval,
                check_now,
            },
        )
        .await?;
    println!(
        "✓ Fluxer auto-upgrade is {} (checking every {}h)",
        if v.auto_upgrade { "ON" } else { "off" },
        v.upgrade_interval_hours
    );
    Ok(())
}

pub async fn backup_stack(
    cfg: &CliConfig,
    cl: Option<&str>,
    out_dir: Option<PathBuf>,
    no_uploads: bool,
) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    let stack: FluxerStack = c.get("/v1/rexctl/export").await?;
    let work = backup::temp_dir("rexctl-backup")?;
    let res = backup_stack_inner(&c, &stack, &work, out_dir, no_uploads).await;
    let _ = std::fs::remove_dir_all(&work);
    res
}

async fn backup_stack_inner(
    c: &Client,
    stack: &FluxerStack,
    work: &Path,
    out_dir: Option<PathBuf>,
    no_uploads: bool,
) -> Result<()> {
    println!("{} Backing up Fluxer '{}' ({})", deploy::arrow(), stack.project, stack.domain);

    // 1. Dump Postgres via pg_dump --format=custom (required when postgres is part of the stack).
    let pg_app = format!("{}-postgres", stack.project);
    let dump_file = work.join("fluxer.dump");
    let m = find_running_machine(c, &pg_app)
        .await
        .with_context(|| format!("{pg_app} is not running or unreachable; refusing to create a backup without the PostgreSQL database"))?;
    println!("    dumping PostgreSQL database from {pg_app}...");
    exec_in_app(
        c,
        m,
        &pg_app,
        r#"PGPASSWORD="${POSTGRES_PASSWORD:-}" exec pg_dump -h 127.0.0.1 -U "${POSTGRES_USER:-fluxer}" -d "${POSTGRES_DB:-fluxer}" --format=custom"#,
        None,
        Some(&dump_file),
    )
    .await
    .context("pg_dump failed")?;
    let sz = std::fs::metadata(&dump_file)?.len();
    if sz == 0 {
        bail!(
            "pg_dump produced an empty file (if the cluster agent is older than this CLI, upgrade the cluster agents with `latrix update`)"
        );
    }
    let mut magic = [0u8; 5];
    use std::io::Read;
    let n = std::fs::File::open(&dump_file)?.read(&mut magic)?;
    if n < 5 || &magic != b"PGDMP" {
        bail!(
            "pg_dump output ({sz} bytes) is not a valid PostgreSQL custom-format dump (missing PGDMP header)"
        );
    }
    println!("    database dump: {}", mb(sz));
    let pg_dump = Some(dump_file);

    // 2. Download stateful non-Postgres volumes
    let mut vol_dirs: BTreeMap<String, PathBuf> = BTreeMap::new();
    let vol_targets: &[(&str, &str)] = &[
        ("valkey", "valkey-data"),
        ("nats", "nats-data"),
        ("meilisearch", "meilisearch-data"),
        ("seaweedfs", "seaweedfs-data"),
    ];
    for (svc, vol_name) in vol_targets {
        if *svc == "seaweedfs" && (no_uploads || stack.external_object_store) {
            continue;
        }
        if *svc == "valkey" && stack.kv_postgres {
            continue;
        }
        let app_name = format!("{}-{svc}", stack.project);
        let v: AppView = match c.get::<AppView>(&format!("/v1/apps/{app_name}")).await {
            Ok(v) => v,
            Err(e) if e.to_string().contains("404") => continue,
            Err(e) => return Err(e).with_context(|| format!("inspecting {app_name} for backup")),
        };
        let Some(vol) = v.volumes.iter().find(|x| x.volume.name == *vol_name) else {
            continue;
        };
        let tgz = work.join(format!("{vol_name}.tar.gz"));
        let n = backup::download(
            c,
            &format!("/v1/m/{}/volume-data?volume={}", vol.volume.primary, vol.volume.id),
            &tgz,
        )
        .await
        .with_context(|| format!("downloading volume {vol_name}"))?;
        println!("    volume {vol_name}: {}", mb(n));
        let dest = work.join("vols").join(vol_name);
        std::fs::create_dir_all(&dest)?;
        let f = std::fs::File::open(&tgz)?;
        tar::Archive::new(flate2::read::GzDecoder::new(f)).unpack(&dest)?;
        vol_dirs.insert((*vol_name).to_string(), dest);
    }

    let dir = out_dir.unwrap_or_else(backup::default_dir);
    let safe_dom = stack
        .domain
        .replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
    let out = dir.join(format!(
        "fluxer-{safe_dom}-{}.tar.zst",
        backup::stamp(util::now())
    ));
    let scope = if no_uploads { "without-uploads" } else { "full" };
    println!("    compressing rexctl-compatible archive...");
    let size = fluxer::write_rexctl_backup(
        &out,
        stack,
        pg_dump.as_deref(),
        &vol_dirs,
        scope,
        "latrix-rexctl",
    )?;
    println!("\n✓ saved {} ({})", out.display(), mb(size));
    println!("  contains secrets — keep safe. Restore with `latrix rexctl deploy {}` or `rexctl restore`.", out.display());
    Ok(())
}

pub async fn logs(
    cfg: &CliConfig,
    cl: Option<&str>,
    service: Option<String>,
    follow: bool,
    tail: u32,
) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    let v: RexctlStatusView = c.get("/v1/rexctl").await?;
    if !v.installed {
        bail!("no Fluxer stack is managed on this cluster");
    }
    let targets: Vec<String> = match service {
        Some(svc) => {
            let app = if svc.starts_with(&format!("{}-", v.project)) {
                svc
            } else {
                format!("{}-{svc}", v.project)
            };
            vec![app]
        }
        None => ["edge", "api", "gateway", "worker", "rust", "media-proxy", "livekit"]
            .iter()
            .filter_map(|s| v.services.iter().find(|x| x.service == *s).map(|x| x.app.clone()))
            .collect(),
    };
    if targets.is_empty() {
        bail!("no matching Fluxer services found");
    }

    let colors = ["36", "35", "33", "32", "34", "31"];
    let mut streams = vec![];
    for (n, app) in targets.iter().enumerate() {
        let Ok(av) = c.get::<AppView>(&format!("/v1/apps/{app}")).await else {
            continue;
        };
        for inst in av.instances.iter().filter(|i| !i.instance.stopping) {
            let path = format!(
                "/v1/m/{}/logs?instance={}&tail={tail}&follow={follow}",
                inst.instance.machine, inst.instance.id
            );
            let Ok(resp) = c.request(reqwest::Method::GET, &path).send().await else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let short = app.strip_prefix(&format!("{}-", v.project)).unwrap_or(app);
            let prefix = format!("\x1b[{}m{short}@{}\x1b[0m", colors[n % colors.len()], inst.machine_name);
            let key = inst.instance.id.clone();
            streams.push(resp.bytes_stream().map(move |b| (key.clone(), prefix.clone(), b)).boxed());
        }
    }
    if streams.is_empty() {
        bail!("no running Fluxer instances to stream logs from");
    }
    let mut all = futures::stream::select_all(streams);
    let mut bufs: std::collections::HashMap<String, (String, Vec<u8>)> = Default::default();
    const MAX_LINE_BYTES: usize = 64 * 1024;
    while let Some((key, prefix, chunk)) = all.next().await {
        let Ok(chunk) = chunk else { continue };
        let (_, buf) = bufs.entry(key).or_insert_with(|| (prefix.clone(), Vec::new()));
        buf.extend_from_slice(&chunk);
        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let raw: Vec<u8> = buf.drain(..=pos).collect();
            let line = String::from_utf8_lossy(&raw);
            println!("{prefix} {}", line.trim_end_matches(['\r', '\n']));
        }
        if buf.len() > MAX_LINE_BYTES {
            let raw: Vec<u8> = std::mem::take(buf);
            let line = String::from_utf8_lossy(&raw);
            println!("{prefix} {}", line.trim_end_matches(['\r', '\n']));
        }
    }
    for (_, (prefix, buf)) in bufs {
        if !buf.is_empty() {
            let line = String::from_utf8_lossy(&buf);
            println!("{prefix} {}", line.trim_end_matches(['\r', '\n']));
        }
    }
    Ok(())
}

pub async fn restart(cfg: &CliConfig, cl: Option<&str>, service: Option<String>) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    let v: RexctlStatusView = c.get("/v1/rexctl").await?;
    if !v.installed {
        bail!("no Fluxer stack is managed on this cluster");
    }
    let targets: Vec<String> = match service {
        Some(svc) => {
            let app = if svc.starts_with(&format!("{}-", v.project)) {
                svc
            } else {
                format!("{}-{svc}", v.project)
            };
            vec![app]
        }
        None => v
            .services
            .iter()
            .filter(|s| s.status != "missing")
            .map(|s| s.app.clone())
            .collect(),
    };
    if targets.is_empty() {
        bail!("no deployed Fluxer services found to restart");
    }
    for app in targets {
        println!("{} Restarting {app}...", deploy::arrow());
        let r: DeployResponse = c
            .post(&format!("/v1/apps/{app}/restart"), &serde_json::json!({}))
            .await?;
        deploy::watch(&c, &app, r.version, 180).await?;
    }
    Ok(())
}

pub async fn config_cmd(cfg: &CliConfig, cl: Option<&str>, action: Option<RexctlConfigCmd>) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    match action.unwrap_or(RexctlConfigCmd::List) {
        RexctlConfigCmd::List => {
            let v: RexctlStatusView = c.get("/v1/rexctl").await?;
            if !v.installed {
                bail!("no Fluxer stack is managed on this cluster");
            }
            let rows: Vec<Vec<String>> = v
                .settings
                .into_iter()
                .map(|(k, val)| vec![k, val])
                .collect();
            if rows.is_empty() {
                println!("(no explicit Fluxer settings)");
            } else {
                print_table(&["KEY", "VALUE"], rows);
            }
            Ok(())
        }
        RexctlConfigCmd::Set { pairs } => {
            if pairs.is_empty() {
                bail!("usage: latrix rexctl config set KEY=value ...");
            }
            let mut set = BTreeMap::new();
            for p in pairs {
                let (k, v) = p
                    .split_once('=')
                    .ok_or_else(|| anyhow!("expected KEY=value, got '{p}'"))?;
                set.insert(k.trim().to_string(), v.to_string());
            }
            let v: RexctlStatusView = c
                .post("/v1/rexctl/config", &RexctlConfigRequest { set, unset: vec![] })
                .await?;
            println!("✓ updated Fluxer settings for {} (affected services are rolling out)", v.domain);
            Ok(())
        }
        RexctlConfigCmd::Unset { keys } => {
            if keys.is_empty() {
                bail!("usage: latrix rexctl config unset KEY ...");
            }
            let v: RexctlStatusView = c
                .post("/v1/rexctl/config", &RexctlConfigRequest { set: BTreeMap::new(), unset: keys })
                .await?;
            println!("✓ removed Fluxer settings for {} (affected services are rolling out)", v.domain);
            Ok(())
        }
    }
}

async fn destroy_apps(c: &Client, v: &RexctlStatusView, purge: bool) -> Result<()> {
    let mut apps: Vec<String> = v.services.iter().rev().map(|s| s.app.clone()).collect();
    if let Ok(st) = c.get::<StatusView>("/v1/status").await {
        for a in st.apps {
            if a.config.as_ref().and_then(|cfg| cfg.group.as_deref()) == Some(v.project.as_str())
                && !apps.contains(&a.name)
            {
                apps.push(a.name);
            }
        }
    }
    for app in apps {
        match c
            .delete::<bool>(&format!("/v1/apps/{app}?purge_volumes={purge}"))
            .await
        {
            Ok(_) => println!("    destroyed {app}"),
            Err(e) if e.to_string().contains("404") || e.to_string().contains("not found") => {}
            Err(e) => return Err(e).with_context(|| format!("destroying {app}")),
        }
    }
    let _: bool = c.delete("/v1/rexctl").await?;
    Ok(())
}

pub async fn destroy(cfg: &CliConfig, cl: Option<&str>, yes: bool, keep_volumes: bool) -> Result<()> {
    let c = connect_latrix(cfg, cl).await?;
    let v: RexctlStatusView = c.get("/v1/rexctl").await?;
    if !v.installed {
        bail!("no Fluxer stack is managed on this cluster");
    }
    let purge = !keep_volumes;
    if !yes {
        if purge {
            println!("tip: run `latrix rexctl backup` first, or pass --keep-volumes");
        }
        print!(
            "Destroy Fluxer stack '{}' ({}, {} service(s)){}? Type '{}' to confirm: ",
            v.project,
            v.domain,
            v.services.len(),
            if purge { " and DELETE all volume data" } else { " (keeping volume data)" },
            v.project
        );
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.trim() != v.project {
            bail!("aborted");
        }
    }
    destroy_apps(&c, &v, purge).await?;
    println!("✓ destroyed Fluxer stack '{}'", v.project);
    Ok(())
}

pub async fn run_cmd(cfg: &CliConfig, cl: Option<&str>, action: Option<RexctlCmd>) -> Result<()> {
    match action.unwrap_or(RexctlCmd::Status) {
        RexctlCmd::Status => status(cfg, cl).await,
        RexctlCmd::Inspect { file, skip_verify } => inspect(&file, skip_verify),
        RexctlCmd::Deploy {
            file,
            project,
            domain,
            release,
            no_auto_upgrade,
            copies,
            region,
            skip_verify,
            replace,
            dry_run,
        } => {
            deploy_backup(
                cfg,
                cl,
                DeployBackupOptions {
                    file,
                    project,
                    domain,
                    release,
                    auto_upgrade: !no_auto_upgrade,
                    copies,
                    region,
                    skip_verify,
                    replace,
                    dry_run,
                },
            )
            .await
        }
        RexctlCmd::Upgrade { version, force } => upgrade(cfg, cl, version, force).await,
        RexctlCmd::AutoUpgrade { mode, interval, check_now } => {
            auto_upgrade(cfg, cl, mode, interval, check_now).await
        }
        RexctlCmd::Backup { out, no_uploads } => backup_stack(cfg, cl, out, no_uploads).await,
        RexctlCmd::Logs { service, follow, tail } => logs(cfg, cl, service, follow, tail).await,
        RexctlCmd::Restart { service } => restart(cfg, cl, service).await,
        RexctlCmd::Config { action } => config_cmd(cfg, cl, action).await,
        RexctlCmd::Destroy { yes, keep_volumes } => destroy(cfg, cl, yes, keep_volumes).await,
    }
}
