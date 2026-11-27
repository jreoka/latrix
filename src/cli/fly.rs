//! `latrix import fly <app>` — move a Fly.io app onto a latrix cluster,
//! with its config, secrets, image, volume data and custom domains.
//!
//! Uses your `fly` (flyctl) login:
//! * config: `fly config show` → latrix.toml
//! * secrets: names from `fly secrets list`, values read from a running
//!   machine's environment (Fly never returns secret values)
//! * image: the deployed image, pulled with Docker after `fly auth docker`
//!   (or `--from-source` to build from the current directory)
//! * data: each volume is tarred on the machine and copied with sftp
//! * domains: `fly certs list` → [http] domains (latrix gets new certificates)
//!
//! Everything is first written as a normal latrix backup file in
//! ~/latrix-backups, then restored onto the cluster — so you also keep a
//! copy of the Fly app's data.

use super::backup::{self, Manifest, ManifestVolume};
use super::client::Client;
use super::profile::CliConfig;
use crate::api_types::StatusView;
use crate::config::*;
use crate::util::{self, now};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;

fn fly_bin() -> Result<&'static str> {
    for b in ["fly", "flyctl"] {
        if std::process::Command::new(b).arg("version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false) {
            return Ok(b);
        }
    }
    bail!("flyctl is not installed (https://fly.io/docs/flyctl/install/) — it is needed to read your Fly app")
}

fn fly(bin: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {bin}"))?;
    if !out.status.success() {
        bail!("{bin} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn sanitize(s: &str) -> String {
    let s: String = s.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    s.trim_matches('-').chars().take(48).collect()
}

fn as_list(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        other => vec![other.clone()],
    }
}

/// Parse `fly config show` output (JSON, or TOML from older/newer flyctl).
pub fn parse_fly_config(text: &str) -> Result<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return Ok(v);
    }
    let t: toml::Value = toml::from_str(text).context("could not parse the Fly app config")?;
    Ok(serde_json::to_value(t)?)
}

/// Fly memory: 512, "512mb", "1gb" -> "512MB"/"1024MB".
fn fly_memory(v: &Value) -> Option<String> {
    if let Some(n) = v.as_u64() {
        return Some(format!("{n}MB"));
    }
    let s = v.as_str()?;
    util::parse_size_mb(s).ok().map(|mb| format!("{mb}MB"))
}

/// Turn a fly.toml (as JSON) into a latrix config. Returns warnings for
/// things that don't carry over.
pub fn convert_fly(f: &Value, name: &str, instances: u32, domains: Vec<String>) -> (AppConfig, Vec<String>) {
    let mut warnings = vec![];
    let mut cfg = AppConfig { app: sanitize(name), ..Default::default() };

    // build
    let b = &f["build"];
    if let Some(img) = b["image"].as_str() {
        cfg.build.image = Some(img.to_string());
    }
    if let Some(df) = b["dockerfile"].as_str() {
        cfg.build.dockerfile = Some(df.to_string());
    }
    if let Some(t) = b["build-target"].as_str().or(b["build_target"].as_str()) {
        cfg.build.target = Some(t.to_string());
    }
    if let Some(args) = b["args"].as_object() {
        for (k, v) in args {
            if let Some(v) = v.as_str() {
                cfg.build.args.insert(k.clone(), v.to_string());
            }
        }
    }
    if b["builder"].is_string() || b["buildpacks"].is_array() {
        warnings.push("the app is built with buildpacks; latrix builds Dockerfiles (the deployed image is migrated as-is)".into());
    }

    // env
    if let Some(env) = f["env"].as_object() {
        for (k, v) in env {
            let v = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            cfg.env.insert(k.clone(), v);
        }
    }

    // command: [processes] (first group, preferring "app") or experimental.cmd
    if let Some(p) = f["processes"].as_object() {
        if p.len() > 1 {
            warnings.push(format!(
                "Fly process groups ({}) — only '{}' is migrated; create another latrix app for each of the others",
                p.keys().cloned().collect::<Vec<_>>().join(", "),
                if p.contains_key("app") { "app" } else { p.keys().next().unwrap() }
            ));
        }
        let cmd = p.get("app").or_else(|| p.values().next());
        if let Some(c) = cmd.and_then(|c| c.as_str()).filter(|c| !c.is_empty()) {
            cfg.command = Some(Command::Shell(c.to_string()));
        }
    } else if let Some(c) = f["experimental"]["cmd"].as_array() {
        cfg.command = Some(Command::Exec(c.iter().filter_map(|x| x.as_str().map(String::from)).collect()));
    }

    // http_service
    let hs = &f["http_service"];
    if let Some(port) = hs["internal_port"].as_u64() {
        let health = as_list(&hs["checks"]).iter().find_map(|c| c["path"].as_str().map(String::from));
        cfg.http = Some(HttpConfig {
            port: port as u16,
            domains: domains.clone(),
            health,
            force_https: hs["force_https"].as_bool(),
        });
    }

    // [[services]]
    for svc in as_list(&f["services"]) {
        let Some(internal) = svc["internal_port"].as_u64().map(|p| p as u16) else { continue };
        let ports = as_list(&svc["ports"]);
        let is_http = ports.iter().any(|p| {
            let handlers: Vec<String> = as_list(&p["handlers"]).iter().filter_map(|h| h.as_str().map(String::from)).collect();
            handlers.iter().any(|h| h == "http") || (handlers.iter().any(|h| h == "tls") && p["port"].as_u64() == Some(443))
        });
        if is_http && cfg.http.is_none() {
            let health = as_list(&svc["http_checks"]).iter().find_map(|c| c["path"].as_str().map(String::from));
            cfg.http = Some(HttpConfig { port: internal, domains: domains.clone(), health, force_https: None });
            continue;
        }
        if is_http {
            continue;
        }
        let public = ports.iter().find_map(|p| p["port"].as_u64()).map(|p| p as u16);
        let udp = svc["protocol"].as_str() == Some("udp");
        if udp {
            warnings.push(format!(
                "UDP port {internal}: on latrix the app should listen on 0.0.0.0 (not fly-global-services)"
            ));
        }
        if !cfg.ports.iter().any(|p| p.port == internal) {
            cfg.ports.push(PortConfig {
                port: internal,
                public: public.is_some() || udp,
                public_port: public.filter(|p| *p != internal),
                protocol: if udp { "udp".into() } else { "tcp".into() },
            });
        }
    }
    if cfg.http.is_none() && !domains.is_empty() {
        warnings.push(format!("domains {} have no HTTP service to point at", domains.join(", ")));
    }

    // [[vm]] / [vm]
    if let Some(vm) = as_list(&f["vm"]).first() {
        if let Some(m) = fly_memory(&vm["memory"]).or_else(|| fly_memory(&vm["memory_mb"])) {
            cfg.scale.memory = m;
        }
        if let Some(c) = vm["cpus"].as_f64() {
            cfg.scale.cpu = c;
        }
    } else if let Some(size) = f["vm"]["size"].as_str() {
        warnings.push(format!("VM size '{size}' — check [scale] cpu/memory in latrix.toml"));
    }

    // [[mounts]]
    for m in as_list(&f["mounts"]) {
        let (Some(src), Some(dst)) = (m["source"].as_str(), m["destination"].as_str()) else { continue };
        cfg.volumes.push(VolumeConfig {
            name: sanitize(src),
            path: dst.to_string(),
            copies: 2,
            sync: "30s".into(),
            pre_sync: None,
            size: m["initial_size"].as_str().map(String::from),
        });
    }

    // scale
    if cfg.volumes.is_empty() {
        cfg.scale.count = Some(instances.max(1));
    } else {
        if instances > 1 {
            warnings.push(format!(
                "{instances} Fly machines each had their own volume; latrix runs one instance with a replicated volume (data from one machine is migrated)"
            ));
        }
        cfg.scale.count = Some(1);
    }
    if let Some(rc) = f["deploy"]["release_command"].as_str() {
        warnings.push(format!("release_command '{rc}' is not run automatically; run it once with `latrix console {} -- {rc}`", cfg.app));
    }
    if f["statics"].is_array() || f["statics"].is_object() {
        warnings.push("[statics] are not migrated; serve them from the app".into());
    }
    (cfg, warnings)
}

/// Find the deployed image reference in flyctl JSON output.
pub fn find_image_ref(v: &Value) -> Option<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) if s.starts_with("registry.fly.io/") => out.push(s.clone()),
            Value::Object(m) => {
                let get = |k: &str| {
                    m.iter().find(|(key, _)| key.eq_ignore_ascii_case(k)).and_then(|(_, v)| v.as_str()).map(String::from)
                };
                if let (Some(reg), Some(repo)) = (get("registry"), get("repository")) {
                    let tag = get("tag").filter(|t| !t.is_empty());
                    let digest = get("digest").filter(|d| d.starts_with("sha256:"));
                    match (tag, digest) {
                        (Some(t), _) => out.push(format!("{reg}/{repo}:{t}")),
                        (None, Some(d)) => out.push(format!("{reg}/{repo}@{d}")),
                        _ => {}
                    }
                }
                for v in m.values() {
                    walk(v, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = vec![];
    walk(v, &mut out);
    out.into_iter().next()
}

/// Names from `fly secrets list --json`.
pub fn secret_names(v: &Value) -> Vec<String> {
    as_list(v)
        .iter()
        .filter_map(|s| {
            s.as_object()?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("name"))
                .and_then(|(_, v)| v.as_str().map(String::from))
        })
        .collect()
}

/// Pick the secret values out of `env` output.
pub fn secrets_from_env(env: &str, names: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in env.lines() {
        let line = line.trim_end_matches('\r');
        if let Some((k, v)) = line.split_once('=') {
            if names.iter().any(|n| n == k) {
                out.insert(k.to_string(), v.to_string());
            }
        }
    }
    out
}

fn count_machines(v: &Value) -> u32 {
    as_list(v)
        .iter()
        .filter(|m| m["state"].as_str().map(|s| s != "destroyed" && s != "destroying").unwrap_or(true))
        .filter(|m| {
            let g = m["config"]["metadata"]["fly_process_group"].as_str().unwrap_or("app");
            g == "app" || g.is_empty()
        })
        .count() as u32
}

fn hostnames(v: &Value) -> Vec<String> {
    as_list(v)
        .iter()
        .filter_map(|c| {
            c.as_object()?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("hostname"))
                .and_then(|(_, v)| v.as_str().map(String::from))
        })
        .filter(|h| !h.ends_with(".fly.dev") && !h.starts_with('*'))
        .collect()
}

fn save_image(image: &str, dest: &Path) -> Result<u64> {
    let mut child = std::process::Command::new("docker")
        .args(["save", image])
        .stdout(Stdio::piped())
        .spawn()
        .context("running docker save")?;
    let mut out = flate2::write::GzEncoder::new(std::fs::File::create(dest)?, flate2::Compression::fast());
    std::io::copy(child.stdout.as_mut().unwrap(), &mut out)?;
    out.finish()?.flush()?;
    if !child.wait()?.success() {
        bail!("docker save failed");
    }
    Ok(std::fs::metadata(dest)?.len())
}

pub struct ImportOptions {
    pub fly_app: String,
    pub name: Option<String>,
    pub no_data: bool,
    pub no_secrets: bool,
    pub from_source: bool,
}

pub async fn import(cfg: &CliConfig, cl: Option<&str>, o: ImportOptions) -> Result<()> {
    let (_, p) = cfg.profile(cl)?;
    if p.kubernetes.is_some() {
        bail!("`import fly` targets latrix clusters");
    }
    let bin = fly_bin()?;
    let app = o.fly_app.as_str();
    println!("==> reading Fly app '{app}'");
    let f = parse_fly_config(&fly(bin, &["config", "show", "-a", app])?)?;
    let machines = fly(bin, &["machines", "list", "-a", app, "--json"]).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let certs = fly(bin, &["certs", "list", "-a", app, "--json"]).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let domains = hostnames(&certs);
    let name = o.name.clone().unwrap_or_else(|| sanitize(app));
    let (config, warnings) = convert_fly(&f, &name, count_machines(&machines), domains.clone());
    config.validate().context("the converted config is not valid")?;
    for w in &warnings {
        println!("    note: {w}");
    }

    let work = backup::temp_dir("fly")?;
    let mut files: Vec<(String, PathBuf)> = vec![];

    // secrets
    let mut secrets = BTreeMap::new();
    if !o.no_secrets {
        let names = secret_names(&serde_json::from_str(&fly(bin, &["secrets", "list", "-a", app, "--json"])?).unwrap_or(Value::Null));
        if !names.is_empty() {
            println!("==> reading {} secret value(s) from a running machine", names.len());
            let env = fly(bin, &["ssh", "console", "-a", app, "-C", "env"]).context(
                "reading secrets needs a running machine with SSH (start one with `fly machine start`, or pass --no-secrets and set them with `latrix secrets set`)",
            )?;
            secrets = secrets_from_env(&env, &names);
            let missing: Vec<&String> = names.iter().filter(|n| !secrets.contains_key(*n)).collect();
            if !missing.is_empty() {
                println!("    note: not found in the machine's environment: {} (set with `latrix secrets set`)", missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            }
        }
    }

    // image
    let mut image = config.build.image.clone().unwrap_or_default();
    let mut image_file = None;
    let build_from_source = o.from_source;
    if !build_from_source {
        let refs = fly(bin, &["image", "show", "-a", app, "--json"])
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| find_image_ref(&v))
            .or_else(|| {
                fly(bin, &["releases", "-a", app, "--image", "--json"])
                    .ok()
                    .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                    .and_then(|v| find_image_ref(&v))
            });
        match refs {
            Some(r) => {
                println!("==> pulling the deployed image {r} (needs Docker running locally)");
                let _ = fly(bin, &["auth", "docker"]);
                let st = std::process::Command::new("docker").args(["pull", &r]).status().context("running docker (install Docker, or use --from-source)")?;
                if !st.success() {
                    bail!("docker pull {r} failed (or use --from-source to build from this directory)");
                }
                let dest = work.join("image.tar.gz");
                let n = save_image(&r, &dest)?;
                println!("    image saved ({:.0} MB)", n as f64 / 1048576.0);
                files.push(("image.tar.gz".into(), dest));
                image_file = Some("image.tar.gz".to_string());
                image = r;
            }
            None if !image.is_empty() => println!("==> using public image {image}"),
            None => bail!("could not find the app's deployed image; run this from the app's source directory with --from-source"),
        }
    }

    // volume data
    let mut volumes = vec![];
    if !o.no_data {
        for v in &config.volumes {
            println!("==> copying volume '{}' ({})", v.name, v.path);
            let remote = format!("/tmp/latrix-{}.tgz", v.name);
            fly(bin, &["ssh", "console", "-a", app, "-C", &format!("tar czf {remote} -C {} .", v.path)])
                .context("could not archive the volume on the Fly machine (is it running?)")?;
            let local = work.join(format!("vol-{}.tar.gz", v.name));
            fly(bin, &["ssh", "sftp", "get", &remote, &local.display().to_string(), "-a", app])?;
            let _ = fly(bin, &["ssh", "console", "-a", app, "-C", &format!("rm -f {remote}")]);
            let size = std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0);
            println!("    {:.1} MB", size as f64 / 1048576.0);
            let file = format!("volumes/{}.tar.gz", v.name);
            files.push((file.clone(), local));
            volumes.push(ManifestVolume { name: v.name.clone(), path: v.path.clone(), file });
        }
    }

    // Keep a local copy, then restore it onto the cluster.
    let manifest = Manifest {
        format: backup::FORMAT,
        app: name.clone(),
        created_at: now(),
        source: format!("fly:{app}"),
        config: config.clone(),
        image: image.clone(),
        image_file: image_file.clone(),
        secrets: secrets.clone(),
        count: config.scale.count.unwrap_or(1),
        volumes,
    };
    let archive = backup::default_dir().join(format!("fly-{app}-{}.latrix-backup.tar", backup::stamp(now())));
    backup::write_archive(&archive, &manifest, &files)?;
    let _ = std::fs::remove_dir_all(&work);
    println!("==> saved a copy as {}", archive.display());

    if !Path::new("latrix.toml").exists() {
        let mut local = config.clone();
        if build_from_source || image_file.is_some() {
            local.build.image = None; // future deploys build from source
        }
        std::fs::write("latrix.toml", toml::to_string_pretty(&local)?)?;
        println!("==> wrote latrix.toml for future `latrix deploy`s");
    }

    let c = Client::connect(&p).await?;
    if build_from_source {
        // Create it stopped with secrets + data, then build & deploy from here.
        let (m2, dir) = backup::read_archive(&archive)?;
        let mut m2 = m2;
        m2.image = "busybox:1.36".into();
        m2.count = 0;
        m2.config.scale.count = Some(0);
        m2.config.scale.min = None;
        m2.config.scale.max = None;
        backup::restore_bundle(&c, &m2, &dir, &name, "imported from Fly (data)").await?;
        let _ = std::fs::remove_dir_all(&dir);
        super::deploy::deploy_one(&c, &config, Path::new("."), false, Some(format!("imported from Fly app {app}"))).await?;
    } else {
        let (m, dir) = backup::read_archive(&archive)?;
        backup::restore_bundle(&c, &m, &dir, &name, &format!("imported from Fly app {app}")).await?;
        let _ = std::fs::remove_dir_all(&dir);
    }

    let st: StatusView = c.get("/v1/status").await?;
    let ips: Vec<String> = st.machines.iter().filter(|m| m.alive).map(|m| m.machine.public_ip.clone()).collect();
    println!("\nNext steps to switch over from Fly:");
    if domains.is_empty() {
        println!("  • test the app at the URL above");
    } else {
        println!("  • point DNS for {} at your machine(s): A record(s) {}", domains.join(", "), ips.join(", "));
        println!("    latrix requests certificates automatically once DNS resolves here");
    }
    if !manifest.volumes.is_empty() {
        println!("  • writes on Fly after this copy are not migrated: for a clean cut-over, stop the Fly app");
        println!("    (`fly scale count 0 -a {app}`) and re-run with --as {name}-2, or copy the final data then");
    }
    println!("  • when you're happy: `fly apps destroy {app}`");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn converts_fly_toml() {
        let fly_toml = r#"
app = "my-shop"
primary_region = "ams"

[build]
  dockerfile = "Dockerfile.prod"

[env]
  PORT = "8080"
  LOG_LEVEL = "info"

[http_service]
  internal_port = 8080
  force_https = true
  min_machines_running = 1
  [[http_service.checks]]
    path = "/healthz"

[[services]]
  internal_port = 5432
  protocol = "tcp"
  [[services.ports]]
    port = 5433

[[mounts]]
  source = "shop_data"
  destination = "/data"
  initial_size = "5gb"

[[vm]]
  memory = "1gb"
  cpus = 2

[deploy]
  release_command = "bin/migrate"
"#;
        let f = parse_fly_config(fly_toml).unwrap();
        let (c, warnings) = convert_fly(&f, "my-shop", 3, vec!["shop.example.com".into()]);
        c.validate().unwrap();
        assert_eq!(c.app, "my-shop");
        assert_eq!(c.build.dockerfile.as_deref(), Some("Dockerfile.prod"));
        assert_eq!(c.env["LOG_LEVEL"], "info");
        let h = c.http.as_ref().unwrap();
        assert_eq!(h.port, 8080);
        assert_eq!(h.health.as_deref(), Some("/healthz"));
        assert_eq!(h.domains, vec!["shop.example.com"]);
        assert_eq!(c.ports[0].port, 5432);
        assert!(c.ports[0].public);
        assert_eq!(c.ports[0].public_port, Some(5433));
        assert_eq!(c.volumes[0].name, "shop-data");
        assert_eq!(c.volumes[0].size.as_deref(), Some("5gb"));
        assert_eq!(c.scale.memory, "1024MB");
        assert_eq!(c.scale.cpu, 2.0);
        assert_eq!(c.scale.count, Some(1), "volumes: single instance");
        assert!(warnings.iter().any(|w| w.contains("release_command")));
        assert!(warnings.iter().any(|w| w.contains("own volume")));
    }

    #[test]
    fn stateless_keeps_machine_count_and_process_cmd() {
        let f = json!({
            "app": "api",
            "processes": {"app": "node server.js", "worker": "node worker.js"},
            "services": [{"internal_port": 3000, "ports": [{"port": 80, "handlers": ["http"]}, {"port": 443, "handlers": ["tls", "http"]}]}]
        });
        let (c, w) = convert_fly(&f, "api", 3, vec![]);
        c.validate().unwrap();
        assert_eq!(c.http.unwrap().port, 3000);
        assert_eq!(c.scale.count, Some(3));
        assert!(matches!(c.command, Some(Command::Shell(ref s)) if s == "node server.js"));
        assert!(w.iter().any(|w| w.contains("worker")));
    }

    #[test]
    fn flyctl_outputs() {
        let img = json!([{"MachineID": "x", "Registry": "registry.fly.io", "Repository": "api", "Tag": "deployment-01ABC", "Digest": "sha256:aa"}]);
        assert_eq!(find_image_ref(&img).unwrap(), "registry.fly.io/api:deployment-01ABC");
        let rel = json!([{"Version": 3, "ImageRef": "registry.fly.io/api:deployment-02"}]);
        assert_eq!(find_image_ref(&rel).unwrap(), "registry.fly.io/api:deployment-02");
        let names = secret_names(&json!([{"Name": "DATABASE_URL", "Digest": "x"}, {"name": "API_KEY"}]));
        assert_eq!(names, vec!["DATABASE_URL", "API_KEY"]);
        let env = "PATH=/usr/bin\r\nDATABASE_URL=postgres://u:p@h/db?x=1\r\nAPI_KEY=abc\r\nHOME=/root\n";
        let s = secrets_from_env(env, &names);
        assert_eq!(s["DATABASE_URL"], "postgres://u:p@h/db?x=1");
        assert_eq!(s.len(), 2);
        let m = json!([{"state": "started", "config": {"metadata": {"fly_process_group": "app"}}}, {"state": "stopped", "config": {"metadata": {"fly_process_group": "worker"}}}, {"state": "destroyed"}]);
        assert_eq!(count_machines(&m), 1);
        assert_eq!(hostnames(&json!([{"Hostname": "shop.com"}, {"Hostname": "x.fly.dev"}])), vec!["shop.com"]);
    }
}
