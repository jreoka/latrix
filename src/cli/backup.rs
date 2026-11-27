//! `latrix backup` / `latrix restore`.
//!
//! A backup is one file on your computer (a plain tar) holding everything
//! needed to bring an app back on any latrix cluster:
//!
//! ```text
//! manifest.json        config, secrets, instance count, image reference
//! image.tar.gz         the image (docker save), unless it's a public image
//! volumes/<name>.tar.gz  a snapshot of each volume
//! ```

use super::client::Client;
use super::profile::CliConfig;
use crate::api_types::*;
use crate::config::AppConfig;
use crate::util::{self, now};
use anyhow::{anyhow, bail, Context, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const FORMAT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    pub app: String,
    pub created_at: u64,
    /// "latrix" or "fly:<app>"
    pub source: String,
    pub config: AppConfig,
    pub image: String,
    #[serde(default)]
    pub image_file: Option<String>,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    pub count: u32,
    #[serde(default)]
    pub volumes: Vec<ManifestVolume>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestVolume {
    pub name: String,
    pub path: String,
    pub file: String,
}

/// "2026-11-27-0156" in UTC, without pulling in a date library.
pub fn stamp(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let (h, m) = ((secs % 86400) / 3600, (secs % 3600) / 60);
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    format!("{y:04}-{mo:02}-{d:02}-{h:02}{m:02}")
}

pub fn default_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join("latrix-backups")
}

pub fn temp_dir(tag: &str) -> Result<PathBuf> {
    let d = std::env::temp_dir().join(format!("latrix-{tag}-{}", util::random_id(6)));
    std::fs::create_dir_all(&d)?;
    Ok(d)
}

/// Write manifest + files into one tar file (readable only by you: it holds secrets).
pub fn write_archive(out: &Path, manifest: &Manifest, files: &[(String, PathBuf)]) -> Result<()> {
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let f = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    crate::agent::set_private(out);
    let mut tar = tar::Builder::new(f);
    let json = serde_json::to_vec_pretty(manifest)?;
    let mut h = tar::Header::new_gnu();
    h.set_size(json.len() as u64);
    h.set_mode(0o600);
    h.set_mtime(manifest.created_at);
    h.set_cksum();
    tar.append_data(&mut h, "manifest.json", json.as_slice())?;
    for (name, path) in files {
        tar.append_path_with_name(path, name)?;
    }
    tar.into_inner()?.flush()?;
    Ok(())
}

pub fn read_archive(path: &Path) -> Result<(Manifest, PathBuf)> {
    let dir = temp_dir("restore")?;
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    tar::Archive::new(f).unpack(&dir).context("not a latrix backup file")?;
    let m: Manifest = serde_json::from_slice(
        &std::fs::read(dir.join("manifest.json")).context("backup has no manifest.json")?,
    )?;
    if m.format > FORMAT {
        bail!("this backup was made by a newer latrix (format {}); upgrade latrix", m.format);
    }
    Ok((m, dir))
}

/// Stream a GET response to a file.
pub async fn download(c: &Client, path: &str, dest: &Path) -> Result<u64> {
    let r = c.request(reqwest::Method::GET, path).send().await?;
    if !r.status().is_success() {
        let status = r.status();
        let body = r.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<ApiErrorBody>(&body).map(|e| e.error).unwrap_or(body);
        bail!("{status}: {msg}");
    }
    let mut f = std::fs::File::create(dest)?;
    let mut n = 0u64;
    let mut s = r.bytes_stream();
    while let Some(chunk) = s.next().await {
        let chunk = chunk?;
        n += chunk.len() as u64;
        f.write_all(&chunk)?;
    }
    f.flush()?;
    Ok(n)
}

/// POST a file as the request body.
pub async fn upload(c: &Client, path: &str, file: &Path) -> Result<serde_json::Value> {
    let f = tokio::fs::File::open(file).await?;
    let r = c
        .request(reqwest::Method::POST, path)
        .body(reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(f)))
        .send()
        .await?;
    let status = r.status();
    let body = r.text().await.unwrap_or_default();
    if !status.is_success() {
        let msg = serde_json::from_str::<ApiErrorBody>(&body).map(|e| e.error).unwrap_or(body);
        bail!("{status}: {msg}");
    }
    Ok(serde_json::from_str(&body).unwrap_or_default())
}

fn mb(n: u64) -> String {
    format!("{:.1} MB", n as f64 / 1048576.0)
}

async fn wait_stopped(c: &Client, app: &str) -> Result<()> {
    let start = Instant::now();
    loop {
        let v: AppView = c.get(&format!("/v1/apps/{app}")).await?;
        if v.instances.is_empty() {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(180) {
            bail!("{app} did not stop within 3 minutes");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn scale_to(c: &Client, app: &str, count: u32) -> Result<()> {
    let _: AppView = c
        .post(&format!("/v1/apps/{app}/scale"), &ScaleRequest { count: Some(count), ..Default::default() })
        .await?;
    Ok(())
}

fn looks_like_database(image: &str) -> bool {
    ["postgres", "mysql", "mariadb", "mongo", "redis", "valkey", "clickhouse", "influx", "timescale"]
        .iter()
        .any(|d| image.contains(d))
}

/// Back up one app into `out_dir`. Returns the backup file path.
pub async fn backup_app(c: &Client, app: &str, out_dir: &Path, with_image: bool, stop: bool) -> Result<PathBuf> {
    let ex: AppExport = c.get(&format!("/v1/apps/{app}/export")).await?;
    let work = temp_dir("backup")?;
    let mut files = vec![];
    let mut manifest = Manifest {
        format: FORMAT,
        app: app.to_string(),
        created_at: now(),
        source: "latrix".into(),
        config: ex.config.clone(),
        image: ex.image.clone(),
        image_file: None,
        secrets: ex.secrets.clone(),
        count: ex.count,
        volumes: vec![],
    };
    println!("==> {app}");

    // Image: built ones live only in the cluster registry, so save them.
    if with_image && !ex.sources.is_empty() {
        let dest = work.join("image.tar.gz");
        let st: StatusView = c.get("/v1/status").await?;
        let mut machines: Vec<u32> = ex.sources.clone();
        machines.extend(st.machines.iter().filter(|m| m.alive).map(|m| m.machine.id));
        let mut done = false;
        for m in machines {
            let path = format!("/v1/m/{m}/image?ref={}", ex.image);
            if let Ok(n) = download(c, &path, &dest).await {
                println!("    image {} ({})", ex.image, mb(n));
                done = true;
                break;
            }
        }
        if !done {
            bail!("could not download the image {} from any machine", ex.image);
        }
        files.push(("image.tar.gz".to_string(), dest));
        manifest.image_file = Some("image.tar.gz".into());
    }

    // Volumes, optionally with the app stopped for a consistent copy.
    let stopped = stop && !ex.volumes.is_empty() && ex.count > 0;
    if !ex.volumes.is_empty() && !stop {
        let has_hook = ex.config.volumes.iter().any(|v| v.pre_sync.is_some());
        if looks_like_database(&ex.image) && !has_hook {
            println!("    note: this looks like a database; use --stop for a guaranteed-consistent copy");
        }
    }
    if stopped {
        println!("    stopping {app} for a consistent snapshot");
        scale_to(c, app, 0).await?;
        wait_stopped(c, app).await?;
    }
    let result: Result<()> = async {
        for v in &ex.volumes {
            let file = format!("volumes/{}.tar.gz", v.name);
            let dest = work.join(format!("vol-{}.tar.gz", v.name));
            let n = download(c, &format!("/v1/m/{}/volume-data?volume={}", v.primary, v.id), &dest)
                .await
                .with_context(|| format!("downloading volume {}", v.name))?;
            println!("    volume {} ({})", v.name, mb(n));
            files.push((file.clone(), dest));
            manifest.volumes.push(ManifestVolume { name: v.name.clone(), path: v.path.clone(), file });
        }
        Ok(())
    }
    .await;
    if stopped {
        scale_to(c, app, ex.count).await?;
        println!("    {app} started again");
    }
    result?;
    let out = out_dir.join(format!("{app}-{}.latrix-backup.tar", stamp(now())));
    write_archive(&out, &manifest, &files)?;
    let _ = std::fs::remove_dir_all(&work);
    println!(
        "    saved {} ({}, {} secret(s))",
        out.display(),
        mb(std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0)),
        manifest.secrets.len()
    );
    Ok(out)
}

pub async fn backup(cfg: &CliConfig, cl: Option<&str>, apps: Vec<String>, all: bool, out: Option<PathBuf>, no_image: bool, stop: bool) -> Result<()> {
    let (_, p) = cfg.profile(cl)?;
    if p.kubernetes.is_some() {
        bail!("backups are for latrix clusters; for Kubernetes use your cluster's backup tooling (e.g. Velero)");
    }
    let c = Client::connect(&p).await?;
    let apps = if all || apps.is_empty() {
        let st: StatusView = c.get("/v1/status").await?;
        if !all && st.apps.len() > 1 {
            bail!("name the app(s) to back up, or pass --all ({})", st.apps.iter().map(|a| a.name.clone()).collect::<Vec<_>>().join(", "));
        }
        st.apps.iter().map(|a| a.name.clone()).collect()
    } else {
        apps
    };
    if apps.is_empty() {
        bail!("there are no apps to back up");
    }
    let dir = out.unwrap_or_else(default_dir);
    let mut failed = vec![];
    for a in &apps {
        if let Err(e) = backup_app(&c, a, &dir, !no_image, stop).await {
            println!("✗ {a}: {e:#}");
            failed.push(a.clone());
        }
    }
    println!("\nBackups are in {} (they contain secrets — keep them safe).", dir.display());
    println!("Restore with: latrix restore <file> [--as new-name]");
    if !failed.is_empty() {
        bail!("{} backup(s) failed: {}", failed.len(), failed.join(", "));
    }
    Ok(())
}

/// Recreate an app from an unpacked backup: create it stopped, put secrets
/// and volume data in place, then start it with its original scale.
pub async fn restore_bundle(c: &Client, m: &Manifest, dir: &Path, name: &str, message: &str) -> Result<()> {
    util::validate_name("app", name)?;
    if c.get::<AppView>(&format!("/v1/apps/{name}")).await.is_ok() {
        bail!("an app named '{name}' already exists; restore under another name with --as, or `latrix destroy {name}` first");
    }
    let mut config = m.config.clone();
    config.app = name.to_string();
    config.validate()?;

    // 1. image
    let (image, builder) = match &m.image_file {
        Some(f) => {
            let plan: BuildPlan = c.post(&format!("/v1/apps/{name}/build-plan"), &serde_json::json!({})).await?;
            println!("==> uploading the image to {}", plan.machine_name);
            let v = upload(c, &format!("/v1/m/{}/image?app={name}&tag={}", plan.machine, plan.tag), &dir.join(f)).await?;
            let img = v["image"].as_str().ok_or_else(|| anyhow!("upload returned no image"))?.to_string();
            (img, Some(plan.machine))
        }
        None => (m.image.clone(), None),
    };

    // 2. create it stopped (count 0) so volumes exist but nothing runs
    let mut stopped = config.clone();
    stopped.scale.count = Some(0);
    stopped.scale.min = None;
    stopped.scale.max = None;
    let _: DeployResponse = c
        .post(
            &format!("/v1/apps/{name}/deploy"),
            &DeployRequest { config: stopped, image: image.clone(), builder, description: "restore: create".into() },
        )
        .await?;

    // 3. secrets
    if !m.secrets.is_empty() {
        let _: DeployResponse = c
            .post(&format!("/v1/apps/{name}/secrets"), &SecretsRequest { set: m.secrets.clone(), unset: vec![] })
            .await?;
        println!("==> restored {} secret(s)", m.secrets.len());
    }

    // 4. volume data onto the volume's primary machine
    if !m.volumes.is_empty() {
        let v: AppView = c.get(&format!("/v1/apps/{name}")).await?;
        for mv in &m.volumes {
            let Some(vol) = v.volumes.iter().find(|x| x.volume.name == mv.name) else {
                println!("    (volume {} is not in the config any more; skipped)", mv.name);
                continue;
            };
            println!("==> restoring volume {} on {}", mv.name, vol.primary_name);
            upload(c, &format!("/v1/m/{}/volume-data?volume={}", vol.volume.primary, vol.volume.id), &dir.join(&mv.file)).await?;
        }
    }

    // 5. start it for real
    let r: DeployResponse = c
        .post(
            &format!("/v1/apps/{name}/deploy"),
            &DeployRequest { config: config.clone(), image, builder, description: message.into() },
        )
        .await?;
    super::deploy::watch(c, name, r.version, config.deploy.health_timeout_secs()).await
}

pub async fn restore(cfg: &CliConfig, cl: Option<&str>, file: &Path, as_name: Option<String>) -> Result<()> {
    let (_, p) = cfg.profile(cl)?;
    if p.kubernetes.is_some() {
        bail!("restore targets latrix clusters");
    }
    let (m, dir) = read_archive(file)?;
    println!(
        "==> restoring {} from {} (made {}{})",
        m.app,
        file.display(),
        util::ago(m.created_at),
        if m.source != "latrix" { format!(", imported from {}", m.source) } else { String::new() }
    );
    let c = Client::connect(&p).await?;
    let name = as_name.unwrap_or_else(|| m.app.clone());
    let res = restore_bundle(&c, &m, &dir, &name, &format!("restored from backup of {}", util::ago(m.created_at))).await;
    let _ = std::fs::remove_dir_all(&dir);
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps() {
        assert_eq!(stamp(0), "1970-01-01-0000");
        assert_eq!(stamp(1795741200), "2026-11-27-0100");
        assert_eq!(stamp(951782400), "2000-02-29-0000");
    }

    #[test]
    fn archive_roundtrip() {
        let dir = temp_dir("test").unwrap();
        let data = dir.join("vol.tar.gz");
        std::fs::write(&data, b"volume-bytes").unwrap();
        let cfg: AppConfig = toml::from_str("app = \"db\"\n[[volumes]]\nname = \"data\"\npath = \"/data\"\n").unwrap();
        let m = Manifest {
            format: FORMAT,
            app: "db".into(),
            created_at: 1,
            source: "latrix".into(),
            config: cfg,
            image: "postgres:16".into(),
            image_file: None,
            secrets: [("PW".to_string(), "s3cret".to_string())].into(),
            count: 1,
            volumes: vec![ManifestVolume { name: "data".into(), path: "/data".into(), file: "volumes/data.tar.gz".into() }],
        };
        let out = dir.join("b.tar");
        write_archive(&out, &m, &[("volumes/data.tar.gz".into(), data)]).unwrap();
        let (back, unpacked) = read_archive(&out).unwrap();
        assert_eq!(back.secrets["PW"], "s3cret");
        assert_eq!(std::fs::read(unpacked.join("volumes/data.tar.gz")).unwrap(), b"volume-bytes");
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(unpacked);
    }
}
