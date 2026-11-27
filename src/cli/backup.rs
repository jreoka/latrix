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
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_ARCHIVE_ENTRIES: usize = 1024;
const MAX_ARCHIVE_BYTES: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB

struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_records: Vec<crate::config::DnsRecordConfig>,
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
    let d = std::env::temp_dir().join(format!("latrix-{tag}-{}", util::random_id(8)));
    util::create_private_dir_all(&d)?;
    Ok(d)
}

fn create_private_file(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).with_context(|| format!("creating {}", path.display()))
}

/// Write manifest + files into one tar file (readable only by you: it holds secrets).
pub fn write_archive(out: &Path, manifest: &Manifest, files: &[(String, PathBuf)]) -> Result<()> {
    if let Some(dir) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = out.with_extension(format!("tmp-{}", util::random_id(8)));
    let res = (|| -> Result<()> {
        let f = create_private_file(&tmp)?;
        let mut tar = tar::Builder::new(f);
        let json = serde_json::to_vec_pretty(manifest)?;
        let mut h = tar::Header::new_gnu();
        h.set_size(json.len() as u64);
        h.set_mode(0o600);
        h.set_mtime(manifest.created_at);
        h.set_cksum();
        tar.append_data(&mut h, "manifest.json", json.as_slice())?;
        for (name, path) in files {
            let mut src = std::fs::File::open(path)?;
            let meta = src.metadata()?;
            let mut fh = tar::Header::new_gnu();
            fh.set_size(meta.len());
            fh.set_mode(0o600);
            fh.set_mtime(manifest.created_at);
            fh.set_cksum();
            tar.append_data(&mut fh, name, &mut src)?;
        }
        let mut inner = tar.into_inner()?;
        inner.flush()?;
        inner.sync_all()?;
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, out) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("moving backup archive into {}", out.display()));
    }
    crate::agent::set_private(out);
    Ok(())
}

fn validate_backup_rel_path(raw: &str) -> Result<PathBuf> {
    if raw.contains('\0') {
        bail!("unsafe NUL byte in backup path");
    }
    let norm = raw.replace('\\', "/");
    let trimmed = norm.trim_start_matches("./");
    let mut out = PathBuf::new();
    for c in Path::new(trimmed).components() {
        match c {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe path in backup archive: '{raw}'");
            }
        }
    }
    Ok(out)
}

fn is_allowed_backup_file(rel: &Path) -> bool {
    let comps: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    match comps.as_slice() {
        [a] if a == "manifest.json" || a == "image.tar.gz" => true,
        [a, b] if a == "volumes" && b.ends_with(".tar.gz") && !b.starts_with('.') => true,
        _ => false,
    }
}

fn resolve_backup_member(dir: &Path, rel_raw: &str) -> Result<PathBuf> {
    let rel = validate_backup_rel_path(rel_raw)?;
    if !is_allowed_backup_file(&rel) {
        bail!("disallowed member path '{rel_raw}' in backup manifest");
    }
    let full = dir.join(&rel);
    let meta = std::fs::symlink_metadata(&full)
        .with_context(|| format!("backup member '{rel_raw}' missing from archive"))?;
    if !meta.file_type().is_file() {
        bail!("backup member '{rel_raw}' is not a regular file");
    }
    let canon_dir = std::fs::canonicalize(dir)?;
    let canon_file = std::fs::canonicalize(&full)?;
    if !canon_file.starts_with(&canon_dir) {
        bail!("backup member '{rel_raw}' escapes backup directory");
    }
    Ok(canon_file)
}

pub fn read_archive(path: &Path) -> Result<(Manifest, PathBuf)> {
    let dir = temp_dir("restore")?;
    let res = (|| -> Result<Manifest> {
        let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut ar = tar::Archive::new(f);
        let mut count = 0usize;
        let mut total = 0u64;
        for entry in ar.entries().context("not a latrix backup file")? {
            count += 1;
            if count > MAX_ARCHIVE_ENTRIES {
                bail!("backup archive has too many entries");
            }
            let mut entry = entry?;
            let etype = entry.header().entry_type();
            let raw = entry.path()?.to_string_lossy().replace('\\', "/");
            let rel = validate_backup_rel_path(&raw)?;
            if rel.as_os_str().is_empty() {
                if etype.is_dir() {
                    continue;
                }
                bail!("empty path in backup archive");
            }
            let dest = dir.join(&rel);
            if etype.is_dir() {
                std::fs::create_dir_all(&dest)?;
                continue;
            }
            if !etype.is_file() {
                bail!("disallowed entry type {:?} in backup archive: '{raw}'", etype);
            }
            if !is_allowed_backup_file(&rel) {
                bail!("unexpected file '{raw}' in backup archive");
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = std::fs::File::create(&dest)?;
            crate::agent::set_private(&dest);
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = entry.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total = total.saturating_add(n as u64);
                if total > MAX_ARCHIVE_BYTES {
                    bail!("backup archive exceeds maximum allowed size");
                }
                out.write_all(&buf[..n])?;
            }
            out.flush()?;
        }
        let m: Manifest = serde_json::from_slice(
            &std::fs::read(dir.join("manifest.json")).context("backup has no manifest.json")?,
        )?;
        if m.format > FORMAT {
            bail!("this backup was made by a newer latrix (format {}); upgrade latrix", m.format);
        }
        Ok(m)
    })();
    match res {
        Ok(m) => Ok((m, dir)),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            Err(e)
        }
    }
}

/// Stream a GET response to a file (with a per-chunk stall timeout).
pub async fn download(c: &Client, path: &str, dest: &Path) -> Result<u64> {
    let r = c.request(reqwest::Method::GET, path).send().await?;
    if !r.status().is_success() {
        let status = r.status();
        let body = r.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<ApiErrorBody>(&body).map(|e| e.error).unwrap_or(body);
        bail!("{status}: {msg}");
    }
    let mut f = std::fs::File::create(dest)?;
    crate::agent::set_private(dest);
    let mut n = 0u64;
    let mut s = r.bytes_stream();
    while let Some(chunk) = tokio::time::timeout(Duration::from_secs(120), s.next())
        .await
        .context("download timed out waiting for data")?
    {
        let chunk = chunk?;
        n += chunk.len() as u64;
        f.write_all(&chunk)?;
    }
    f.flush()?;
    Ok(n)
}

fn verify_gzip_integrity(path: &Path) -> Result<()> {
    let f = std::fs::File::open(path)?;
    let mut dec = flate2::read::GzDecoder::new(f);
    let mut sink = std::io::sink();
    std::io::copy(&mut dec, &mut sink)
        .with_context(|| format!("downloaded archive {} is corrupted or truncated", path.display()))?;
    Ok(())
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

async fn restore_scale(c: &Client, app: &str, ex: &AppExport) -> Result<()> {
    let req = if ex.config.scale.autoscale() {
        ScaleRequest {
            count: Some(ex.count),
            min: ex.config.scale.min,
            max: ex.config.scale.max,
            ..Default::default()
        }
    } else {
        ScaleRequest {
            count: Some(ex.count),
            ..Default::default()
        }
    };
    let _: AppView = c.post(&format!("/v1/apps/{app}/scale"), &req).await?;
    Ok(())
}

fn looks_like_database(image: &str) -> bool {
    let lower = image.to_ascii_lowercase();
    ["postgres", "mysql", "mariadb", "mongo", "redis", "valkey", "clickhouse", "influx", "timescale"]
        .iter()
        .any(|d| lower.contains(d))
}

/// Back up one app into `out_dir`. Returns the backup file path.
pub async fn backup_app(c: &Client, app: &str, out_dir: &Path, with_image: bool, stop: bool) -> Result<PathBuf> {
    util::validate_name("app", app)?;
    let ex: AppExport = c.get(&format!("/v1/apps/{app}/export")).await?;
    let work_guard = TempDirGuard(temp_dir("backup")?);
    let work = &work_guard.0;
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
        dns_records: ex.dns_records.clone(),
    };
    println!("==> {app}");

    // Image: built ones live only in the cluster registry, so save them.
    if with_image && !ex.sources.is_empty() {
        let dest = work.join("image.tar.gz");
        let st: StatusView = c.get("/v1/status").await?;
        let mut machines: Vec<u32> = vec![];
        for m in ex.sources.iter().copied().chain(st.machines.iter().filter(|m| m.alive).map(|m| m.machine.id)) {
            if !machines.contains(&m) {
                machines.push(m);
            }
        }
        let mut done = false;
        let mut url_builder = reqwest::Url::parse("http://placeholder.invalid/image")?;
        url_builder.query_pairs_mut().append_pair("ref", &ex.image);
        let query = url_builder.query().unwrap_or("");
        for m in machines {
            let path = format!("/v1/m/{m}/image?{query}");
            if let Ok(n) = download(c, &path, &dest).await {
                if verify_gzip_integrity(&dest).is_ok() {
                    println!("    image {} ({})", ex.image, mb(n));
                    done = true;
                    break;
                }
            }
        }
        if !done {
            bail!("could not download a valid copy of image {} from any machine", ex.image);
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
    }
    let result: Result<()> = async {
        if stopped {
            wait_stopped(c, app).await?;
        }
        for v in &ex.volumes {
            let file = format!("volumes/{}.tar.gz", v.name);
            let dest = work.join(format!("vol-{}.tar.gz", v.name));
            let n = download(c, &format!("/v1/m/{}/volume-data?volume={}", v.primary, v.id), &dest)
                .await
                .with_context(|| format!("downloading volume {}", v.name))?;
            verify_gzip_integrity(&dest)
                .with_context(|| format!("verifying downloaded volume {}", v.name))?;
            println!("    volume {} ({})", v.name, mb(n));
            files.push((file.clone(), dest));
            manifest.volumes.push(ManifestVolume { name: v.name.clone(), path: v.path.clone(), file });
        }
        Ok(())
    }
    .await;
    if stopped {
        if let Err(e) = restore_scale(c, app, &ex).await {
            eprintln!("    ! failed to restart {app} after backup: {e:#}");
        } else {
            println!("    {app} started again");
        }
    }
    result?;
    let t = now();
    let out = out_dir.join(format!("{app}-{}{:02}.latrix-backup.tar", stamp(t), t % 60));
    write_archive(&out, &manifest, &files)?;
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
            let img_path = resolve_backup_member(dir, f)?;
            let plan: BuildPlan = c.post(&format!("/v1/apps/{name}/build-plan"), &serde_json::json!({})).await?;
            println!("==> uploading the image to {}", plan.machine_name);
            let v = upload(c, &format!("/v1/m/{}/image?app={name}&tag={}", plan.machine, plan.tag), &img_path).await?;
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

    // If staging fails before the final deploy, clean up the half-restored stopped app.
    let staged: Result<()> = async {
        // 3. secrets
        if !m.secrets.is_empty() {
            let _: DeployResponse = c
                .post(&format!("/v1/apps/{name}/secrets"), &SecretsRequest { set: m.secrets.clone(), unset: vec![] })
                .await?;
            println!("==> restored {} secret(s)", m.secrets.len());
        }

        // 3b. CLI-managed DNS records
        if !m.dns_records.is_empty() {
            let _: DnsStatusView = c
                .post(&format!("/v1/apps/{name}/dns"), &AppDnsRequest { add: m.dns_records.clone(), remove: vec![] })
                .await?;
            println!("==> restored {} DNS record(s)", m.dns_records.len());
        }

        // 4. volume data onto the volume's primary machine
        if !m.volumes.is_empty() {
            let v: AppView = c.get(&format!("/v1/apps/{name}")).await?;
            for mv in &m.volumes {
                let Some(vol) = v.volumes.iter().find(|x| x.volume.name == mv.name) else {
                    println!("    (volume {} is not in the config any more; skipped)", mv.name);
                    continue;
                };
                let vol_path = resolve_backup_member(dir, &mv.file)?;
                println!("==> restoring volume {} on {}", mv.name, vol.primary_name);
                upload(c, &format!("/v1/m/{}/volume-data?volume={}", vol.volume.primary, vol.volume.id), &vol_path).await?;
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = staged {
        let _ = c.delete::<bool>(&format!("/v1/apps/{name}?purge_volumes=true")).await;
        return Err(e);
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
    // Connect before extracting secrets onto disk.
    let c = Client::connect(&p).await?;
    let (m, dir) = read_archive(file)?;
    let _guard = TempDirGuard(dir.clone());
    println!(
        "==> restoring {} from {} (made {}{})",
        m.app,
        file.display(),
        util::ago(m.created_at),
        if m.source != "latrix" { format!(", imported from {}", m.source) } else { String::new() }
    );
    let name = as_name.unwrap_or_else(|| m.app.clone());
    restore_bundle(&c, &m, &dir, &name, &format!("restored from backup of {}", util::ago(m.created_at))).await
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
            dns_records: vec![],
        };
        let out = dir.join("b.tar");
        write_archive(&out, &m, &[("volumes/data.tar.gz".into(), data)]).unwrap();
        let (back, unpacked) = read_archive(&out).unwrap();
        assert_eq!(back.secrets["PW"], "s3cret");
        assert_eq!(std::fs::read(unpacked.join("volumes/data.tar.gz")).unwrap(), b"volume-bytes");
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(unpacked);
    }

    #[test]
    fn read_archive_rejects_traversal_symlinks_and_unexpected_files() {
        let dir = temp_dir("bad-tar").unwrap();

        // Unexpected file outside allowlist
        let unexpected = dir.join("unexpected.tar");
        {
            let mut b = tar::Builder::new(std::fs::File::create(&unexpected).unwrap());
            let mut hdr = tar::Header::new_gnu();
            let data = b"evil";
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            b.append_data(&mut hdr, "etc/passwd", &data[..]).unwrap();
            b.finish().unwrap();
        }
        assert!(read_archive(&unexpected).is_err());

        // Symlink entry rejected
        let symlink_tar = dir.join("symlink.tar");
        {
            let mut b = tar::Builder::new(std::fs::File::create(&symlink_tar).unwrap());
            let mut hdr = tar::Header::new_gnu();
            hdr.set_entry_type(tar::EntryType::Symlink);
            hdr.set_size(0);
            hdr.set_mode(0o777);
            hdr.set_cksum();
            b.append_link(&mut hdr, "manifest.json", "/etc/shadow").unwrap();
            b.finish().unwrap();
        }
        assert!(read_archive(&symlink_tar).is_err());

        let _ = std::fs::remove_dir_all(dir);
    }
}
