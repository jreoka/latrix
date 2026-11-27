//! `latrix launch` and `latrix deploy`.

use super::client::Client;
use crate::agent::builder::BUILD_HEADER;
use crate::api_types::*;
use crate::config::{self, AppConfig};
use crate::state::ReleaseStatus;
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use futures::StreamExt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn sanitize(name: &str) -> String {
    let s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let s = s.trim_matches('-').to_string();
    let mut out = String::new();
    for c in s.chars() {
        if !(c == '-' && out.ends_with('-')) {
            out.push(c);
        }
    }
    if out.is_empty() {
        "app".into()
    } else {
        out.chars().take(40).collect()
    }
}

/// Terminal width when stdout is an interactive terminal (and colors aren't
/// disabled with NO_COLOR / LATRIX_PLAIN); None means plain text output.
pub fn tty_width() -> Option<u16> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal()
        || std::env::var_os("NO_COLOR").is_some()
        || std::env::var_os("LATRIX_PLAIN").is_some()
        || std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false)
    {
        return None;
    }
    #[cfg(windows)]
    if enable_ansi_support::enable_ansi_support().is_err() {
        return None;
    }
    Some(terminal_size::terminal_size().map(|(w, _)| w.0).unwrap_or(100))
}

/// "==>" in bold blue on a terminal, plain otherwise.
pub fn arrow() -> &'static str {
    if tty_width().is_some() {
        "\x1b[1;34m==>\x1b[0m"
    } else {
        "==>"
    }
}

pub fn launch(name: Option<String>, image: Option<String>, port: Option<u16>, force: bool) -> Result<()> {
    let path = Path::new("latrix.toml");
    if path.exists() && !force {
        bail!("latrix.toml already exists (use --force to overwrite)");
    }
    let dir = std::env::current_dir()?;
    let name = sanitize(&name.unwrap_or_else(|| {
        dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "app".into())
    }));
    for f in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"] {
        if Path::new(f).exists() && image.is_none() {
            println!("Found {f}. You can deploy it directly with:\n  latrix deploy --compose {f}\nor convert it with `latrix compose convert {f} --write`.");
            if !Path::new("Dockerfile").exists() {
                return Ok(());
            }
        }
    }
    let mut detected_port = port;
    if image.is_none() {
        match std::fs::read_to_string("Dockerfile") {
            Ok(df) => {
                if detected_port.is_none() {
                    detected_port = df.lines().find_map(|l| {
                        let l = l.trim();
                        let rest = l.strip_prefix("EXPOSE ").or_else(|| l.strip_prefix("expose "))?;
                        rest.split_whitespace().next()?.split('/').next()?.parse().ok()
                    });
                }
                println!("Detected Dockerfile{}", detected_port.map(|p| format!(" (EXPOSE {p})")).unwrap_or_default());
            }
            Err(_) => {
                println!("No Dockerfile found. Add one, or re-run with --image <image> to deploy a prebuilt image.");
            }
        }
    }
    let text = config::template(&name, detected_port.or(if image.is_some() { None } else { Some(8080) }), image.as_deref());
    std::fs::write(path, &text)?;
    let cfg: AppConfig = toml::from_str(&text)?;
    cfg.validate()?;
    println!("Wrote latrix.toml for app '{name}'. Edit it if you like, then run `latrix deploy`.");
    Ok(())
}

/// Gzipped tarball of the build context. Honors .dockerignore, or .gitignore
/// when there is no .dockerignore. `.git` is never uploaded.
pub fn pack_context(dir: &Path) -> Result<(PathBuf, u64, usize)> {
    let has_dockerignore = dir.join(".dockerignore").exists();
    let out = std::env::temp_dir().join(format!("latrix-ctx-{}.tar.gz", crate::util::random_id(8)));
    let file = std::fs::File::create(&out)?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    tar.follow_symlinks(false);
    let mut walker = ignore::WalkBuilder::new(dir);
    walker
        .hidden(false)
        .git_ignore(!has_dockerignore)
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .parents(false)
        .ignore(false)
        .add_custom_ignore_filename(".dockerignore")
        .filter_entry(|e| e.file_name() != ".git");
    let mut files = 0;
    for entry in walker.build() {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(dir).unwrap_or(path);
        if rel.as_os_str().is_empty() {
            continue;
        }
        let ft = entry.file_type();
        if ft.map(|t| t.is_file() || t.is_symlink()).unwrap_or(false) {
            tar.append_path_with_name(path, rel)
                .with_context(|| format!("adding {}", path.display()))?;
            files += 1;
        }
    }
    let gz = tar.into_inner()?;
    let mut f = gz.finish()?;
    f.flush()?;
    let size = std::fs::metadata(&out)?.len();
    Ok((out, size, files))
}

pub async fn build(client: &Client, app: &AppConfig, base: &Path) -> Result<(String, u32)> {
    let plan: BuildPlan = client
        .post(&format!("/v1/apps/{}/build-plan", app.app), &serde_json::json!({}))
        .await?;
    let req = BuildRequest {
        app: app.app.clone(),
        tag: plan.tag.clone(),
        dockerfile: app.build.dockerfile.clone(),
        target: app.build.target.clone(),
        args: app.build.args.clone(),
        git: app.build.git.clone(),
        branch: app.build.branch.clone(),
        context: app.build.context.clone(),
        cache_from: plan.cache_from.clone(),
        tty_cols: tty_width(),
    };
    let header = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&req)?);
    let mut rb = client
        .request(reqwest::Method::POST, &format!("/v1/m/{}/build", plan.machine))
        .header(BUILD_HEADER, header);
    let mut cleanup = None;
    if app.build.git.is_none() {
        let ctx = base.join(app.build.context.as_deref().unwrap_or("."));
        if !ctx.is_dir() {
            bail!("build context {} is not a directory", ctx.display());
        }
        let (archive, size, files) = pack_context(&ctx)?;
        println!(
            "{} Uploading build context ({files} files, {:.1} MB) to {}",
            arrow(),
            size as f64 / 1048576.0,
            plan.machine_name
        );
        let f = tokio::fs::File::open(&archive).await?;
        rb = rb.body(reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(f)));
        cleanup = Some(archive);
    } else {
        println!("{} Building {} from git on {}", arrow(), app.build.git.as_deref().unwrap(), plan.machine_name);
    }
    let resp = rb.send().await;
    if let Some(p) = cleanup {
        let _ = std::fs::remove_file(p);
    }
    let resp = resp?;
    if !resp.status().is_success() {
        bail!("build request failed: {} {}", resp.status(), resp.text().await.unwrap_or_default());
    }
    let mut stream = resp.bytes_stream();
    let mut buf = String::new();
    let mut result: Option<BuildResult> = None;
    let raw = req.tty_cols.is_some();
    let mut out = std::io::stdout();
    while let Some(chunk) = stream.next().await {
        buf.push_str(&String::from_utf8_lossy(&chunk?));
        if raw {
            // Docker's live view: print everything as it arrives, except the
            // final result line (which may be split across chunks).
            match buf.find(BUILD_RESULT_PREFIX) {
                Some(i) => {
                    out.write_all(buf[..i].as_bytes())?;
                    buf.drain(..i);
                    if let Some(end) = buf.find('\n') {
                        let line: String = buf.drain(..=end).collect();
                        result = serde_json::from_str(line.trim_end().trim_start_matches(BUILD_RESULT_PREFIX)).ok();
                    }
                }
                None => {
                    // Keep a possible partial marker at the end.
                    let keep = (BUILD_RESULT_PREFIX.len()).min(buf.len());
                    let mut cut = buf.len() - keep;
                    while !buf.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    out.write_all(buf[..cut].as_bytes())?;
                    buf.drain(..cut);
                }
            }
            out.flush()?;
            continue;
        }
        while let Some(i) = buf.find('\n') {
            let line: String = buf.drain(..=i).collect();
            let line = line.trim_end();
            if let Some(json) = line.strip_prefix(BUILD_RESULT_PREFIX) {
                result = serde_json::from_str(json).ok();
            } else if !line.is_empty() {
                println!("    {line}");
            }
        }
    }
    if raw {
        print!("\x1b[0m\x1b[?25h"); // reset colors, show the cursor
        let _ = out.flush();
    }
    let r = result.ok_or_else(|| anyhow!("build connection closed before finishing"))?;
    if !r.ok {
        bail!("build failed: {}", r.error.unwrap_or_default());
    }
    println!("{} Built {} in {}s", arrow(), r.image, r.seconds);
    Ok((r.image, plan.machine))
}

pub async fn deploy_one(client: &Client, app: &AppConfig, base: &Path, detach: bool, message: Option<String>) -> Result<()> {
    app.validate()?;
    println!("{} Deploying {}", arrow(), app.app);
    let (image, builder) = match &app.build.image {
        Some(img) => (img.clone(), None),
        None => {
            let (img, m) = build(client, app, base).await?;
            (img, Some(m))
        }
    };
    let resp: DeployResponse = client
        .post(
            &format!("/v1/apps/{}/deploy", app.app),
            &DeployRequest {
                config: app.clone(),
                image,
                builder,
                description: message.unwrap_or_default(),
            },
        )
        .await?;
    println!("{} Release v{} created", arrow(), resp.version);
    if detach {
        return Ok(());
    }
    watch(client, &app.app, resp.version, app.deploy.health_timeout_secs()).await
}

pub async fn watch(client: &Client, app: &str, version: u64, health_timeout: u64) -> Result<()> {
    let start = Instant::now();
    let mut last = String::new();
    let limit = Duration::from_secs(health_timeout * 2 + 120);
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let v: AppView = client.get(&format!("/v1/apps/{app}")).await?;
        let status = v.releases.iter().find(|r| r.version == version).map(|r| r.status.clone());
        let mine: Vec<&InstanceView> = v
            .instances
            .iter()
            .filter(|i| i.instance.release == version && !i.instance.stopping)
            .collect();
        let healthy = mine.iter().filter(|i| i.report.as_ref().map(|r| r.healthy).unwrap_or(false)).count();
        let mut states: Vec<String> = mine
            .iter()
            .map(|i| {
                let st = i.report.as_ref().map(|r| r.status.clone()).unwrap_or_else(|| "pending".into());
                format!("{}@{}", st, i.machine_name)
            })
            .collect();
        states.sort();
        let errors: Vec<String> = mine
            .iter()
            .filter_map(|i| i.report.as_ref().and_then(|r| r.error.clone()))
            .collect();
        let line = format!(
            "    {healthy}/{} healthy  [{}]{}",
            v.count,
            states.join(", "),
            errors.first().map(|e| format!("\n    ! {e}")).unwrap_or_default()
        );
        if line != last {
            println!("{line}");
            last = line;
        }
        match status {
            Some(ReleaseStatus::Active) => {
                let color = tty_width().is_some();
                let (g, c, r) = if color { ("\x1b[1;32m", "\x1b[36m", "\x1b[0m") } else { ("", "", "") };
                println!("\n{g}✓ {app} v{version} is live{r}");
                for u in &v.urls {
                    println!("  {c}{u}{r}");
                }
                if !v.internal.is_empty() {
                    println!("  internal: {}", v.internal.join(", "));
                }
                return Ok(());
            }
            Some(ReleaseStatus::Failed) => {
                bail!(
                    "release v{version} did not pass health checks and was rolled back.\n  See what happened: latrix logs {app}"
                );
            }
            Some(ReleaseStatus::Superseded) => {
                println!("release v{version} was superseded by a newer deploy");
                return Ok(());
            }
            None => bail!("release v{version} disappeared"),
            _ => {}
        }
        if start.elapsed() > limit {
            println!("still rolling out in the background — check `latrix ps {app}`");
            return Ok(());
        }
    }
}
