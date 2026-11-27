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
    let truncated: String = out.chars().take(40).collect();
    let clean = truncated.trim_end_matches('-');
    if clean.is_empty() {
        "app".into()
    } else {
        clean.to_string()
    }
}

/// Returned when the user cancels a deploy or stops watching with Ctrl+C.
#[derive(Debug)]
pub struct DeployCancelled;

impl std::fmt::Display for DeployCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for DeployCancelled {}

struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct TtyReset(bool);

impl Drop for TtyReset {
    fn drop(&mut self) {
        if self.0 {
            let mut out = std::io::stdout();
            let _ = out.write_all(b"\x1b[?2026l\x1b[0m\x1b[?25h");
            let _ = out.flush();
        }
    }
}

/// Terminal `(cols, rows)` when stdout is an interactive terminal (and colors
/// aren't disabled with NO_COLOR / LATRIX_PLAIN); None means plain text output.
pub fn tty_size() -> Option<(u16, u16)> {
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
    let (w, h) = terminal_size::terminal_size()
        .map(|(w, h)| (w.0, h.0))
        .unwrap_or((100, 24));
    Some((w, h))
}

/// Terminal width when stdout is an interactive terminal (and colors aren't
/// disabled with NO_COLOR / LATRIX_PLAIN); None means plain text output.
pub fn tty_width() -> Option<u16> {
    tty_size().map(|(w, _)| w)
}

fn push_valid_utf8(carry: &mut Vec<u8>, bytes: &[u8], out: &mut String) {
    carry.extend_from_slice(bytes);
    let valid = match std::str::from_utf8(carry) {
        Ok(_) => carry.len(),
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        Err(_) => carry.len(),
    };
    if valid > 0 {
        let chunk: Vec<u8> = carry.drain(..valid).collect();
        out.push_str(&String::from_utf8_lossy(&chunk));
    }
}

/// True if `tail` (which starts with ESC) is a truncated CSI or OSC sequence.
fn is_incomplete_ansi(tail: &str) -> bool {
    let b = tail.as_bytes();
    if b.is_empty() || b[0] != 0x1b {
        return false;
    }
    if b.len() == 1 {
        return true;
    }
    match b[1] {
        b'[' => {
            // CSI ends at a final byte in 0x40..=0x7E. Cap length so malformed
            // input can't stall output forever.
            b.len() < 64 && !b[2..].iter().any(|&c| (0x40..=0x7e).contains(&c))
        }
        b']' => {
            // OSC ends at BEL or ST (ESC \).
            b.len() < 256 && !b[2..].contains(&0x07) && !tail[2..].contains("\x1b\\")
        }
        _ => false,
    }
}

/// Number of trailing bytes to hold back so we neither split `marker` nor
/// flush an incomplete ANSI escape sequence.
fn tail_keep_len(s: &str, marker: &str) -> usize {
    let mut keep = 0;
    let max = s.len().min(marker.len().saturating_sub(1));
    for k in (1..=max).rev() {
        if s.is_char_boundary(s.len() - k) && marker.starts_with(&s[s.len() - k..]) {
            keep = k;
            break;
        }
    }
    if let Some(esc) = s[..s.len() - keep].rfind('\x1b') {
        if is_incomplete_ansi(&s[esc..]) {
            keep = s.len() - esc;
        }
    }
    keep
}

fn write_raw_frame(out: &mut impl Write, data: &[u8]) -> std::io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    // DEC mode 2026 (Synchronized Output): terminals that support it (Windows
    // Terminal, iTerm2, Kitty, Alacritty, WezTerm, Ghostty) apply the whole
    // cursor-up + redraw atomically without flicker; others ignore it.
    out.write_all(b"\x1b[?2026h")?;
    out.write_all(data)?;
    out.write_all(b"\x1b[?2026l")?;
    out.flush()
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
    let cfg: AppConfig = toml::from_str(&text)?;
    cfg.validate()?;
    std::fs::write(path, &text)?;
    println!("Wrote latrix.toml for app '{name}'. Edit it if you like, then run `latrix deploy`.");
    Ok(())
}

fn create_private_temp(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path).with_context(|| format!("creating {}", path.display()))
}

/// Gzipped tarball of the build context. Honors .dockerignore, or .gitignore
/// when there is no .dockerignore. `.git` is never uploaded.
pub fn pack_context(dir: &Path) -> Result<(PathBuf, u64, usize)> {
    let has_dockerignore = dir.join(".dockerignore").exists();
    let canon_dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let out = std::env::temp_dir().join(format!("latrix-ctx-{}.tar.gz", crate::util::random_id(8)));
    let guard = TempFile(out.clone());
    let file = create_private_temp(&out)?;
    let out_canon = std::fs::canonicalize(&out).unwrap_or_else(|_| out.clone());
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
    let mut warned_dotenv = false;
    for entry in walker.build() {
        let entry = entry?;
        let path = entry.path();
        if path == out || path == out_canon {
            continue;
        }
        let rel = path.strip_prefix(dir).unwrap_or(path);
        if rel.as_os_str().is_empty() {
            continue;
        }
        let ft = entry.file_type();
        if ft.map(|t| t.is_symlink()).unwrap_or(false) {
            // Reject symlinks that escape the build context directory.
            if let Ok(target) = std::fs::read_link(path) {
                let resolved = if target.is_absolute() {
                    target
                } else {
                    path.parent().unwrap_or(dir).join(target)
                };
                if let Ok(canon_target) = std::fs::canonicalize(&resolved) {
                    if !canon_target.starts_with(&canon_dir) {
                        bail!(
                            "symlink '{}' in build context points outside the build directory ({})",
                            rel.display(),
                            canon_target.display()
                        );
                    }
                }
            }
            tar.append_path_with_name(path, rel)
                .with_context(|| format!("adding {}", path.display()))?;
            files += 1;
        } else if ft.map(|t| t.is_file()).unwrap_or(false) {
            if !warned_dotenv {
                if let Some(fname) = path.file_name().and_then(|s| s.to_str()) {
                    if (fname == ".env" || fname.starts_with(".env."))
                        && !matches!(fname, ".env.example" | ".env.sample" | ".env.template")
                    {
                        println!("    ! warning: including '{fname}' in build context (add it to .dockerignore and use `latrix secrets set` for secrets)");
                        warned_dotenv = true;
                    }
                }
            }
            tar.append_path_with_name(path, rel)
                .with_context(|| format!("adding {}", path.display()))?;
            files += 1;
        } else if ft.map(|t| t.is_dir()).unwrap_or(false) {
            let _ = tar.append_dir(rel, path);
        }
    }
    let gz = tar.into_inner()?;
    let mut f = gz.finish()?;
    f.flush()?;
    let size = std::fs::metadata(&out)?.len();
    std::mem::forget(guard);
    Ok((out, size, files))
}

pub async fn build(client: &Client, app: &AppConfig, base: &Path) -> Result<(String, u32)> {
    let plan: BuildPlan = client
        .post(&format!("/v1/apps/{}/build-plan", app.app), &serde_json::json!({}))
        .await?;
    let tty = tty_size();
    let req = BuildRequest {
        app: app.app.clone(),
        tag: plan.tag.clone(),
        dockerfile: app.build.dockerfile.as_ref().map(|s| s.replace('\\', "/")),
        target: app.build.target.clone(),
        args: app.build.args.clone(),
        git: app.build.git.clone(),
        branch: app.build.branch.clone(),
        context: app.build.context.as_ref().map(|s| s.replace('\\', "/")),
        cache_from: plan.cache_from.clone(),
        tty_cols: tty.map(|(w, _)| w),
        tty_rows: tty.map(|(_, h)| h),
    };
    let header = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&req)?);
    // Keep TempFile declared before `rb` so the file handle closes before removal on Windows.
    let mut _cleanup: Option<TempFile> = None;
    let mut rb = client
        .request(reqwest::Method::POST, &format!("/v1/m/{}/build", plan.machine))
        .header(BUILD_HEADER, header);
    if app.build.git.is_none() {
        let ctx = base.join(app.build.context.as_deref().unwrap_or("."));
        if !ctx.is_dir() {
            bail!("build context {} is not a directory", ctx.display());
        }
        let ctx_clone = ctx.clone();
        let (archive, size, files) = tokio::task::spawn_blocking(move || pack_context(&ctx_clone)).await??;
        println!(
            "{} Uploading build context ({files} files, {:.1} MB) to {}",
            arrow(),
            size as f64 / 1048576.0,
            plan.machine_name
        );
        let f = tokio::fs::File::open(&archive).await?;
        _cleanup = Some(TempFile(archive));
        rb = rb.body(reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(f)));
    } else {
        println!(
            "{} Building {} from git on {}",
            arrow(),
            crate::util::redact_url_creds(app.build.git.as_deref().unwrap()),
            plan.machine_name
        );
    }
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let resp = tokio::select! {
        r = rb.send() => r,
        _ = &mut ctrl_c => {
            println!("\nCancelled build — nothing was deployed.");
            return Err(DeployCancelled.into());
        }
    };
    drop(_cleanup);
    let resp = resp?;
    if !resp.status().is_success() {
        bail!("build request failed: {} {}", resp.status(), resp.text().await.unwrap_or_default());
    }
    let mut stream = resp.bytes_stream();
    let mut raw_carry: Vec<u8> = Vec::new();
    let mut buf = String::new();
    let mut result: Option<BuildResult> = None;
    let raw = req.tty_cols.is_some();
    let _tty_reset = TtyReset(raw);
    let mut out = std::io::stdout();
    let mut eof = false;
    while !eof {
        let first = tokio::select! {
            c = stream.next() => c,
            _ = &mut ctrl_c => {
                drop(stream);
                drop(_tty_reset);
                println!("\nCancelled build — nothing was deployed.");
                return Err(DeployCancelled.into());
            }
        };
        let Some(chunk) = first else { break };
        push_valid_utf8(&mut raw_carry, &chunk?, &mut buf);
        if raw {
            // Coalesce back-to-back TCP chunks of the same BuildKit redraw
            // before painting inside a single synchronized update.
            while buf.len() < 64 * 1024 && !buf.contains(BUILD_RESULT_PREFIX) {
                let next = tokio::select! {
                    r = tokio::time::timeout(Duration::from_millis(8), stream.next()) => r,
                    _ = &mut ctrl_c => {
                        drop(stream);
                        drop(_tty_reset);
                        println!("\nCancelled build — nothing was deployed.");
                        return Err(DeployCancelled.into());
                    }
                };
                match next {
                    Ok(Some(c)) => push_valid_utf8(&mut raw_carry, &c?, &mut buf),
                    Ok(None) => {
                        eof = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            // Docker's live view: print everything as it arrives, except the
            // final result line (which may be split across chunks).
            match buf.find(BUILD_RESULT_PREFIX) {
                Some(i) => {
                    write_raw_frame(&mut out, &buf.as_bytes()[..i])?;
                    buf.drain(..i);
                    if let Some(end) = buf.find('\n') {
                        let line: String = buf.drain(..=end).collect();
                        result = serde_json::from_str(line.trim_end().trim_start_matches(BUILD_RESULT_PREFIX)).ok();
                    }
                }
                None => {
                    let keep = tail_keep_len(&buf, BUILD_RESULT_PREFIX);
                    let cut = buf.len() - keep;
                    write_raw_frame(&mut out, &buf.as_bytes()[..cut])?;
                    buf.drain(..cut);
                }
            }
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
    if !raw_carry.is_empty() {
        buf.push_str(&String::from_utf8_lossy(&raw_carry));
    }
    if !buf.is_empty() {
        if raw {
            if let Some(i) = buf.find(BUILD_RESULT_PREFIX) {
                write_raw_frame(&mut out, &buf.as_bytes()[..i])?;
                let rest = &buf[i + BUILD_RESULT_PREFIX.len()..];
                result = serde_json::from_str(rest.trim()).ok();
            } else {
                write_raw_frame(&mut out, buf.as_bytes())?;
            }
        } else {
            let line = buf.trim_end();
            if let Some(json) = line.strip_prefix(BUILD_RESULT_PREFIX) {
                result = serde_json::from_str(json).ok();
            } else if !line.is_empty() {
                println!("    {line}");
            }
        }
    }
    drop(_tty_reset);
    let r = result.ok_or_else(|| anyhow!("build connection closed before finishing"))?;
    if !r.ok {
        let e = r.error.unwrap_or_default();
        if e.contains("push") {
            bail!("build failed: {e}\n  The image built but could not be stored on the cluster; `latrix doctor` shows why.");
        }
        bail!("build failed: {e}");
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
    // Warnings about this app (e.g. "no machine in region ...") are shown as they happen.
    let event_key = |e: &crate::state::Event| format!("{}|{}", e.ts, e.message);
    let mut seen: std::collections::HashSet<String> = client
        .get::<Vec<crate::state::Event>>("/v1/events")
        .await
        .map(|v| v.iter().map(event_key).collect())
        .unwrap_or_default();
    let prefix = format!("{app}: ");
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut consecutive_poll_errors = 0u32;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = &mut ctrl_c => {
                println!(
                    "\nStopped watching — release v{version} is still rolling out on the cluster.\n  Check progress: latrix ps {app}\n  Undo rollout:   latrix rollback {app}"
                );
                return Err(DeployCancelled.into());
            }
        }
        let poll = async {
            if let Ok(evs) = client.get::<Vec<crate::state::Event>>("/v1/events").await {
                for e in evs {
                    if seen.insert(event_key(&e)) && e.level == "warn" && e.message.starts_with(&prefix) {
                        println!("    ! {}", &e.message[prefix.len()..]);
                    }
                }
            }
            client.get::<AppView>(&format!("/v1/apps/{app}")).await
        };
        let v = tokio::select! {
            r = poll => match r {
                Ok(v) => {
                    consecutive_poll_errors = 0;
                    v
                }
                Err(e) => {
                    consecutive_poll_errors += 1;
                    if consecutive_poll_errors >= 5 || start.elapsed() > limit {
                        return Err(e);
                    }
                    continue;
                }
            },
            _ = &mut ctrl_c => {
                println!(
                    "\nStopped watching — release v{version} is still rolling out on the cluster.\n  Check progress: latrix ps {app}\n  Undo rollout:   latrix rollback {app}"
                );
                return Err(DeployCancelled.into());
            }
        };
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
            bail!(
                "timed out waiting for {app} v{version} to become healthy (still rolling out in the background — check `latrix ps {app}`)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keep_does_not_hold_back_complete_frames() {
        assert_eq!(tail_keep_len("=> [builder 5/7] RUN cargo build\x1b[0m\r\n", BUILD_RESULT_PREFIX), 0);
        assert_eq!(tail_keep_len("\x1b[28Ahello world\x1b[K", BUILD_RESULT_PREFIX), 0);
    }

    #[test]
    fn tail_keep_holds_partial_marker_and_partial_ansi() {
        assert_eq!(tail_keep_len("done\nLATRIX_RES", BUILD_RESULT_PREFIX), "LATRIX_RES".len());
        assert_eq!(tail_keep_len("done\nL", BUILD_RESULT_PREFIX), 1);
        assert_eq!(tail_keep_len("hello\x1b[38;5;", BUILD_RESULT_PREFIX), "\x1b[38;5;".len());
        assert_eq!(tail_keep_len("hello\x1b", BUILD_RESULT_PREFIX), 1);
        assert_eq!(tail_keep_len("hello\x1b[38;5;242m", BUILD_RESULT_PREFIX), 0);
    }

    #[test]
    fn push_valid_utf8_handles_split_multibyte_chars() {
        let mut carry = Vec::new();
        let mut out = String::new();
        let bytes = "✓ ok".as_bytes();
        push_valid_utf8(&mut carry, &bytes[..2], &mut out);
        assert_eq!(out, "");
        push_valid_utf8(&mut carry, &bytes[2..], &mut out);
        assert_eq!(out, "✓ ok");
        assert!(carry.is_empty());
    }
}
