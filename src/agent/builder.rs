//! Builds images on the cluster.
//!
//! The CLI uploads a gzipped tarball of the build context (or asks for a git
//! checkout). The leader picks the builder with cache affinity (the machine
//! that built the app last time keeps warm BuildKit layers). When the build
//! moves to a different machine it still reuses layers from the previous
//! release's image through BuildKit inline cache (`--cache-from`), pulled
//! from whichever registry in the mesh has it.

use super::{cmd, cmd_timeout, Agent};
use crate::api_types::{BuildRequest, BuildResult, BUILD_RESULT_PREFIX};
use crate::util;
use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures::StreamExt;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::info;

pub const BUILD_HEADER: &str = "x-latrix-build";

fn git_lock(app: &str) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    let map = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    map.lock()
        .unwrap()
        .entry(app.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Resolve a relative subpath inside `base`, ensuring no `..`, absolute prefix,
/// or symlink escapes `base`.
fn resolve_confined_path(base: &Path, sub: &str, must_exist: bool) -> Result<PathBuf> {
    let sub_clean = sub.replace('\\', "/");
    let rel = Path::new(&sub_clean);
    let mut normalized = PathBuf::new();
    for comp in rel.components() {
        match comp {
            Component::CurDir => {}
            Component::Normal(p) => normalized.push(p),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("path '{sub}' must be relative and stay inside the build directory");
            }
        }
    }
    let joined = if normalized.as_os_str().is_empty() {
        base.to_path_buf()
    } else {
        base.join(&normalized)
    };
    let canon_base = std::fs::canonicalize(base).context("canonicalizing build root")?;
    if must_exist || joined.exists() {
        let canon = std::fs::canonicalize(&joined)
            .with_context(|| format!("resolving '{sub}' inside build context"))?;
        if !canon.starts_with(&canon_base) {
            bail!("path '{sub}' escapes the build context");
        }
        Ok(canon)
    } else {
        Ok(joined)
    }
}

/// Safely extract a gzipped build context tarball into `dest` without allowing
/// path traversal, absolute paths, device/FIFO entries, setuid bits, or
/// symlinks/hardlinks escaping `dest`.
fn unpack_context_safely(archive: &Path, dest: &Path, cancelled: &AtomicBool) -> Result<()> {
    const MAX_FILES: usize = 100_000;
    const MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB
    let f = std::fs::File::open(archive)?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    let canon_dest = std::fs::canonicalize(dest)?;
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    for entry in ar.entries().context("reading build context archive")? {
        if cancelled.load(Ordering::Relaxed) {
            bail!("build cancelled during extraction");
        }
        let mut entry = entry?;
        file_count += 1;
        if file_count > MAX_FILES {
            bail!("build context exceeds maximum file limit ({MAX_FILES})");
        }
        let raw_path = entry.path()?.into_owned();
        let mut rel = PathBuf::new();
        for comp in raw_path.components() {
            match comp {
                Component::CurDir => {}
                Component::Normal(p) => rel.push(p),
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    bail!("build context contains unsafe path '{}'", raw_path.display());
                }
            }
        }
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = canon_dest.join(&rel);
        // Ensure no existing ancestor under canon_dest is a symlink.
        let mut check = canon_dest.clone();
        if let Some(parent) = rel.parent() {
            for comp in parent.components() {
                if let Component::Normal(p) = comp {
                    check.push(p);
                    if let Ok(meta) = std::fs::symlink_metadata(&check) {
                        if meta.file_type().is_symlink() {
                            bail!("build context path '{}' traverses through a symlink", rel.display());
                        }
                    }
                }
            }
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if kind.is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let sz = entry.header().size().unwrap_or(0);
            total_bytes = total_bytes.saturating_add(sz);
            if total_bytes > MAX_BYTES {
                bail!("build context exceeds maximum extracted size (4 GiB)");
            }
            if std::fs::symlink_metadata(&target).is_ok() {
                let _ = std::fs::remove_file(&target);
            }
            let mut out = std::fs::File::create(&target)?;
            std::io::copy(&mut entry, &mut out)?;
            #[cfg(unix)]
            if let Ok(mode) = entry.header().mode() {
                use std::os::unix::fs::PermissionsExt;
                // Preserve normal rwx bits while stripping setuid/setgid/sticky and ensuring owner rw.
                let safe_mode = (mode & 0o777) | 0o600;
                let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(safe_mode));
            }
        } else if kind.is_symlink() {
            if let Some(link) = entry.link_name()? {
                // Only allow relative symlinks that resolve within canon_dest.
                if link.is_absolute() {
                    bail!("build context contains absolute symlink '{}'", rel.display());
                }
                let mut resolved = target.parent().unwrap_or(&canon_dest).to_path_buf();
                for comp in link.components() {
                    match comp {
                        Component::CurDir => {}
                        Component::Normal(p) => resolved.push(p),
                        Component::ParentDir => {
                            if !resolved.pop() || !resolved.starts_with(&canon_dest) {
                                bail!("build context symlink '{}' escapes build root", rel.display());
                            }
                        }
                        Component::RootDir | Component::Prefix(_) => {
                            bail!("build context contains unsafe symlink '{}'", rel.display());
                        }
                    }
                }
                if !resolved.starts_with(&canon_dest) {
                    bail!("build context symlink '{}' escapes build root", rel.display());
                }
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                #[cfg(unix)]
                {
                    let _ = std::fs::remove_file(&target);
                    std::os::unix::fs::symlink(&link, &target)?;
                }
            }
        } else {
            // Skip special device/FIFO/hardlink entries safely.
            continue;
        }
    }
    Ok(())
}

pub async fn handle_build(State(agent): State<Arc<Agent>>, req: Request) -> Response {
    let spec = match req
        .headers()
        .get(BUILD_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
        .and_then(|b| serde_json::from_slice::<BuildRequest>(&b).ok())
    {
        Some(s) => s,
        None => return (StatusCode::BAD_REQUEST, "missing or invalid build header").into_response(),
    };
    if let Err(e) = util::validate_name("app", &spec.app) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if !util::safe_id(&spec.tag) {
        return (StatusCode::BAD_REQUEST, "invalid tag").into_response();
    }
    if let Some(git) = &spec.git {
        if let Err(e) = util::validate_git_url(git) {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    }
    if let Some(branch) = &spec.branch {
        if let Err(e) = util::validate_git_branch(branch) {
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    }
    if let Some(target) = &spec.target {
        if target.starts_with('-') || target.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return (StatusCode::BAD_REQUEST, "invalid build target").into_response();
        }
    }
    for c in &spec.cache_from {
        if util::validate_image_ref(c).is_err() || c.contains(',') || c.contains("type=") {
            return (StatusCode::BAD_REQUEST, format!("invalid cache_from '{c}'")).into_response();
        }
    }

    // Receive the context before starting (unique per-build nonce prevents concurrent collisions).
    let nonce = util::random_id(8);
    let work = agent
        .data
        .join("builds")
        .join(format!("{}-{}-{nonce}", spec.app, spec.tag));
    if let Err(e) = util::create_private_dir_all(&work) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    let archive = work.with_extension("tar.gz");
    let cleanup = BuildCleanup {
        work: work.clone(),
        archive: archive.clone(),
    };
    let mut received = 0u64;
    if spec.git.is_none() {
        let mut opts = tokio::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut file = match opts.open(&archive).await {
            Ok(f) => f,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let mut body = req.into_body().into_data_stream();
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(c) => {
                    received += c.len() as u64;
                    if received > 4 * 1024 * 1024 * 1024 {
                        return (StatusCode::PAYLOAD_TOO_LARGE, "build context exceeds 4 GiB limit").into_response();
                    }
                    if let Err(e) = file.write_all(&c).await {
                        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                    }
                }
                Err(e) => return (StatusCode::BAD_REQUEST, format!("upload interrupted: {e}")).into_response(),
            }
        }
        let _ = file.flush().await;
    }

    let (tx, rx) = mpsc::channel::<String>(512);
    tokio::spawn(async move {
        let _cleanup = cleanup;
        let _guard = BuildGuard::new(agent.clone());
        let _gc_read = agent.rt.registry_gc_lock.read().await;
        let cancelled = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let image = format!("{}/{}:{}", agent.registry(), spec.app, spec.tag);
        let arrow = if spec.tty_cols.is_some() { "\x1b[1;34m==>\x1b[0m" } else { "==>" };
        if tx
            .send(format!(
                "{arrow} building {} on machine #{} ({:.1} MB context)\n",
                spec.app,
                agent.me.machine_id,
                received as f64 / 1048576.0
            ))
            .await
            .is_err()
        {
            info!("build of {} cancelled before start (client disconnected)", spec.app);
            return;
        }
        let res = tokio::select! {
            r = tokio::time::timeout(
                Duration::from_secs(3600),
                build(&agent, &spec, &work, &archive, &image, &tx, &cancelled),
            ) => Some(r.unwrap_or_else(|_| Err(anyhow::anyhow!("build timed out after 60 minutes")))),
            _ = tx.closed() => {
                cancelled.store(true, Ordering::SeqCst);
                info!("build of {} cancelled after {}s (client disconnected)", spec.app, started.elapsed().as_secs());
                None
            }
        };
        drop(_gc_read);
        drop(_guard);
        drop(_cleanup);
        // Keep the build cache within budget after every build.
        super::runtime::prune_build_cache(&agent).await;
        let Some(res) = res else { return };
        let result = BuildResult {
            ok: res.is_ok(),
            image: image.clone(),
            error: res.err().map(|e| format!("{e:#}")),
            seconds: started.elapsed().as_secs(),
        };
        info!("build of {} finished: ok={} in {}s", spec.app, result.ok, result.seconds);
        let _ = tx
            .send(format!("\n{BUILD_RESULT_PREFIX}{}\n", serde_json::to_string(&result).unwrap()))
            .await;
    });
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|l| (Ok::<_, std::io::Error>(bytes::Bytes::from(l)), rx))
    });
    Body::from_stream(stream).into_response()
}

struct BuildCleanup {
    work: PathBuf,
    archive: PathBuf,
}

impl Drop for BuildCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.work);
        let _ = std::fs::remove_file(&self.archive);
    }
}

struct BuildGuard {
    agent: Arc<Agent>,
}

impl BuildGuard {
    fn new(agent: Arc<Agent>) -> Self {
        agent.rt.builds_running.fetch_add(1, Ordering::SeqCst);
        Self { agent }
    }
}

impl Drop for BuildGuard {
    fn drop(&mut self) {
        self.agent.rt.builds_running.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn build(
    agent: &Arc<Agent>,
    spec: &BuildRequest,
    work: &Path,
    archive: &Path,
    image: &str,
    tx: &mpsc::Sender<String>,
    cancelled: &Arc<AtomicBool>,
) -> Result<()> {
    let _git_guard = if spec.git.is_some() {
        Some(git_lock(&spec.app).lock_owned().await)
    } else {
        None
    };
    let ctx: PathBuf = if let Some(url) = &spec.git {
        let repo = agent.data.join("git").join(&spec.app);
        checkout(url, spec.branch.as_deref(), &repo, tx).await?;
        match &spec.context {
            Some(sub) if !sub.is_empty() && sub != "." => {
                resolve_confined_path(&repo, sub, true)?
            }
            _ => std::fs::canonicalize(&repo).unwrap_or(repo),
        }
    } else {
        let a = archive.to_path_buf();
        let w = work.to_path_buf();
        let cancel_flag = cancelled.clone();
        tokio::task::spawn_blocking(move || unpack_context_safely(&a, &w, &cancel_flag))
            .await??;
        std::fs::canonicalize(work).unwrap_or_else(|_| work.to_path_buf())
    };
    let df_rel = spec.dockerfile.as_deref().unwrap_or("Dockerfile");
    let dockerfile = resolve_confined_path(&ctx, df_rel, false)?;
    if !dockerfile.exists() {
        bail!(
            "no {df_rel} found in the build context (set [build] dockerfile, or image = \"...\" to deploy a prebuilt image)"
        );
    }
    let dockerfile = resolve_confined_path(&ctx, df_rel, true)?;

    // Warm the cache from the previous release if it isn't local yet.
    for c in &spec.cache_from {
        let arrow = if spec.tty_cols.is_some() { "\x1b[1;34m==>\x1b[0m" } else { "==>" };
        let _ = tx.send(format!("{arrow} using cache from {c}\n")).await;
    }
    // BuildKit needs the buildx plugin; without it fall back to the classic builder.
    let buildkit = cmd_timeout("docker", &["buildx", "version"], Duration::from_secs(10))
        .await
        .is_ok();
    if !buildkit {
        let _ = tx.send("==> docker buildx not found, using the classic builder (slower, no cache sharing)\n".into()).await;
    }
    let mut args: Vec<String> = vec!["build".into()];
    if buildkit {
        args.push("--progress=plain".into());
        // Plain image manifests (no provenance attestation index), so the
        // inline build cache can be imported by the next build on any machine.
        args.push("--provenance=false".into());
        args.push("--sbom=false".into());
    }
    args.extend([
        "-t".into(),
        image.into(),
        "-f".into(),
        dockerfile.display().to_string(),
        "--build-arg".into(),
        "BUILDKIT_INLINE_CACHE=1".into(),
    ]);
    for c in &spec.cache_from {
        args.push("--cache-from".into());
        args.push(c.clone());
    }
    if let Some(t) = &spec.target {
        args.push("--target".into());
        args.push(t.clone());
    }
    for (k, v) in &spec.args {
        args.push("--build-arg".into());
        args.push(format!("{k}={v}"));
    }
    args.push(ctx.display().to_string());
    let bk = if buildkit { "1" } else { "0" };
    // Probe util-linux `script -qfec` directly (macOS/BusyBox `script` does not support -e/-c).
    let tty = match spec.tty_cols {
        Some(cols)
            if buildkit
                && cmd_timeout("script", &["-qfec", "true", "/dev/null"], Duration::from_secs(5))
                    .await
                    .is_ok() =>
        {
            // Leave 2 rows of headroom so BuildKit's cursor-up redraws never
            // hit the top of the viewport and scroll/duplicate lines.
            let rows = spec.tty_rows.unwrap_or(24).saturating_sub(2).clamp(10, 200);
            Some((cols.clamp(40, 400), rows))
        }
        _ => None,
    };
    if let Some((cols, rows)) = tty {
        // Docker's own live, colored progress view (it needs a terminal).
        let mut a = args.clone();
        a.insert(1, "--progress=tty".into());
        a.retain(|x| x != "--progress=plain");
        run_in_pty(&format!("docker {}", shell_join(&a)), &[("DOCKER_BUILDKIT", "1")], cols, rows, tx).await?;
        let _ = tx.send(format!("\n\x1b[1;34m==>\x1b[0m pushing {image} to the cluster registry\n")).await;
        let local = local_alias(agent, image).await?;
        run_in_pty(&format!("docker push {}", crate::util::shell_quote(&local)), &[], cols, rows, tx).await?;
        return Ok(());
    }
    run_streaming("docker", &args, &[("DOCKER_BUILDKIT", bk)], tx).await?;
    let _ = tx.send(format!("==> pushing {image} to the cluster registry\n")).await;
    let local = local_alias(agent, image).await?;
    run_streaming("docker", &["push".to_string(), local], &[], tx).await?;
    Ok(())
}

async fn checkout(url: &str, branch: Option<&str>, repo: &Path, tx: &mpsc::Sender<String>) -> Result<()> {
    util::validate_git_url(url)?;
    if let Some(b) = branch {
        util::validate_git_branch(b)?;
    }
    let display_url = util::redact_url_creds(url);
    let safe_git_env: &[(&str, &str)] = &[
        ("GIT_TERMINAL_PROMPT", "0"),
        ("GIT_LFS_SKIP_SMUDGE", "1"),
    ];
    let safe_cfg = |mut args: Vec<String>| -> Vec<String> {
        let mut out = vec![
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
            "-c".into(),
            "core.fsmonitor=false".into(),
            "-c".into(),
            "protocol.ext.allow=never".into(),
            "-c".into(),
            "protocol.file.allow=never".into(),
        ];
        out.append(&mut args);
        out
    };
    let mut need_clone = !repo.join(".git").exists();
    if !need_clone {
        let _ = tx.send(format!("==> updating git checkout of {display_url}\n")).await;
        let r = repo.display().to_string();
        let b = branch.unwrap_or("HEAD").to_string();
        let update_res = async {
            run_streaming(
                "git",
                &safe_cfg(vec![
                    "-C".into(),
                    r.clone(),
                    "remote".into(),
                    "set-url".into(),
                    "origin".into(),
                    "--".into(),
                    url.into(),
                ]),
                safe_git_env,
                tx,
            )
            .await?;
            run_streaming(
                "git",
                &safe_cfg(vec![
                    "-C".into(),
                    r.clone(),
                    "fetch".into(),
                    "--depth".into(),
                    "1".into(),
                    "origin".into(),
                    "--".into(),
                    b,
                ]),
                safe_git_env,
                tx,
            )
            .await?;
            run_streaming(
                "git",
                &safe_cfg(vec![
                    "-C".into(),
                    r.clone(),
                    "reset".into(),
                    "--hard".into(),
                    "FETCH_HEAD".into(),
                ]),
                safe_git_env,
                tx,
            )
            .await?;
            run_streaming(
                "git",
                &safe_cfg(vec!["-C".into(), r, "clean".into(), "-fdx".into()]),
                safe_git_env,
                tx,
            )
            .await
        }
        .await;
        if update_res.is_err() {
            // Recover from a corrupted partial `.git` directory by wiping and re-cloning.
            let _ = std::fs::remove_dir_all(repo);
            need_clone = true;
        }
    }
    if need_clone {
        let _ = tx.send(format!("==> cloning {display_url}\n")).await;
        if let Some(p) = repo.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut args = vec!["clone".to_string(), "--depth".into(), "1".into()];
        if let Some(b) = branch {
            args.push("--branch".into());
            args.push(b.into());
        }
        args.push("--".into());
        args.push(url.into());
        args.push(repo.display().to_string());
        run_streaming("git", &safe_cfg(args), safe_git_env, tx).await?;
    }
    let sha = cmd("git", &["-C", &repo.display().to_string(), "rev-parse", "--short", "HEAD"])
        .await
        .unwrap_or_default();
    let _ = tx.send(format!("==> at commit {}\n", sha.trim())).await;
    Ok(())
}

/// The same image under 127.0.0.1:<registry port>: pushing there always
/// reaches this machine's registry (no dependence on the mesh, and Docker
/// trusts 127.0.0.0/8 registries without extra configuration).
async fn local_alias(agent: &Agent, image: &str) -> Result<String> {
    let Some((_, repo)) = image.split_once('/') else { return Ok(image.to_string()) };
    let local = format!("127.0.0.1:{}/{repo}", crate::util::REGISTRY_PORT);
    if local != image {
        cmd_timeout("docker", &["tag", image, &local], Duration::from_secs(30)).await?;
    }
    let ok = agent
        .http
        .get(format!("http://127.0.0.1:{}/v2/", crate::util::REGISTRY_PORT))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    if !ok {
        bail!("this machine's image registry isn't running yet (it starts within a minute of the agent); try again, or run `latrix doctor`");
    }
    Ok(local)
}

fn shell_join(args: &[String]) -> String {
    args.iter().map(|a| crate::util::shell_quote(a)).collect::<Vec<_>>().join(" ")
}

/// Run a shell command in a pseudo-terminal of `cols`×`rows` (via util-linux
/// `script`) and forward its raw output, escape sequences included.
async fn run_in_pty(
    command: &str,
    envs: &[(&str, &str)],
    cols: u16,
    rows: u16,
    tx: &mpsc::Sender<String>,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let inner = format!("stty cols {cols} rows {rows} 2>/dev/null; exec {command}");
    let mut child = tokio::process::Command::new("script")
        .args(["-qfec", &inner, "/dev/null"])
        .envs(envs.iter().cloned())
        .env("COLUMNS", cols.to_string())
        .env("LINES", rows.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("running script")?;
    let mut out = child.stdout.take().unwrap();
    // Drain stderr concurrently so `script` never deadlocks on a full stderr pipe.
    let err = child.stderr.take().unwrap();
    let tx_err = tx.clone();
    let err_task = tokio::spawn(async move {
        let mut l = BufReader::new(err).lines();
        while let Ok(Some(line)) = l.next_line().await {
            if tx_err.send(line + "\n").await.is_err() {
                break;
            }
        }
    });
    let mut buf = vec![0u8; 16 * 1024];
    let mut carry: Vec<u8> = vec![];
    let mut eof = false;
    while !eof {
        let n = out.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        carry.extend_from_slice(&buf[..n]);
        // Coalesce back-to-back PTY reads (Linux's PTY buffer is 4 KB, so a
        // single BuildKit redraw often arrives in 2+ immediate reads).
        while carry.len() < 64 * 1024 {
            match tokio::time::timeout(Duration::from_millis(5), out.read(&mut buf)).await {
                Ok(Ok(0)) => {
                    eof = true;
                    break;
                }
                Ok(Ok(m)) => carry.extend_from_slice(&buf[..m]),
                Ok(Err(e)) => {
                    err_task.abort();
                    return Err(e.into());
                }
                Err(_) => break,
            }
        }
        // Only forward complete UTF-8; keep a trailing incomplete character for the next read.
        let mut ready = String::new();
        while !carry.is_empty() {
            match std::str::from_utf8(&carry) {
                Ok(s) => {
                    ready.push_str(s);
                    carry.clear();
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    if valid > 0 {
                        ready.push_str(std::str::from_utf8(&carry[..valid]).unwrap_or_default());
                        carry.drain(..valid);
                    }
                    if let Some(bad_len) = e.error_len() {
                        ready.push('\u{FFFD}');
                        carry.drain(..bad_len);
                    } else {
                        break; // incomplete UTF-8 sequence at end of buffer
                    }
                }
            }
        }
        if !ready.is_empty() && tx.send(ready).await.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
            err_task.abort();
            return Ok(());
        }
    }
    if !carry.is_empty() {
        let _ = tx.send(String::from_utf8_lossy(&carry).into_owned()).await;
    }
    let status = child.wait().await?;
    let _ = err_task.await;
    if !status.success() {
        bail!("{} exited with {status}", command.split_whitespace().nth(1).unwrap_or("command"));
    }
    Ok(())
}

async fn run_streaming(
    program: &str,
    args: &[String],
    envs: &[(&str, &str)],
    tx: &mpsc::Sender<String>,
) -> Result<()> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .envs(envs.iter().cloned())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("running {program}"))?;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let (t1, t2) = (tx.clone(), tx.clone());
    let a = tokio::spawn(async move {
        let mut l = BufReader::new(out).lines();
        while let Ok(Some(line)) = l.next_line().await {
            if t1.send(line + "\n").await.is_err() {
                break;
            }
        }
    });
    let b = tokio::spawn(async move {
        let mut l = BufReader::new(err).lines();
        while let Ok(Some(line)) = l.next_line().await {
            if t2.send(line + "\n").await.is_err() {
                break;
            }
        }
    });
    let status = child.wait().await?;
    let _ = a.await;
    let _ = b.await;
    if !status.success() {
        bail!("{program} {} exited with {status}", args.first().cloned().unwrap_or_default());
    }
    Ok(())
}
