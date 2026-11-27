//! Builds images on the cluster.
//!
//! The CLI uploads a gzipped tarball of the build context (or asks for a git
//! checkout). The leader picks the builder with cache affinity (the machine
//! that built the app last time keeps warm BuildKit layers). When the build
//! moves to a different machine it still reuses layers from the previous
//! release's image through BuildKit inline cache (`--cache-from`), pulled
//! from whichever registry in the mesh has it.

use super::{cmd, Agent};
use crate::api_types::{BuildRequest, BuildResult, BUILD_RESULT_PREFIX};
use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures::StreamExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tracing::info;

pub const BUILD_HEADER: &str = "x-latrix-build";

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
    if let Err(e) = crate::util::validate_name("app", &spec.app) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    if !spec.tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        return (StatusCode::BAD_REQUEST, "invalid tag").into_response();
    }

    // Receive the context before starting (the upload is part of the request).
    let work = agent.data.join("builds").join(format!("{}-{}", spec.app, spec.tag));
    let _ = std::fs::remove_dir_all(&work);
    if let Err(e) = std::fs::create_dir_all(&work) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    let archive = work.with_extension("tar.gz");
    let mut received = 0u64;
    if spec.git.is_none() {
        let mut file = match tokio::fs::File::create(&archive).await {
            Ok(f) => f,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
        let mut body = req.into_body().into_data_stream();
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(c) => {
                    received += c.len() as u64;
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
        let started = Instant::now();
        agent.rt.builds_running.fetch_add(1, Ordering::SeqCst);
        let image = format!("{}/{}:{}", agent.registry(), spec.app, spec.tag);
        let _ = tx
            .send(format!(
                "==> building {} on machine #{} ({:.1} MB context)\n",
                spec.app,
                agent.me.machine_id,
                received as f64 / 1048576.0
            ))
            .await;
        let res = build(&agent, &spec, &work, &archive, &image, &tx).await;
        agent.rt.builds_running.fetch_sub(1, Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&work);
        let _ = std::fs::remove_file(&archive);
        // Keep the build cache within budget after every build.
        super::runtime::prune_build_cache(&agent).await;
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

async fn build(
    agent: &Arc<Agent>,
    spec: &BuildRequest,
    work: &Path,
    archive: &Path,
    image: &str,
    tx: &mpsc::Sender<String>,
) -> Result<()> {
    let ctx: PathBuf = if let Some(url) = &spec.git {
        let repo = agent.data.join("git").join(&spec.app);
        checkout(url, spec.branch.as_deref(), &repo, tx).await?;
        match &spec.context {
            Some(sub) if !sub.is_empty() && sub != "." => {
                if sub.contains("..") {
                    bail!("context may not contain '..'");
                }
                repo.join(sub)
            }
            _ => repo,
        }
    } else {
        let a = archive.to_path_buf();
        let w = work.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let f = std::fs::File::open(&a)?;
            let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
            ar.set_preserve_permissions(true);
            ar.unpack(&w).context("extracting build context")?;
            Ok(())
        })
        .await??;
        work.to_path_buf()
    };
    let dockerfile = ctx.join(spec.dockerfile.as_deref().unwrap_or("Dockerfile"));
    if !dockerfile.exists() {
        bail!(
            "no {} found in the build context (set [build] dockerfile, or image = \"...\" to deploy a prebuilt image)",
            spec.dockerfile.as_deref().unwrap_or("Dockerfile")
        );
    }

    // Warm the cache from the previous release if it isn't local yet.
    for c in &spec.cache_from {
        let _ = tx.send(format!("==> using cache from {c}\n")).await;
    }
    // BuildKit needs the buildx plugin; without it fall back to the classic builder.
    let buildkit = cmd("docker", &["buildx", "version"]).await.is_ok();
    if !buildkit {
        let _ = tx.send("==> docker buildx not found, using the classic builder (slower, no cache sharing)\n".into()).await;
    }
    let mut args: Vec<String> = vec!["build".into()];
    if buildkit {
        args.push("--progress=plain".into());
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
    run_streaming("docker", &args, &[("DOCKER_BUILDKIT", bk)], tx).await?;
    let _ = tx.send(format!("==> pushing {image} to the cluster registry\n")).await;
    run_streaming("docker", &["push".to_string(), image.to_string()], &[], tx).await?;
    Ok(())
}

async fn checkout(url: &str, branch: Option<&str>, repo: &Path, tx: &mpsc::Sender<String>) -> Result<()> {
    if repo.join(".git").exists() {
        let _ = tx.send(format!("==> updating git checkout of {url}\n")).await;
        let r = repo.display().to_string();
        let b = branch.unwrap_or("HEAD").to_string();
        run_streaming(
            "git",
            &["-C".into(), r.clone(), "remote".into(), "set-url".into(), "origin".into(), url.into()],
            &[],
            tx,
        )
        .await?;
        run_streaming(
            "git",
            &["-C".into(), r.clone(), "fetch".into(), "--depth".into(), "1".into(), "origin".into(), b],
            &[],
            tx,
        )
        .await?;
        run_streaming(
            "git",
            &["-C".into(), r.clone(), "reset".into(), "--hard".into(), "FETCH_HEAD".into()],
            &[],
            tx,
        )
        .await?;
        run_streaming("git", &["-C".into(), r, "clean".into(), "-fdx".into()], &[], tx).await?;
    } else {
        let _ = tx.send(format!("==> cloning {url}\n")).await;
        if let Some(p) = repo.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut args = vec!["clone".to_string(), "--depth".into(), "1".into()];
        if let Some(b) = branch {
            args.push("--branch".into());
            args.push(b.into());
        }
        args.push(url.into());
        args.push(repo.display().to_string());
        run_streaming("git", &args, &[("GIT_TERMINAL_PROMPT", "0")], tx).await?;
    }
    let sha = cmd("git", &["-C", &repo.display().to_string(), "rev-parse", "--short", "HEAD"])
        .await
        .unwrap_or_default();
    let _ = tx.send(format!("==> at commit {}\n", sha.trim())).await;
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
            let _ = t1.send(line + "\n").await;
        }
    });
    let b = tokio::spawn(async move {
        let mut l = BufReader::new(err).lines();
        while let Ok(Some(line)) = l.next_line().await {
            let _ = t2.send(line + "\n").await;
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
