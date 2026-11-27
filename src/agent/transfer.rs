//! Moving data in and out of machines: volume snapshots and images. Used by
//! `latrix backup`, `latrix restore` and `latrix import fly`. All endpoints
//! are machine-local (`/v1/local/*`, reached through `/v1/m/{id}/*`).

use super::{cmd_timeout, Agent};
use crate::state::Volume;
use crate::util::{self, random_id, REGISTRY_PORT};
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

const MAX_UPLOAD_BYTES: u64 = 20 * 1024 * 1024 * 1024; // 20 GiB
const MAX_VOLUME_EXTRACT_BYTES: u64 = 100 * 1024 * 1024 * 1024; // 100 GiB
const MAX_EXEC_STDERR_BYTES: usize = 256 * 1024;

struct RemoveFileOnDrop(PathBuf);
impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct RemoveDirOnDrop(PathBuf);
impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        if self.0.exists() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(crate::api_types::ApiErrorBody { error: msg.into() })).into_response()
}

/// Inspect a gzipped volume tarball before invoking `tar` as root, rejecting
/// path traversal, absolute paths, device/FIFO nodes, setuid/setgid bits,
/// escaping symlinks/hardlinks, and excessive decompressed size.
fn validate_volume_tarball(path: &Path) -> Result<(), String> {
    let f = std::fs::File::open(path).map_err(|e| format!("open archive: {e}"))?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    let mut total_size = 0u64;
    for entry in ar.entries().map_err(|e| format!("invalid tar archive: {e}"))? {
        let entry = entry.map_err(|e| format!("corrupt tar entry: {e}"))?;
        let p = entry.path().map_err(|e| format!("invalid entry path: {e}"))?;
        let mut depth = 0usize;
        for c in p.components() {
            match c {
                Component::CurDir => {}
                Component::Normal(_) => depth += 1,
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(format!("unsafe path in volume archive: {}", p.display()));
                }
            }
        }
        let hdr = entry.header();
        let kind = hdr.entry_type();
        if kind.is_character_special() || kind.is_block_special() || kind.is_fifo() {
            return Err(format!("special device/FIFO entry not allowed in volume archive: {}", p.display()));
        }
        if let Ok(mode) = hdr.mode() {
            if mode & 0o6000 != 0 {
                return Err(format!("setuid/setgid bit not allowed in volume archive: {}", p.display()));
            }
        }
        if kind.is_symlink() || kind.is_hard_link() {
            if let Ok(Some(link)) = entry.link_name() {
                if link.is_absolute() {
                    return Err(format!("absolute link target not allowed in volume archive: {}", p.display()));
                }
                let mut cur = depth.saturating_sub(1) as isize;
                for c in link.components() {
                    match c {
                        Component::CurDir => {}
                        Component::Normal(_) => cur += 1,
                        Component::ParentDir => {
                            cur -= 1;
                            if cur < 0 {
                                return Err(format!("escaping link target in volume archive: {}", p.display()));
                            }
                        }
                        Component::RootDir | Component::Prefix(_) => {
                            return Err(format!("unsafe link target in volume archive: {}", p.display()));
                        }
                    }
                }
            }
        }
        total_size = total_size.saturating_add(hdr.size().unwrap_or(0));
        if total_size > MAX_VOLUME_EXTRACT_BYTES {
            return Err("volume archive exceeds maximum allowed size".into());
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct VolumeQuery {
    pub volume: String,
}

/// Stream a gzipped tarball of a volume (running `pre_sync` first if set).
pub async fn get_volume(State(agent): State<Arc<Agent>>, Query(q): Query<VolumeQuery>) -> Response {
    if !util::safe_id(&q.volume) {
        return err(StatusCode::BAD_REQUEST, "invalid volume id");
    }
    let dir = agent.data.join("volumes").join(&q.volume);
    if !dir.is_dir() {
        return err(StatusCode::NOT_FOUND, format!("volume {} is not on this machine", q.volume));
    }
    let s = agent.snapshot();
    if let Some(v) = s.volumes.get(&q.volume) {
        let pre = s
            .apps
            .get(&v.app)
            .and_then(|a| a.config())
            .and_then(|c| c.volumes.iter().find(|x| x.name == v.name))
            .and_then(|x| x.pre_sync.clone());
        if let (Some(pre), Some(ctr)) = (pre, agent.rt.running_container(&v.app)) {
            let _ = cmd_timeout("docker", &["exec", &ctr, "sh", "-c", &pre], Duration::from_secs(120)).await;
        }
    }
    let child = tokio::process::Command::new("tar")
        .args(["--numeric-owner", "-czf", "-", "-C", &dir.display().to_string(), "."])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let stdout = child.stdout.take().unwrap();
    let reader = tokio_util::io::ReaderStream::new(stdout);
    // Keep `child` attached to the response stream so client disconnects terminate `tar`.
    let stream = futures::stream::unfold((reader, Some(child)), |(mut r, mut c)| async move {
        match r.next().await {
            Some(item) => Some((item, (r, c))),
            None => {
                if let Some(mut ch) = c.take() {
                    if let Ok(st) = ch.wait().await {
                        if !st.success() {
                            return Some((
                                Err(std::io::Error::other(format!("tar exited with {st}"))),
                                (r, None),
                            ));
                        }
                    }
                }
                None
            }
        }
    });
    info!("streaming a snapshot of volume {}", q.volume);
    Body::from_stream(stream).into_response()
}

async fn save_body(req: Request, path: &PathBuf) -> Result<u64, String> {
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path).await.map_err(|e| e.to_string())?;
    let mut n = 0u64;
    let mut body = req.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let c = chunk.map_err(|e| format!("upload interrupted: {e}"))?;
        n = n.saturating_add(c.len() as u64);
        if n > MAX_UPLOAD_BYTES {
            return Err("upload exceeds maximum allowed size".into());
        }
        f.write_all(&c).await.map_err(|e| e.to_string())?;
    }
    f.flush().await.map_err(|e| e.to_string())?;
    Ok(n)
}

/// Replace a volume's contents with an uploaded gzipped tarball. The app
/// must not be running on this machine (restore scales it to 0 first).
pub async fn put_volume(State(agent): State<Arc<Agent>>, Query(q): Query<VolumeQuery>, req: Request) -> Response {
    if !util::safe_id(&q.volume) {
        return err(StatusCode::BAD_REQUEST, "invalid volume id");
    }
    let s = agent.snapshot();
    let app = s
        .volumes
        .get(&q.volume)
        .map(|v| v.app.clone())
        .unwrap_or_else(|| q.volume.split("__").next().unwrap_or_default().to_string());
    if agent.rt.app_has_active_work(&app, &s, agent.me.machine_id) {
        return err(StatusCode::CONFLICT, format!("{app} is running on this machine; scale it to 0 first"));
    }
    let base = agent.data.join("volumes");
    let _ = std::fs::create_dir_all(&base);
    let tmp = base.join(format!(".restore-{}.tar.gz", random_id(8)));
    let _tmp_guard = RemoveFileOnDrop(tmp.clone());
    let size = match save_body(req, &tmp).await {
        Ok(n) => n,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let tmp_check = tmp.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || validate_volume_tarball(&tmp_check))
        .await
        .unwrap_or_else(|e| Err(e.to_string()))
    {
        return err(StatusCode::BAD_REQUEST, e);
    }

    let vlock = agent.vols.volume_lock(&q.volume);
    let _vol_guard = vlock.lock_owned().await;
    if agent.rt.app_has_active_work(&app, &agent.snapshot(), agent.me.machine_id) {
        return err(StatusCode::CONFLICT, format!("{app} started running during upload; scale it to 0 first"));
    }

    let new_dir = base.join(format!(".{}-new-{}", q.volume, random_id(6)));
    let new_guard = RemoveDirOnDrop(new_dir.clone());
    if let Err(e) = std::fs::create_dir_all(&new_dir) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    let res = cmd_timeout(
        "tar",
        &[
            "--numeric-owner",
            "-xzf",
            &tmp.display().to_string(),
            "-C",
            &new_dir.display().to_string(),
        ],
        Duration::from_secs(600),
    )
    .await;
    if let Err(e) = res {
        return err(StatusCode::BAD_REQUEST, format!("could not unpack the volume data: {e}"));
    }
    let dir = base.join(&q.volume);
    let old = base.join(format!(".{}-old-{}", q.volume, random_id(6)));
    if dir.exists() {
        if let Err(e) = std::fs::rename(&dir, &old) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    }
    if let Err(e) = std::fs::rename(&new_dir, &dir) {
        let _ = std::fs::rename(&old, &dir);
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    std::mem::forget(new_guard);
    let _ = std::fs::remove_dir_all(&old);
    agent.vols.kick();
    info!("restored volume {} ({} bytes compressed)", q.volume, size);
    Json(serde_json::json!({"ok": true, "bytes": size})).into_response()
}

#[derive(Deserialize)]
pub struct ImageQuery {
    #[serde(rename = "ref")]
    pub image: String,
}

/// Stream `docker save <image>` (gzipped).
pub async fn get_image(Query(q): Query<ImageQuery>) -> Response {
    if util::validate_image_ref(&q.image).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid image reference");
    }
    if cmd_timeout("docker", &["image", "inspect", "--format", "{{.Id}}", "--", &q.image], Duration::from_secs(15))
        .await
        .is_err()
    {
        return err(StatusCode::NOT_FOUND, format!("image {} is not on this machine", q.image));
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(16);
    let image = q.image.clone();
    // Run `docker save` + synchronous gzip compression in a dedicated blocking thread
    // so multi-GB image exports never starve Tokio async heartbeat workers.
    tokio::task::spawn_blocking(move || {
        use std::io::{Read, Write};
        let mut child = match std::process::Command::new("docker")
            .args(["save", &image])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.blocking_send(Err(e));
                return;
            }
        };
        let mut stdout = child.stdout.take().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = enc.write_all(&buf[..n]) {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = tx.blocking_send(Err(e));
                        return;
                    }
                    let out = std::mem::take(enc.get_mut());
                    if !out.is_empty() && tx.blocking_send(Ok(out.into())).is_err() {
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = tx.blocking_send(Err(e));
                    return;
                }
            }
        }
        let status = child.wait();
        match status {
            Ok(st) if st.success() => {
                if let Ok(rest) = enc.finish() {
                    if !rest.is_empty() {
                        let _ = tx.blocking_send(Ok(rest.into()));
                    }
                }
            }
            Ok(st) => {
                let _ = tx.blocking_send(Err(std::io::Error::other(format!("docker save exited with {st}"))));
            }
            Err(e) => {
                let _ = tx.blocking_send(Err(e));
            }
        }
    });
    let stream = futures::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|x| (x, rx)) });
    Body::from_stream(stream).into_response()
}

#[derive(Deserialize)]
pub struct LoadQuery {
    pub app: String,
    pub tag: String,
}

/// Load an uploaded (gzipped) `docker save` archive and push it into this
/// machine's registry as <registry>/<app>:<tag>. Returns the new reference.
pub async fn put_image(State(agent): State<Arc<Agent>>, Query(q): Query<LoadQuery>, req: Request) -> Response {
    if util::validate_name("app", &q.app).is_err() || !util::safe_id(&q.tag) {
        return err(StatusCode::BAD_REQUEST, "invalid app or tag");
    }
    let tmp = agent.data.join(format!(".image-upload-{}.tar.gz", random_id(8)));
    let _tmp_guard = RemoveFileOnDrop(tmp.clone());
    if let Err(e) = save_body(req, &tmp).await {
        return err(StatusCode::BAD_REQUEST, e);
    }
    // `docker load -i` handles gzipped tarballs natively without spawning `sh`/`gunzip`.
    let out = match cmd_timeout("docker", &["load", "-i", &tmp.display().to_string()], Duration::from_secs(600)).await {
        Ok(o) => o,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("docker load failed: {e}")),
    };
    // "Loaded image: name:tag" or "Loaded image ID: sha256:..."
    let Some(loaded) = out
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("Loaded image: ").or_else(|| l.strip_prefix("Loaded image ID: ")))
        .map(|s| s.trim().to_string())
    else {
        return err(StatusCode::BAD_REQUEST, format!("could not tell which image was loaded: {out}"));
    };
    let _gc_read = agent.rt.registry_gc_lock.read().await;
    let target = format!("{}/{}:{}", agent.registry(), q.app, q.tag);
    let local = format!("127.0.0.1:{REGISTRY_PORT}/{}:{}", q.app, q.tag);
    if let Err(e) = cmd_timeout("docker", &["tag", &loaded, &target], Duration::from_secs(30)).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    if local != target {
        let _ = cmd_timeout("docker", &["tag", &loaded, &local], Duration::from_secs(30)).await;
    }
    if let Err(e) = cmd_timeout("docker", &["push", "-q", &local], Duration::from_secs(600)).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("push to the cluster registry failed: {e}"));
    }
    info!("loaded uploaded image as {target}");
    Json(serde_json::json!({ "image": target })).into_response()
}

/// Volume id used on disk for an app's volume.
#[allow(dead_code)]
pub fn volume_id(app: &str, name: &str) -> String {
    Volume::dir_name(app, name)
}

#[derive(Deserialize)]
pub struct ExecQuery {
    pub app: String,
    /// Shell command (`sh -c`), base64-encoded (standard or URL-safe) or passed via X-Latrix-Exec header.
    #[serde(default)]
    pub cmd: Option<String>,
}

/// Run a non-interactive command inside a running app container on this
/// machine, piping the HTTP request body to stdin and streaming stdout back.
/// Used by `latrix rexctl` for `pg_restore`, `pg_dump`, and one-shot init jobs.
pub async fn exec_container(
    State(agent): State<Arc<Agent>>,
    Query(q): Query<ExecQuery>,
    req: Request,
) -> Response {
    use base64::Engine;
    if util::validate_name("app", &q.app).is_err() {
        return err(StatusCode::BAD_REQUEST, "invalid app name");
    }
    let Some(ctr) = agent.rt.running_container(&q.app) else {
        return err(StatusCode::NOT_FOUND, format!("{} is not running on this machine", q.app));
    };
    let encoded = req
        .headers()
        .get("x-latrix-exec")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .or(q.cmd);
    let Some(encoded) = encoded else {
        return err(StatusCode::BAD_REQUEST, "missing command (cmd query or x-latrix-exec header)");
    };
    let cmd_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.trim()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded.trim()));
    let cmd_str = match cmd_bytes.ok().and_then(|b| String::from_utf8(b).ok()) {
        Some(s) if !s.trim().is_empty() => s,
        _ => return err(StatusCode::BAD_REQUEST, "invalid base64 command"),
    };

    // Spool request body (e.g. a postgres dump) to a private 0600 temp file with
    // RAII cleanup attached BEFORE creating it so disconnects never leak files.
    let tmp_in = agent.data.join(format!(".exec-in-{}", random_id(8)));
    let _in_guard = RemoveFileOnDrop(tmp_in.clone());
    let in_size = match save_body(req, &tmp_in).await {
        Ok(n) => n,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };

    let tmp_out = agent.data.join(format!(".exec-out-{}", random_id(8)));
    let out_guard = RemoveFileOnDrop(tmp_out.clone());
    let stdin_stdio = if in_size > 0 {
        match std::fs::File::open(&tmp_in) {
            Ok(f) => std::process::Stdio::from(f),
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    } else {
        std::process::Stdio::null()
    };
    let stdout_file = {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&tmp_out) {
            Ok(f) => f,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    };

    let mut docker_args = vec!["exec"];
    if in_size > 0 {
        docker_args.push("-i");
    }
    docker_args.extend([ctr.as_str(), "sh", "-c", cmd_str.as_str()]);

    let mut child = match tokio::process::Command::new("docker")
        .args(&docker_args)
        .stdin(stdin_stdio)
        .stdout(std::process::Stdio::from(stdout_file))
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("docker exec failed: {e}")),
    };
    let mut stderr_pipe = child.stderr.take().unwrap();
    let stderr_task = tokio::spawn(async move {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stderr_pipe.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() < MAX_EXEC_STDERR_BYTES {
                        let take = n.min(MAX_EXEC_STDERR_BYTES - buf.len());
                        buf.extend_from_slice(&chunk[..take]);
                    }
                }
            }
        }
        buf
    });
    let status = match tokio::time::timeout(Duration::from_secs(1800), child.wait()).await {
        Ok(Ok(st)) => st,
        Ok(Err(e)) => {
            stderr_task.abort();
            return err(StatusCode::INTERNAL_SERVER_ERROR, format!("docker exec failed: {e}"));
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            stderr_task.abort();
            return err(StatusCode::GATEWAY_TIMEOUT, "docker exec timed out after 30 minutes");
        }
    };
    let stderr_bytes = stderr_task.await.unwrap_or_default();

    if status.success() {
        let f = match tokio::fs::File::open(&tmp_out).await {
            Ok(f) => f,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        let stream = tokio_util::io::ReaderStream::new(f);
        let stream = futures::stream::unfold((stream, out_guard), |(mut s, g)| async move {
            s.next().await.map(|item| (item, (s, g)))
        });
        Body::from_stream(stream).into_response()
    } else {
        let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_string();
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "exec exited with {}: {}",
                status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
                if stderr.is_empty() { "(no stderr)".into() } else { stderr }
            ),
        )
    }
}
