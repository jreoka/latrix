//! Moving data in and out of machines: volume snapshots and images. Used by
//! `latrix backup`, `latrix restore` and `latrix import fly`. All endpoints
//! are machine-local (`/v1/local/*`, reached through `/v1/m/{id}/*`).

use super::{cmd, Agent};
use crate::state::Volume;
use crate::util::{random_id, REGISTRY_PORT};
use axum::body::Body;
use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::StreamExt;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tracing::info;

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(crate::api_types::ApiErrorBody { error: msg.into() })).into_response()
}

fn safe_id(id: &str) -> bool {
    !id.is_empty() && !id.contains('/') && !id.contains('\\') && !id.contains("..")
}

#[derive(Deserialize)]
pub struct VolumeQuery {
    pub volume: String,
}

/// Stream a gzipped tarball of a volume (running `pre_sync` first if set).
pub async fn get_volume(State(agent): State<Arc<Agent>>, Query(q): Query<VolumeQuery>) -> Response {
    if !safe_id(&q.volume) {
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
            let _ = cmd("docker", &["exec", &ctr, "sh", "-c", &pre]).await;
        }
    }
    let child = tokio::process::Command::new("tar")
        .args(["-czf", "-", "-C", &dir.display().to_string(), "."])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let stdout = child.stdout.take().unwrap();
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    info!("streaming a snapshot of volume {}", q.volume);
    Body::from_stream(tokio_util::io::ReaderStream::new(stdout)).into_response()
}

async fn save_body(req: Request, path: &PathBuf) -> Result<u64, String> {
    let mut f = tokio::fs::File::create(path).await.map_err(|e| e.to_string())?;
    let mut n = 0u64;
    let mut body = req.into_body().into_data_stream();
    while let Some(chunk) = body.next().await {
        let c = chunk.map_err(|e| format!("upload interrupted: {e}"))?;
        n += c.len() as u64;
        f.write_all(&c).await.map_err(|e| e.to_string())?;
    }
    f.flush().await.map_err(|e| e.to_string())?;
    Ok(n)
}

/// Replace a volume's contents with an uploaded gzipped tarball. The app
/// must not be running on this machine (restore scales it to 0 first).
pub async fn put_volume(State(agent): State<Arc<Agent>>, Query(q): Query<VolumeQuery>, req: Request) -> Response {
    if !safe_id(&q.volume) {
        return err(StatusCode::BAD_REQUEST, "invalid volume id");
    }
    let s = agent.snapshot();
    let app = s
        .volumes
        .get(&q.volume)
        .map(|v| v.app.clone())
        .unwrap_or_else(|| q.volume.split("__").next().unwrap_or_default().to_string());
    if agent.rt.running_container(&app).is_some() {
        return err(StatusCode::CONFLICT, format!("{app} is running on this machine; scale it to 0 first"));
    }
    let base = agent.data.join("volumes");
    let _ = std::fs::create_dir_all(&base);
    let tmp = base.join(format!(".restore-{}.tar.gz", random_id(6)));
    let size = match save_body(req, &tmp).await {
        Ok(n) => n,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let new_dir = base.join(format!(".{}-new-{}", q.volume, random_id(4)));
    let _ = std::fs::create_dir_all(&new_dir);
    let res = cmd("tar", &["-xzf", &tmp.display().to_string(), "-C", &new_dir.display().to_string()]).await;
    let _ = std::fs::remove_file(&tmp);
    if let Err(e) = res {
        let _ = std::fs::remove_dir_all(&new_dir);
        return err(StatusCode::BAD_REQUEST, format!("could not unpack the volume data: {e}"));
    }
    let dir = base.join(&q.volume);
    let old = base.join(format!(".{}-old-{}", q.volume, random_id(4)));
    if dir.exists() {
        if let Err(e) = std::fs::rename(&dir, &old) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    }
    if let Err(e) = std::fs::rename(&new_dir, &dir) {
        let _ = std::fs::rename(&old, &dir);
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
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
    if q.image.starts_with('-') || q.image.contains(char::is_whitespace) {
        return err(StatusCode::BAD_REQUEST, "invalid image reference");
    }
    if cmd("docker", &["image", "inspect", "--format", "{{.Id}}", &q.image]).await.is_err() {
        return err(StatusCode::NOT_FOUND, format!("image {} is not on this machine", q.image));
    }
    let child = tokio::process::Command::new("docker")
        .args(["save", &q.image])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let stdout = child.stdout.take().unwrap();
    // Compress on the fly in a blocking thread.
    let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<bytes::Bytes>>(16);
    tokio::spawn(async move {
        let mut reader = tokio_util::io::ReaderStream::new(stdout);
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        use std::io::Write;
        while let Some(chunk) = reader.next().await {
            let Ok(c) = chunk else { break };
            if enc.write_all(&c).is_err() {
                break;
            }
            let out = std::mem::take(enc.get_mut());
            if !out.is_empty() && tx.send(Ok(out.into())).await.is_err() {
                return;
            }
        }
        if let Ok(rest) = enc.finish() {
            let _ = tx.send(Ok(rest.into())).await;
        }
        let _ = child.wait().await;
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
    if crate::util::validate_name("app", &q.app).is_err()
        || !q.tag.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        return err(StatusCode::BAD_REQUEST, "invalid app or tag");
    }
    let tmp = agent.data.join(format!("image-upload-{}.tar.gz", random_id(6)));
    if let Err(e) = save_body(req, &tmp).await {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let script = format!("gunzip -c '{}' | docker load", tmp.display());
    let out = super::sh(&script).await;
    let _ = std::fs::remove_file(&tmp);
    let out = match out {
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
    let target = format!("{}/{}:{}", agent.registry(), q.app, q.tag);
    if let Err(e) = cmd("docker", &["tag", &loaded, &target]).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }
    if let Err(e) = cmd("docker", &["push", "-q", &target]).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("push to the cluster registry failed: {e}"));
    }
    info!("loaded uploaded image as {target}");
    let _ = REGISTRY_PORT;
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
    if crate::util::validate_name("app", &q.app).is_err() {
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

    // Spool request body (e.g. a postgres dump) to a temp file so we never deadlock
    // on simultaneous stdin/stdout streaming and can report clean exit errors.
    let tmp_in = agent.data.join(format!(".exec-in-{}", random_id(6)));
    let in_size = match save_body(req, &tmp_in).await {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_in);
            return err(StatusCode::BAD_REQUEST, e);
        }
    };

    let tmp_out = agent.data.join(format!(".exec-out-{}", random_id(6)));
    let stdin_stdio = if in_size > 0 {
        match std::fs::File::open(&tmp_in) {
            Ok(f) => std::process::Stdio::from(f),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_in);
                return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
            }
        }
    } else {
        std::process::Stdio::null()
    };
    let stdout_file = match std::fs::File::create(&tmp_out) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_in);
            return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
    };

    struct RemoveOnDrop(PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    let mut docker_args = vec!["exec"];
    if in_size > 0 {
        docker_args.push("-i");
    }
    docker_args.extend([ctr.as_str(), "sh", "-c", cmd_str.as_str()]);

    // Use `spawn()` + `wait_with_output()` rather than `Command::output()`,
    // because `Command::output()` overrides `.stdout(...)` with `Stdio::piped()`
    // and would leave `tmp_out` empty while buffering stdout in memory.
    let child = tokio::process::Command::new("docker")
        .args(&docker_args)
        .stdin(stdin_stdio)
        .stdout(std::process::Stdio::from(stdout_file))
        .stderr(std::process::Stdio::piped())
        .spawn();
    let res = match child {
        Ok(c) => c.wait_with_output().await,
        Err(e) => Err(e),
    };
    let _ = std::fs::remove_file(&tmp_in);

    match res {
        Ok(out) if out.status.success() => {
            let f = match tokio::fs::File::open(&tmp_out).await {
                Ok(f) => f,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp_out);
                    return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
                }
            };
            // Stream output file and unlink when finished or dropped early.
            let guard = RemoveOnDrop(tmp_out);
            let stream = tokio_util::io::ReaderStream::new(f);
            let stream = futures::stream::unfold((stream, guard), |(mut s, g)| async move {
                s.next().await.map(|item| (item, (s, g)))
            });
            Body::from_stream(stream).into_response()
        }
        Ok(out) => {
            let _ = std::fs::remove_file(&tmp_out);
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "exec exited with {}: {}",
                    out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
                    if stderr.is_empty() { "(no stderr)".into() } else { stderr }
                ),
            )
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_out);
            err(StatusCode::INTERNAL_SERVER_ERROR, format!("docker exec failed: {e}"))
        }
    }
}
