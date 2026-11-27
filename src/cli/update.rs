//! Keeping the CLI itself up to date: a once-a-day notice when a newer
//! release exists, and `latrix self-update`.

use super::client::Client;
use super::profile::CliConfig;
use crate::agent::selfupdate::{asset_url, latest_version, newer};
use crate::util::{self, now};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Serialize, Deserialize, Default)]
struct Check {
    checked_at: u64,
    latest: String,
}

struct RemoveFileGuard(PathBuf);
impl Drop for RemoveFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn check_file() -> PathBuf {
    CliConfig::path().with_file_name("update-check.json")
}

/// Print a one-line notice (at most a 2s network check, once a day).
pub async fn notice() {
    if std::env::var_os("LATRIX_NO_UPDATE_CHECK").is_some() {
        return;
    }
    let path = check_file();
    let mut c: Check = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    if now().saturating_sub(c.checked_at) > 86400 {
        match tokio::time::timeout(Duration::from_secs(2), latest_version()).await {
            Ok(Ok(v)) => {
                c = Check { checked_at: now(), latest: v };
            }
            _ => {
                // Record the attempt timestamp so offline users do not pay a 2s delay on every command.
                c.checked_at = now();
            }
        }
        let _ = util::write_atomic(&path, &serde_json::to_vec(&c).unwrap_or_default());
    }
    if newer(&c.latest, util::VERSION) {
        eprintln!("(latrix {} is available — run `latrix self-update`)", c.latest);
    }
}

fn asset_name() -> Result<String> {
    let arch = std::env::consts::ARCH;
    Ok(match std::env::consts::OS {
        "windows" => format!("latrix-{arch}-pc-windows-msvc.exe"),
        "macos" => format!("latrix-{arch}-apple-darwin"),
        "linux" => format!("latrix-{arch}-unknown-linux-musl"),
        other => bail!("no prebuilt latrix for {other}; build it with cargo"),
    })
}

fn update_http_client() -> Result<reqwest::Client> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        if attempt.url().scheme() != "https" {
            return attempt.error("refusing non-HTTPS redirect during self-update");
        }
        attempt.follow()
    });
    Ok(reqwest::Client::builder()
        .redirect(policy)
        .timeout(Duration::from_secs(300))
        .build()?)
}

pub async fn self_update(cfg: &CliConfig, cl: Option<&str>) -> Result<()> {
    let latest = latest_version().await.context("checking for a new release")?;
    if newer(&latest, util::VERSION) {
        let asset = asset_name()?;
        let url = asset_url(&latest, &asset);
        if !url.starts_with("https://") {
            bail!("refusing non-HTTPS self-update URL '{url}'");
        }
        let http = update_http_client()?;
        println!("==> downloading latrix {latest}");
        let resp = http
            .get(&url)
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("downloading {url}"))?;
        if let Some(len) = resp.content_length() {
            if len > 128 * 1024 * 1024 {
                bail!("update binary exceeds 128 MB size limit");
            }
        }
        let bytes = resp.bytes().await?;
        if bytes.len() > 128 * 1024 * 1024 {
            bail!("update binary exceeds 128 MB size limit");
        }

        // Verify SHA256SUMS if published for this release.
        let sums_url = asset_url(&latest, "SHA256SUMS");
        if let Ok(r) = http.get(&sums_url).timeout(Duration::from_secs(15)).send().await {
            if r.status().is_success() {
                if let Ok(text) = r.text().await {
                    let expected = text.lines().find_map(|line| {
                        let (hash, file) = line.trim().split_once(char::is_whitespace)?;
                        let f = file.trim().trim_start_matches('*');
                        (f == asset && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
                            .then(|| hash.to_string())
                    });
                    if let Some(exp) = expected {
                        let mut h = Sha256::new();
                        h.update(&bytes);
                        let got = format!("{:x}", h.finalize());
                        if !got.eq_ignore_ascii_case(&exp) {
                            bail!("SHA256 checksum mismatch for {asset} (expected {exp}, got {got})");
                        }
                    }
                }
            }
        }

        let exe = std::env::current_exe()?;
        let parent = exe.parent().ok_or_else(|| anyhow::anyhow!("cannot determine executable directory"))?;
        let tmp_name = if cfg!(windows) {
            format!("latrix.new-{}.exe", util::random_id(8))
        } else {
            format!("latrix.new-{}", util::random_id(8))
        };
        let new = parent.join(tmp_name);
        let guard = RemoveFileGuard(new.clone());
        std::fs::write(&new, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
        }
        let out = std::process::Command::new(&new)
            .arg("--version")
            .output()
            .context("running the new version")?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let ver_token = stdout.split_whitespace().nth(1).map(|v| v.trim_start_matches('v'));
        if !out.status.success() || ver_token != Some(latest.as_str()) {
            bail!("the downloaded file doesn't look like latrix {latest}");
        }
        // A running program can't be overwritten on Windows, but it can be renamed.
        let old = exe.with_extension(if cfg!(windows) { "old.exe" } else { "old" });
        let _ = std::fs::remove_file(&old);
        if cfg!(windows) {
            std::fs::rename(&exe, &old).context("moving the old version aside")?;
            if let Err(e) = std::fs::rename(&new, &exe) {
                let _ = std::fs::rename(&old, &exe);
                return Err(e).context("installing the new version (restored previous binary)");
            }
        } else {
            std::fs::rename(&new, &exe).context("installing the new version")?;
        }
        std::mem::forget(guard);
        let _ = util::write_atomic(&check_file(), &serde_json::to_vec(&Check { checked_at: now(), latest: latest.clone() })?);
        println!("✓ latrix is now {latest}");
    } else {
        println!("latrix {} is the latest version", util::VERSION);
    }
    // Ask the cluster to upgrade its machines now instead of within 6 hours.
    if let Ok((_, p)) = cfg.profile(cl) {
        if !p.local && p.kubernetes.is_none() {
            if let Ok(c) = Client::connect(&p).await {
                if c.post::<_, bool>("/v1/upgrade-now", &serde_json::json!({})).await.is_ok() {
                    println!("==> your machines are upgrading themselves to the latest version, one at a time (`latrix machine list` shows progress)");
                }
            }
        }
    }
    Ok(())
}
