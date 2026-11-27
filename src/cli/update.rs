//! Keeping the CLI itself up to date: a once-a-day notice when a newer
//! release exists, and `latrix self-update`.

use super::client::Client;
use super::profile::CliConfig;
use crate::agent::selfupdate::{asset_url, latest_version, newer};
use crate::util::{self, now};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Default)]
struct Check {
    checked_at: u64,
    latest: String,
}

fn check_file() -> std::path::PathBuf {
    CliConfig::path().with_file_name("update-check.json")
}

/// Print a one-line notice (at most a 2s network check, once a day).
pub async fn notice() {
    let path = check_file();
    let mut c: Check = std::fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    if now().saturating_sub(c.checked_at) > 86400 {
        if let Ok(Ok(v)) = tokio::time::timeout(Duration::from_secs(2), latest_version()).await {
            c = Check { checked_at: now(), latest: v };
            let _ = util::write_atomic(&path, &serde_json::to_vec(&c).unwrap_or_default());
        }
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

pub async fn self_update(cfg: &CliConfig, cl: Option<&str>) -> Result<()> {
    let latest = latest_version().await.context("checking for a new release")?;
    if newer(&latest, util::VERSION) {
        let url = asset_url(&latest, &asset_name()?);
        println!("==> downloading latrix {latest}");
        let bytes = reqwest::Client::new()
            .get(&url)
            .timeout(Duration::from_secs(300))
            .send()
            .await?
            .error_for_status()
            .with_context(|| format!("downloading {url}"))?
            .bytes()
            .await?;
        let exe = std::env::current_exe()?;
        let new = exe.with_extension("new");
        std::fs::write(&new, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755))?;
        }
        let out = std::process::Command::new(&new).arg("--version").output().context("running the new version")?;
        if !String::from_utf8_lossy(&out.stdout).contains(&latest) {
            let _ = std::fs::remove_file(&new);
            bail!("the downloaded file doesn't look like latrix {latest}");
        }
        // A running program can't be overwritten on Windows, but it can be renamed.
        let old = exe.with_extension("old");
        let _ = std::fs::remove_file(&old);
        if cfg!(windows) {
            std::fs::rename(&exe, &old).context("moving the old version aside")?;
        }
        std::fs::rename(&new, &exe).context("installing the new version")?;
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
