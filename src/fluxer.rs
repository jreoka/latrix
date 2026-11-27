//! Fluxer `rexctl` backup format, release resolver, and stack planner.
//!
//! Shared between the CLI (`latrix rexctl`) and the cluster agent's automatic
//! Fluxer upgrade loop so initial deploys/restores and cluster-side upgrades
//! generate identical `latrix` app configurations.

use crate::config::*;
use crate::state::FluxerStack;
use crate::util;
use anyhow::{bail, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const MAX_BACKUP_ENTRIES: usize = 100_000;
const MAX_BACKUP_BYTES: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB
const MAX_COMPOSE_BUNDLE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
const MAX_COMPOSE_TEXT_BYTES: u64 = 2 * 1024 * 1024; // 2 MiB

pub const DEFAULT_RELEASE_URL: &str = "https://fluxer.dev/rexctl/release.json";
pub const BACKUP_FORMAT_VERSION: u32 = 2;
pub const DUMP_ENTRY: &str = "postgres/fluxer.dump";

/// Default Caddyfile matching Fluxer's `internal/stack/files/Caddyfile`.
pub const DEFAULT_CADDYFILE: &str = r#"{
	servers {
		trusted_proxies static {$FLUXER_EDGE_TRUSTED_PROXIES:private_ranges}
		trusted_proxies_strict
		protocols {$FLUXER_EDGE_PROTOCOLS:h1 h2}
	}
	{$FLUXER_EDGE_GLOBAL_OPTIONS}
}

(upstream) {
	reverse_proxy {args[0]} {
		header_up X-Forwarded-For {client_ip}
		header_up X-Real-IP {client_ip}
		header_up -Forwarded
	}
}

{$FLUXER_EDGE_SITE_ADDRESS} {
	{$FLUXER_EDGE_TLS_DIRECTIVE}
	import /etc/caddy/conf.d/*.caddy
	encode {$FLUXER_EDGE_ENCODE:zstd gzip}

	handle /_health {
		respond "OK" 200
	}

	handle /_edge {
		header Cache-Control no-store
		respond "{system.hostname}" 200
	}

	handle_path /api/* {
		import upstream api:8080
	}

	handle /gateway {
		rewrite * /
		import upstream gateway:8080
	}

	handle_path /gateway/* {
		import upstream gateway:8080
	}

	handle_path /media/* {
		import upstream media-proxy:8080
	}

	handle_path /livekit/* {
		import upstream livekit:7880
	}

	handle {$FLUXER_ADMIN_BASE_PATH:/admin} {
		rewrite * /
		import upstream {$FLUXER_ADMIN_UPSTREAM:admin:8080}
	}

	handle_path {$FLUXER_ADMIN_BASE_PATH:/admin}/* {
		import upstream {$FLUXER_ADMIN_UPSTREAM:admin:8080}
	}

	@staticAssets path /web/* /emoji/* /libs/* /avatars/* /badges/* /desktop/*
	handle @staticAssets {
		import upstream static-proxy:8080
	}

	handle /.well-known/fluxer {
		import upstream api:8080
	}

	handle /.well-known/webfinger {
		import upstream api:8080
	}

	handle {
		import upstream app-proxy:8080
	}
}

:8088 {
	handle /.well-known/fluxer {
		import upstream api:8080
	}

	handle /_edge {
		respond "{system.hostname}" 200
	}
}

import /etc/caddy/conf.d/sites/*.caddy
"#;

// ---------------------------------------------------------------------------
// Backup manifest & rexctl state types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlManifest {
    #[serde(default)]
    pub format: u32,
    #[serde(default)]
    pub release: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub database: String,
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
    #[serde(default)]
    pub entries: Vec<RexctlEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RexctlEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RexctlState {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub runtime: String,
    #[serde(default)]
    pub release: String,
    #[serde(default)]
    pub previous_release: String,
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    #[serde(default)]
    pub secrets: BTreeMap<String, String>,
    #[serde(default)]
    pub setup_done: bool,
    #[serde(default)]
    pub images: serde_json::Value,
}

/// Everything parsed from a `rexctl` backup archive.
#[derive(Debug)]
pub struct ExtractedBackup {
    pub manifest: RexctlManifest,
    pub state: Option<RexctlState>,
    pub dotenv: BTreeMap<String, String>,
    pub caddyfile: Option<String>,
    pub caddy_dropins: BTreeMap<String, String>,
    pub compose_images: BTreeMap<String, String>,
    pub postgres_dump: Option<PathBuf>,
    pub postgres_dump_size: u64,
    /// volume short name (e.g. "meilisearch-data") -> extracted directory path
    pub volumes: BTreeMap<String, PathBuf>,
    pub work_dir: PathBuf,
    pub verified_entries: usize,
    pub is_native: bool,
}

impl Drop for ExtractedBackup {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl ExtractedBackup {
    pub fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.work_dir);
    }

    pub fn project_name(&self) -> String {
        let raw = if !self.manifest.project.trim().is_empty() {
            self.manifest.project.as_str()
        } else if let Some(s) = &self.state {
            if !s.project.trim().is_empty() {
                s.project.as_str()
            } else {
                "fluxer"
            }
        } else {
            "fluxer"
        };
        sanitize_name(raw)
    }

    pub fn domain(&self) -> String {
        if !self.manifest.domain.trim().is_empty() {
            return self.manifest.domain.trim().to_ascii_lowercase();
        }
        if let Some(s) = &self.state {
            if let Some(d) = s.settings.get("domain").or_else(|| s.settings.get("FLUXER_DOMAIN")) {
                if !d.trim().is_empty() {
                    return d.trim().to_ascii_lowercase();
                }
            }
        }
        if let Some(d) = self.dotenv.get("FLUXER_DOMAIN") {
            if !d.trim().is_empty() {
                return d.trim().to_ascii_lowercase();
            }
        }
        String::new()
    }

    pub fn release(&self) -> String {
        if !self.manifest.release.trim().is_empty() {
            return self.manifest.release.trim().to_string();
        }
        if let Some(s) = &self.state {
            if !s.release.trim().is_empty() {
                return s.release.trim().to_string();
            }
        }
        String::new()
    }

    /// Build a `FluxerStack` ready to store in cluster state and plan services.
    pub fn to_stack(
        &self,
        project_override: Option<&str>,
        domain_override: Option<&str>,
        release_override: Option<&str>,
        auto_upgrade: bool,
        region: Option<String>,
        copies: u32,
    ) -> Result<FluxerStack> {
        let project = sanitize_name(project_override.unwrap_or(&self.project_name()));
        util::validate_name("project", &project)?;

        let mut settings = BTreeMap::new();
        let mut secrets = BTreeMap::new();

        // Merge legacy .env first so rexctl state.json takes precedence.
        for (k, v) in &self.dotenv {
            if k.starts_with("COMPOSE_") || k == "FLUXER_SETTINGS_LOADED" || v.is_empty() {
                continue;
            }
            if is_secret_entry(k, v) {
                secrets.insert(k.clone(), v.clone());
            } else {
                settings.insert(k.clone(), v.clone());
            }
        }
        if let Some(st) = &self.state {
            for (k, v) in &st.settings {
                if !v.is_empty() {
                    if is_secret_entry(k, v) && k != "storage.secret_key" && k != "storage.access_key" {
                        secrets.insert(k.clone(), v.clone());
                    } else {
                        settings.insert(k.clone(), v.clone());
                    }
                }
            }
            for (k, v) in &st.secrets {
                if !v.is_empty() {
                    secrets.insert(k.clone(), v.clone());
                }
            }
        }

        let backup_domain = self.domain();
        let domain = domain_override
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| backup_domain.clone());
        if domain.is_empty() {
            bail!("backup has no domain configured — pass --domain <your-domain>");
        }
        crate::config::validate_domain(&domain)?;
        if !backup_domain.is_empty() && domain != backup_domain {
            clear_stale_domain_settings(&mut settings, &backup_domain);
        }
        settings.insert("domain".into(), domain.clone());

        let release = release_override
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| self.release());

        let storage_backend = settings
            .get("storage.backend")
            .or_else(|| settings.get("FLUXER_STORAGE_BACKEND"))
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        let storage_endpoint = settings
            .get("storage.endpoint")
            .or_else(|| settings.get("FLUXER_S3_ENDPOINT"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !is_bundled_seaweedfs_endpoint(s));
        let external_object_store = storage_backend != "filesystem" && storage_endpoint.is_some();

        let bundled_voice = settings
            .get("voice.bundled")
            .or_else(|| settings.get("FLUXER_LIVEKIT_BUNDLED"))
            .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no" | "off"))
            .unwrap_or(true);

        let kv_postgres = settings
            .get("kv.mode")
            .or_else(|| settings.get("FLUXER_KV_MODE"))
            .map(|v| v.trim().eq_ignore_ascii_case("postgres"))
            .unwrap_or(false);

        let rust_single = settings
            .get("rust.process")
            .or_else(|| settings.get("FLUXER_RUST_PROCESS"))
            .map(|v| v.trim().eq_ignore_ascii_case("single"))
            .unwrap_or(false);

        let caddyfile_custom = self
            .caddyfile
            .as_deref()
            .map(|c| !c.trim().is_empty() && c != DEFAULT_CADDYFILE)
            .unwrap_or(false);

        let now = util::now();
        Ok(FluxerStack {
            project,
            domain,
            release,
            previous_release: None,
            auto_upgrade,
            upgrade_interval_hours: 6,
            last_check: 0,
            last_upgrade: 0,
            last_error: None,
            latest_available: None,
            settings,
            secrets,
            caddyfile: self
                .caddyfile
                .clone()
                .unwrap_or_else(|| DEFAULT_CADDYFILE.to_string()),
            caddyfile_custom,
            caddy_dropins: self.caddy_dropins.clone(),
            services: vec![],
            external_object_store,
            bundled_voice,
            kv_postgres,
            rust_single,
            copies: copies.max(1),
            region,
            image_overrides: self.compose_images.clone(),
            created_at: now,
            updated_at: now,
        })
    }
}

/// Remove derived URL/origin settings that still point to `old_domain` so changing
/// the stack domain regenerates fresh endpoints cleanly.
pub fn clear_stale_domain_settings(settings: &mut BTreeMap<String, String>, old_domain: &str) {
    let old = old_domain.trim().to_ascii_lowercase();
    if old.is_empty() {
        return;
    }
    const DERIVED_KEYS: &[&str] = &[
        "FLUXER_PUBLIC_ORIGIN",
        "FLUXER_APP_ENDPOINT",
        "FLUXER_MEDIA_ENDPOINT",
        "FLUXER_MEDIA_PROXY_PUBLIC_ENDPOINT",
        "FLUXER_MEDIA_PROXY_UPLOAD_RELAY_ENDPOINT",
        "FLUXER_ADMIN_ENDPOINT",
        "FLUXER_MARKETING_ENDPOINT",
        "FLUXER_LIVEKIT_URL",
        "FLUXER_PASSKEY_RP_ID",
        "FLUXER_PASSKEY_ADDITIONAL_ALLOWED_ORIGINS",
        "FLUXER_GATEWAY_MEDIA_PROXY_ENDPOINT",
        "FLUXER_GATEWAY_STATIC_CDN_ENDPOINT",
        "FLUXER_MEDIA_PROXY_CORS_ALLOWED_ORIGINS",
        "FLUXER_STATIC_CDN_ENDPOINT",
    ];
    for key in DERIVED_KEYS {
        if let Some(val) = settings.get(*key) {
            if val.to_ascii_lowercase().contains(&old) {
                settings.remove(*key);
            }
        }
    }
}

/// True when an S3 endpoint URL targets the bundled `seaweedfs` service rather than an external S3/R2 host.
pub fn is_bundled_seaweedfs_endpoint(endpoint: &str) -> bool {
    let is_bundled_host = |h: &str| {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        h == "seaweedfs"
            || h == "seaweedfs.internal"
            || (h.starts_with("seaweedfs.") && h.ends_with(".internal"))
            || h.ends_with("-seaweedfs.internal")
    };
    let s = endpoint.trim();
    if let Ok(u) = reqwest::Url::parse(s) {
        if let Some(host) = u.host_str() {
            return is_bundled_host(host);
        }
    }
    let host_port = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
        .unwrap_or(s)
        .split('/')
        .next()
        .unwrap_or("");
    let host = host_port.split(':').next().unwrap_or("");
    is_bundled_host(host)
}

pub fn sanitize_name(s: &str) -> String {
    let s: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let trimmed = s.trim_matches('-').to_string();
    let mut out = String::new();
    for c in trimmed.chars() {
        if !(c == '-' && out.ends_with('-')) {
            out.push(c);
        }
    }
    let truncated: String = out.chars().take(32).collect();
    let clean = truncated.trim_end_matches('-');
    if clean.is_empty() {
        "fluxer".into()
    } else {
        clean.to_string()
    }
}

// ---------------------------------------------------------------------------
// Archive extraction & verification (.tar.zst / .tar.gz / .tar)
// ---------------------------------------------------------------------------

fn safe_rel_path(raw: &str) -> Result<PathBuf> {
    if raw.contains('\0') {
        bail!("unsafe NUL byte in backup archive path");
    }
    let normalized = raw.replace('\\', "/");
    let trimmed = normalized.trim_start_matches("./");
    let p = Path::new(trimmed);
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.contains('\0') {
                    bail!("unsafe path in backup archive: {raw}");
                }
                out.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe path in backup archive: {raw}");
            }
        }
    }
    Ok(out)
}

fn canonical_arc_path(rel: &Path) -> String {
    rel.components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_safe_release_segment(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && !s.contains("..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn check_no_symlink_ancestors(root: &Path, rel: &Path) -> Result<()> {
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if let Ok(meta) = std::fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                bail!("backup archive attempts to traverse symlink at {}", cur.display());
            }
        }
    }
    Ok(())
}

/// Validate a symlink target inside `volumes/<vol>/...` so it cannot escape its volume root.
fn validate_volume_symlink(rel: &Path, target: &Path) -> Result<()> {
    let comps: Vec<String> = rel
        .components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if comps.len() < 3 || comps[0] != "volumes" {
        bail!("symlinks are not allowed outside volumes/ in backup archives ({})", rel.display());
    }
    if target.is_absolute() {
        bail!("absolute symlink target rejected in backup archive: {}", target.display());
    }
    let mut depth: i64 = (comps.len() as i64) - 3; // depth of parent dir relative to volumes/<vol>
    for c in target.components() {
        match c {
            Component::CurDir => {}
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    bail!(
                        "symlink '{}' in backup archive escapes volume boundary via '{}'",
                        rel.display(),
                        target.display()
                    );
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("unsafe symlink target in backup archive: {}", target.display());
            }
        }
    }
    Ok(())
}

fn open_archive_reader(path: &Path) -> Result<Box<dyn Read>> {
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic)?;
    f.seek(SeekFrom::Start(0))?;
    if n >= 4 && magic == [0x28, 0xB5, 0x2F, 0xFD] {
        let dec = zstd::stream::read::Decoder::new(f).context("invalid zstd backup archive")?;
        Ok(Box::new(dec))
    } else if n >= 2 && magic[0] == 0x1F && magic[1] == 0x8B {
        Ok(Box::new(flate2::read::GzDecoder::new(f)))
    } else {
        Ok(Box::new(f))
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn sha256_file(path: &Path) -> Result<(u64, String)> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        h.update(&buf[..n]);
    }
    Ok((total, format!("{:x}", h.finalize())))
}

pub fn extract_and_verify_backup(path: &Path, verify: bool) -> Result<ExtractedBackup> {
    let work_dir = std::env::temp_dir().join(format!("latrix-rexctl-{}", util::random_id(8)));
    util::create_private_dir_all(&work_dir)?;

    let res = extract_inner(path, &work_dir, verify);
    if res.is_err() {
        let _ = std::fs::remove_dir_all(&work_dir);
    }
    res
}

fn extract_inner(path: &Path, work_dir: &Path, verify: bool) -> Result<ExtractedBackup> {
    let reader = open_archive_reader(path)?;
    let mut ar = tar::Archive::new(reader);

    let mut hashes: BTreeMap<String, (u64, String)> = BTreeMap::new();
    let mut sums_text: Option<String> = None;
    let mut entry_count = 0usize;
    let mut total_bytes = 0u64;

    for entry in ar.entries().context("reading backup tar archive")? {
        entry_count += 1;
        if entry_count > MAX_BACKUP_ENTRIES {
            bail!("backup archive exceeds maximum entry limit ({MAX_BACKUP_ENTRIES})");
        }
        let mut entry = entry?;
        let raw_path = entry.path()?.to_string_lossy().replace('\\', "/");
        let rel = safe_rel_path(&raw_path)?;
        let canon = canonical_arc_path(&rel);
        let etype = entry.header().entry_type();
        if canon.is_empty() {
            if etype.is_dir() {
                continue;
            }
            bail!("empty entry path in backup archive: '{raw_path}'");
        }
        check_no_symlink_ancestors(work_dir, &rel)?;
        let dest = work_dir.join(&rel);
        if etype.is_dir() {
            std::fs::create_dir_all(&dest)?;
            continue;
        }
        if etype.is_symlink() {
            let link = entry
                .link_name()?
                .ok_or_else(|| anyhow::anyhow!("symlink '{canon}' missing target"))?;
            validate_volume_symlink(&rel, &link)?;
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            #[cfg(unix)]
            {
                if dest.exists() || std::fs::symlink_metadata(&dest).is_ok() {
                    let _ = std::fs::remove_file(&dest);
                }
                std::os::unix::fs::symlink(&link, &dest)?;
            }
            continue;
        }
        if !etype.is_file() {
            bail!("unsupported archive entry type {:?} at '{canon}'", etype);
        }
        if hashes.contains_key(&canon) {
            bail!("duplicate entry '{canon}' in backup archive");
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = std::fs::File::create(&dest)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut file_bytes = 0u64;
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            total_bytes = total_bytes.saturating_add(n as u64);
            if total_bytes > MAX_BACKUP_BYTES {
                bail!("backup archive exceeds maximum extracted size ({MAX_BACKUP_BYTES} bytes)");
            }
            out.write_all(&buf[..n])?;
            hasher.update(&buf[..n]);
            file_bytes += n as u64;
        }
        out.flush()?;
        let digest = format!("{:x}", hasher.finalize());
        if canon == "SHA256SUMS" {
            sums_text = Some(std::fs::read_to_string(&dest).context("reading SHA256SUMS")?);
        }
        hashes.insert(canon, (file_bytes, digest));
    }

    let manifest_path = work_dir.join("manifest.json");
    if !manifest_path.exists() {
        bail!("not a rexctl backup archive (missing manifest.json)");
    }
    let manifest: RexctlManifest = serde_json::from_slice(
        &std::fs::read(&manifest_path).context("reading manifest.json")?,
    )
    .context("invalid manifest.json in backup archive")?;

    if manifest.format > BACKUP_FORMAT_VERSION {
        bail!(
            "backup format {} is newer than supported (format {}) — upgrade latrix",
            manifest.format,
            BACKUP_FORMAT_VERSION
        );
    }

    let mut verified_entries = 0usize;
    if verify {
        let mut covered: BTreeSet<String> = BTreeSet::new();
        for e in &manifest.entries {
            let rel = safe_rel_path(&e.path)?;
            let p = canonical_arc_path(&rel);
            if p.is_empty() {
                bail!("backup damaged: empty path in manifest.json");
            }
            if e.sha256.len() != 64 || !e.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("backup damaged: invalid sha256 checksum for '{p}' in manifest.json");
            }
            let Some((sz, got)) = hashes.get(&p) else {
                bail!("backup damaged: manifest entry '{p}' is missing from archive");
            };
            if !got.eq_ignore_ascii_case(&e.sha256) {
                bail!(
                    "backup damaged: checksum mismatch for '{p}' (expected {}, got {got})",
                    e.sha256
                );
            }
            if *sz != e.size {
                bail!(
                    "backup damaged: size mismatch for '{p}' (expected {} bytes, got {sz})",
                    e.size
                );
            }
            if covered.insert(p) {
                verified_entries += 1;
            }
        }
        if let Some(sums) = &sums_text {
            for (lineno, raw_line) in sums.lines().enumerate() {
                let line = raw_line.trim();
                if line.is_empty() {
                    continue;
                }
                let Some((expected, rest)) = line.split_once(char::is_whitespace) else {
                    bail!("backup damaged: malformed SHA256SUMS line {}", lineno + 1);
                };
                let raw_file = rest.trim().trim_start_matches('*');
                if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) || raw_file.is_empty() {
                    bail!("backup damaged: malformed SHA256SUMS line {}", lineno + 1);
                }
                let rel = safe_rel_path(raw_file)?;
                let file = canonical_arc_path(&rel);
                let Some((_, got)) = hashes.get(&file) else {
                    bail!("backup damaged: SHA256SUMS entry '{file}' is missing");
                };
                if !got.eq_ignore_ascii_case(expected) {
                    bail!("backup damaged: SHA256SUMS mismatch for '{file}'");
                }
                if covered.insert(file) {
                    verified_entries += 1;
                }
            }
        }
        if verified_entries == 0 {
            bail!("backup damaged: archive contains no verifiable checksum entries (pass --skip-verify to bypass)");
        }
        for file in hashes.keys() {
            if file == "manifest.json" || file == "SHA256SUMS" {
                continue;
            }
            if !covered.contains(file) {
                bail!("backup damaged: unverified file '{file}' present in archive");
            }
        }
    }

    // Parse files/.rexctl/state.json
    let state_path = work_dir.join("files").join(".rexctl").join("state.json");
    let state: Option<RexctlState> = if state_path.exists() {
        let raw = std::fs::read(&state_path).context("reading files/.rexctl/state.json")?;
        Some(serde_json::from_slice(&raw).context("parsing files/.rexctl/state.json")?)
    } else {
        None
    };

    // Parse files/.env (fallback for older/ejected backups)
    let dotenv_path = work_dir.join("files").join(".env");
    let dotenv = if dotenv_path.exists() {
        parse_dotenv(&std::fs::read_to_string(&dotenv_path).unwrap_or_default())
    } else {
        BTreeMap::new()
    };

    // Validate manifest.release before joining it into any filesystem path.
    let safe_release = is_safe_release_segment(&manifest.release).then(|| manifest.release.trim());

    // Locate Caddyfile
    let mut caddy_candidates = vec![
        work_dir.join("files").join("Caddyfile"),
        work_dir.join("files").join(".rexctl").join("generated").join("Caddyfile"),
    ];
    if let Some(rel_seg) = safe_release {
        caddy_candidates.push(work_dir.join("files").join("releases").join(rel_seg).join("Caddyfile"));
    }
    let caddyfile = caddy_candidates
        .iter()
        .find(|p| p.is_file())
        .and_then(|p| std::fs::read_to_string(p).ok());

    // Locate caddy.d/*.caddy drop-ins
    let mut caddy_dropins = BTreeMap::new();
    let dropin_dir = work_dir.join("files").join("caddy.d");
    if dropin_dir.is_dir() {
        collect_caddy_dropins(&dropin_dir, &dropin_dir, &mut caddy_dropins);
    }

    // Parse pinned images from any compose files included in the backup
    let mut compose_images = BTreeMap::new();
    let mut compose_roots = vec![];
    if let Some(rel_seg) = safe_release {
        compose_roots.push(work_dir.join("files").join("releases").join(rel_seg));
    }
    compose_roots.push(work_dir.join("files").join(".rexctl").join("generated"));
    compose_roots.push(work_dir.join("files"));
    for root in &compose_roots {
        let base = root.join("docker-compose.yml");
        if base.is_file() {
            if let Ok(txt) = std::fs::read_to_string(&base) {
                for (k, v) in parse_compose_images(&txt) {
                    compose_images.entry(k).or_insert(v);
                }
            }
        }
        let rust = root.join("rust-server.compose.yml");
        if rust.is_file() {
            if let Ok(txt) = std::fs::read_to_string(&rust) {
                for (k, v) in parse_compose_images(&txt) {
                    compose_images.entry(k).or_insert(v);
                }
            }
        }
    }

    // Locate postgres/fluxer.dump
    let dump_path = work_dir.join("postgres").join("fluxer.dump");
    let (postgres_dump, postgres_dump_size) = if dump_path.is_file() {
        let meta = std::fs::metadata(&dump_path)?;
        if meta.len() < 5 {
            bail!("postgres/fluxer.dump is truncated ({} bytes; expected PGDMP header)", meta.len());
        }
        let mut f = std::fs::File::open(&dump_path)?;
        let mut head = [0u8; 5];
        f.read_exact(&mut head)?;
        if &head != b"PGDMP" {
            bail!("postgres/fluxer.dump does not have a valid PGDMP header");
        }
        (Some(dump_path), meta.len())
    } else {
        (None, 0)
    };

    // Locate extracted volumes/<short>/
    let mut volumes = BTreeMap::new();
    let vols_dir = work_dir.join("volumes");
    if vols_dir.is_dir() {
        for ent in std::fs::read_dir(&vols_dir)? {
            let ent = ent?;
            if ent.file_type()?.is_dir() {
                let name = ent.file_name().to_string_lossy().to_string();
                volumes.insert(name, ent.path());
            }
        }
    }

    let is_native = state
        .as_ref()
        .map(|s| s.runtime.eq_ignore_ascii_case("native"))
        .unwrap_or(false);

    Ok(ExtractedBackup {
        manifest,
        state,
        dotenv,
        caddyfile,
        caddy_dropins,
        compose_images,
        postgres_dump,
        postgres_dump_size,
        volumes,
        work_dir: work_dir.to_path_buf(),
        verified_entries,
        is_native,
    })
}

fn collect_caddy_dropins(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        let Ok(ft) = ent.file_type() else { continue };
        let p = ent.path();
        if ft.is_dir() {
            collect_caddy_dropins(base, &p, out);
        } else if ft.is_file() && p.extension().and_then(|e| e.to_str()) == Some("caddy") {
            if let (Ok(rel), Ok(content)) = (p.strip_prefix(base), std::fs::read_to_string(&p)) {
                out.insert(rel.to_string_lossy().replace('\\', "/"), content);
            }
        }
    }
}

/// Write a `rexctl`-compatible format-2 `.tar.zst` backup archive.
pub fn write_rexctl_backup(
    out_path: &Path,
    stack: &FluxerStack,
    pg_dump: Option<&Path>,
    volume_dirs: &BTreeMap<String, PathBuf>,
    scope: &str,
    reason: &str,
) -> Result<u64> {
    if let Some(parent) = out_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    // Build all virtual files in a private temporary staging directory so we can
    // compute exact sizes and SHA256 checksums for manifest.json + SHA256SUMS.
    let stage = std::env::temp_dir().join(format!("latrix-rexctl-pack-{}", util::random_id(8)));
    util::create_private_dir_all(&stage)?;
    let res = write_backup_inner(&stage, out_path, stack, pg_dump, volume_dirs, scope, reason);
    let _ = std::fs::remove_dir_all(&stage);
    res
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

fn write_backup_inner(
    stage: &Path,
    out_path: &Path,
    stack: &FluxerStack,
    pg_dump: Option<&Path>,
    volume_dirs: &BTreeMap<String, PathBuf>,
    scope: &str,
    reason: &str,
) -> Result<u64> {
    let mut entries_to_pack: Vec<(String, PathBuf, u32)> = vec![];
    let mut manifest_entries: Vec<RexctlEntry> = vec![];

    // 1. files/.rexctl/state.json
    let rex_state = RexctlState {
        schema: 6,
        kind: String::new(),
        project: stack.project.clone(),
        runtime: "compose".into(),
        release: stack.release.clone(),
        previous_release: stack.previous_release.clone().unwrap_or_default(),
        settings: stack.settings.clone(),
        secrets: stack.secrets.clone(),
        setup_done: true,
        images: serde_json::json!({}),
    };
    let state_file = stage.join("state.json");
    let state_bytes = serde_json::to_vec_pretty(&rex_state)?;
    std::fs::write(&state_file, &state_bytes)?;
    let state_arc = "files/.rexctl/state.json".to_string();
    manifest_entries.push(RexctlEntry {
        path: state_arc.clone(),
        size: state_bytes.len() as u64,
        sha256: sha256_hex(&state_bytes),
    });
    entries_to_pack.push((state_arc, state_file, 0o600));

    // 2. files/Caddyfile + drop-ins
    if !stack.caddyfile.is_empty() {
        let cf = stage.join("Caddyfile");
        std::fs::write(&cf, stack.caddyfile.as_bytes())?;
        let arc = "files/Caddyfile".to_string();
        manifest_entries.push(RexctlEntry {
            path: arc.clone(),
            size: stack.caddyfile.len() as u64,
            sha256: sha256_hex(stack.caddyfile.as_bytes()),
        });
        entries_to_pack.push((arc, cf, 0o644));
    }
    for (rel, body) in &stack.caddy_dropins {
        let safe = safe_rel_path(rel)?;
        let canon_rel = canonical_arc_path(&safe);
        if canon_rel.is_empty() {
            continue;
        }
        let f = stage.join("caddy.d").join(&safe);
        if let Some(p) = f.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&f, body.as_bytes())?;
        let arc = format!("files/caddy.d/{canon_rel}");
        manifest_entries.push(RexctlEntry {
            path: arc.clone(),
            size: body.len() as u64,
            sha256: sha256_hex(body.as_bytes()),
        });
        entries_to_pack.push((arc, f, 0o644));
    }

    // 3. postgres/fluxer.dump
    if let Some(dump) = pg_dump {
        let (sz, sha) = sha256_file(dump)?;
        manifest_entries.push(RexctlEntry {
            path: DUMP_ENTRY.into(),
            size: sz,
            sha256: sha,
        });
        entries_to_pack.push((DUMP_ENTRY.into(), dump.to_path_buf(), 0o600));
    }

    // 4. volumes/<short>/...
    let mut vol_names = vec![];
    for (short, dir) in volume_dirs {
        vol_names.push(short.clone());
        collect_dir_entries(dir, dir, &format!("volumes/{short}"), &mut entries_to_pack, &mut manifest_entries)?;
    }

    let manifest = RexctlManifest {
        format: BACKUP_FORMAT_VERSION,
        release: stack.release.clone(),
        project: stack.project.clone(),
        domain: stack.domain.clone(),
        created_at: rfc3339_utc(util::now()),
        reason: Some(reason.to_string()),
        database: if pg_dump.is_some() { DUMP_ENTRY.into() } else { String::new() },
        volumes: vol_names,
        skipped: if pg_dump.is_none() { vec!["database".into()] } else { vec![] },
        left: vec![],
        scope: scope.to_string(),
        entries: manifest_entries.clone(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;

    let mut sums = String::new();
    for e in &manifest_entries {
        sums.push_str(&format!("{}  {}\n", e.sha256, e.path));
    }

    let tmp_out = out_path.with_extension(format!("tmp-{}", util::random_id(8)));
    let write_res = (|| -> Result<()> {
        let out_file = create_private_file(&tmp_out)?;
        let enc = zstd::stream::write::Encoder::new(out_file, 3)?;
        let mut tar = tar::Builder::new(enc);
        let now = util::now();

        let mut add_bytes = |name: &str, data: &[u8], mode: u32| -> Result<()> {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(mode);
            h.set_mtime(now);
            h.set_cksum();
            tar.append_data(&mut h, name, data)?;
            Ok(())
        };
        add_bytes("manifest.json", &manifest_bytes, 0o600)?;
        add_bytes("SHA256SUMS", sums.as_bytes(), 0o600)?;

        for (arc_name, src, mode) in &entries_to_pack {
            let mut f = std::fs::File::open(src)?;
            let meta = f.metadata()?;
            let mut h = tar::Header::new_gnu();
            h.set_size(meta.len());
            h.set_mode(*mode);
            h.set_mtime(now);
            h.set_cksum();
            tar.append_data(&mut h, arc_name, &mut f)?;
        }

        let enc = tar.into_inner()?;
        let mut file = enc.finish()?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp_out);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp_out, out_path) {
        let _ = std::fs::remove_file(&tmp_out);
        return Err(e).with_context(|| format!("moving backup archive into {}", out_path.display()));
    }
    crate::agent::set_private(out_path);
    Ok(std::fs::metadata(out_path)?.len())
}

fn collect_dir_entries(
    base: &Path,
    dir: &Path,
    prefix: &str,
    entries_to_pack: &mut Vec<(String, PathBuf, u32)>,
    manifest_entries: &mut Vec<RexctlEntry>,
) -> Result<()> {
    let mut items: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    items.sort_by_key(|e| e.file_name());
    for ent in items {
        let p = ent.path();
        let ft = ent.file_type()?;
        if ft.is_dir() {
            collect_dir_entries(base, &p, prefix, entries_to_pack, manifest_entries)?;
        } else if ft.is_file() {
            let rel = p.strip_prefix(base)?.to_string_lossy().replace('\\', "/");
            let arc = format!("{prefix}/{rel}");
            let (sz, sha) = sha256_file(&p)?;
            manifest_entries.push(RexctlEntry { path: arc.clone(), size: sz, sha256: sha });
            entries_to_pack.push((arc, p, 0o644));
        }
    }
    Ok(())
}

/// Format unix timestamp as RFC3339 UTC (`2026-11-27T01:30:00Z`).
pub fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if mo <= 2 { 1 } else { 0 };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Pack a local directory into a `.tar.gz` file (for uploading to `/v1/m/{id}/volume-data`).
pub fn pack_dir_targz(dir: &Path, out: &Path) -> Result<u64> {
    let f = std::fs::File::create(out)?;
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::fast());
    let mut tar = tar::Builder::new(gz);
    tar.follow_symlinks(false);
    tar.append_dir_all(".", dir)?;
    let gz = tar.into_inner()?;
    let mut f = gz.finish()?;
    f.flush()?;
    Ok(std::fs::metadata(out)?.len())
}

// ---------------------------------------------------------------------------
// Release resolver & compose bundle parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxerRelease {
    pub version: String,
    #[serde(default)]
    pub min_from: String,
    #[serde(default)]
    pub schema_changed: bool,
    #[serde(default)]
    pub compose_url: String,
}

#[derive(Debug, Clone, Default)]
pub struct ComposeBundle {
    pub images: BTreeMap<String, String>,
    pub caddyfile: Option<String>,
}

pub fn parse_fluxer_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.trim().trim_start_matches('v');
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let y: u64 = parts[0].parse().ok()?;
    let m: u64 = parts[1].parse().ok()?;
    let p: u64 = if parts.len() == 3 { parts[2].parse().ok()? } else { 0 };
    if y < 2000 {
        return None;
    }
    Some((y, m, p))
}

pub fn compare_fluxer_versions(a: &str, b: &str) -> std::cmp::Ordering {
    match (parse_fluxer_version(a), parse_fluxer_version(b)) {
        (Some(pa), Some(pb)) => pa.cmp(&pb),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, None) => a.cmp(b),
    }
}

pub fn is_newer_fluxer(candidate: &str, current: &str) -> bool {
    if current.trim().is_empty() {
        return parse_fluxer_version(candidate).is_some();
    }
    compare_fluxer_versions(candidate, current) == std::cmp::Ordering::Greater
}

pub fn check_upgrade_path(from: &str, to: &FluxerRelease) -> Result<()> {
    let min = to.min_from.trim();
    if min.is_empty() || from.trim().is_empty() {
        return Ok(());
    }
    if parse_fluxer_version(min).is_none() {
        bail!(
            "Fluxer release {} specifies an unparseable minimum source release '{}' — refusing upgrade",
            to.version,
            min
        );
    }
    if parse_fluxer_version(from).is_none() {
        bail!(
            "cannot verify upgrade path from unparseable release '{}' to {} (requires >= {})",
            from,
            to.version,
            min
        );
    }
    if compare_fluxer_versions(from, min) == std::cmp::Ordering::Less {
        bail!(
            "Fluxer {from} cannot upgrade directly to {} (minimum source release is {min}). Upgrade to {min} first: `latrix rexctl upgrade {min}`",
            to.version,
        );
    }
    Ok(())
}

pub fn postgres_major(image_ref: &str) -> Option<u32> {
    let r = image_ref.trim().split('@').next().unwrap_or("");
    let base = r.rsplit('/').next().unwrap_or(r);
    let (_, tag) = base.split_once(':')?;
    let digits: String = tag.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u32>().ok().filter(|&n| n > 0)
}

fn validate_release_url(raw: &str) -> Result<reqwest::Url> {
    let u = reqwest::Url::parse(raw.trim()).with_context(|| format!("invalid Fluxer URL '{raw}'"))?;
    if !u.username().is_empty() || u.password().is_some() {
        bail!("Fluxer URL must not contain embedded credentials");
    }
    let host = u.host_str().ok_or_else(|| anyhow::anyhow!("Fluxer URL missing host"))?;
    let is_local_test = host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1";
    match u.scheme() {
        "https" => {}
        "http" if is_local_test => {}
        other => bail!("Fluxer URL must use https:// (got {other}://)"),
    }
    if !is_local_test {
        let lower = host.trim_end_matches('.').to_ascii_lowercase();
        if lower.ends_with(".internal") || lower.ends_with(".localhost") {
            bail!("Fluxer URL host '{host}' is not allowed");
        }
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                bail!("Fluxer URL IP '{ip}' is not allowed");
            }
            match ip {
                IpAddr::V4(v4) => {
                    let [a, b, _, _] = v4.octets();
                    if (a == 169 && b == 254) || (a == 10 && (b == 77 || b == 78)) {
                        bail!("Fluxer URL IP '{ip}' is not allowed");
                    }
                }
                IpAddr::V6(v6) => {
                    if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                        bail!("Fluxer URL IP '{ip}' is not allowed");
                    }
                }
            }
        }
    }
    Ok(u)
}

fn release_http_client() -> Result<reqwest::Client> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        let target = attempt.url().as_str();
        if let Err(e) = validate_release_url(target) {
            return attempt.error(e.to_string());
        }
        // Prevent HTTPS -> HTTP downgrade on redirects.
        if let Some(prev) = attempt.previous().last() {
            if prev.scheme() == "https" && attempt.url().scheme() != "https" {
                return attempt.error("refusing HTTPS-to-HTTP redirect");
            }
        }
        attempt.follow()
    });
    Ok(reqwest::Client::builder()
        .redirect(policy)
        .timeout(Duration::from_secs(90))
        .build()?)
}

pub async fn resolve_release(_client: &reqwest::Client, version: Option<&str>) -> Result<FluxerRelease> {
    let base = std::env::var("REXCTL_RELEASE_URL").unwrap_or_else(|_| DEFAULT_RELEASE_URL.into());
    let mut url = validate_release_url(&base)?;
    if let Some(v) = version.map(str::trim).filter(|v| !v.is_empty()) {
        if !is_safe_release_segment(v) {
            bail!("invalid Fluxer release version '{v}'");
        }
        url.query_pairs_mut().append_pair("version", v);
    }
    let http = release_http_client()?;
    let resp = http
        .get(url.clone())
        .header("Accept", "application/json")
        .header("User-Agent", format!("latrix/{}", util::VERSION))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .with_context(|| format!("fetching Fluxer release metadata from {url}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("unknown Fluxer release '{}'", version.unwrap_or("latest"));
    }
    if !resp.status().is_success() {
        bail!("Fluxer release resolver returned {}", resp.status());
    }
    let body = resp.bytes().await.context("reading Fluxer release.json")?;
    if body.len() > 1024 * 1024 {
        bail!("Fluxer release.json response is unexpectedly large");
    }
    let rel: FluxerRelease = serde_json::from_slice(&body).context("invalid Fluxer release.json")?;
    if parse_fluxer_version(&rel.version).is_none() {
        bail!("unexpected Fluxer release version '{}'", rel.version);
    }
    if !rel.compose_url.trim().is_empty() {
        validate_release_url(&rel.compose_url)?;
    }
    Ok(rel)
}

pub async fn fetch_compose_bundle(_client: &reqwest::Client, compose_url: &str) -> Result<ComposeBundle> {
    if compose_url.trim().is_empty() {
        return Ok(ComposeBundle::default());
    }
    let url = validate_release_url(compose_url)?;
    let http = release_http_client()?;
    let mut resp = http
        .get(url)
        .header("User-Agent", format!("latrix/{}", util::VERSION))
        .timeout(Duration::from_secs(90))
        .send()
        .await
        .with_context(|| format!("downloading Fluxer compose bundle {compose_url}"))?
        .error_for_status()
        .with_context(|| format!("downloading Fluxer compose bundle {compose_url}"))?;
    if let Some(len) = resp.content_length() {
        if len > MAX_COMPOSE_BUNDLE_BYTES as u64 {
            bail!("Fluxer compose bundle exceeds {MAX_COMPOSE_BUNDLE_BYTES} bytes");
        }
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_COMPOSE_BUNDLE_BYTES {
            bail!("Fluxer compose bundle exceeds {MAX_COMPOSE_BUNDLE_BYTES} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }

    let dec = flate2::read::GzDecoder::new(bytes.as_slice());
    let mut ar = tar::Archive::new(dec);
    let mut bundle = ComposeBundle::default();
    let mut entries_seen = 0usize;
    for entry in ar.entries()? {
        entries_seen += 1;
        if entries_seen > 1000 {
            bail!("Fluxer compose bundle contains too many archive entries");
        }
        let entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let raw_name = entry.path()?.to_string_lossy().replace('\\', "/");
        let Ok(rel) = safe_rel_path(&raw_name) else { continue };
        let norm = canonical_arc_path(&rel);
        if norm == "docker-compose.yml" || norm == "rust-server.compose.yml" {
            let mut txt = String::new();
            entry.take(MAX_COMPOSE_TEXT_BYTES + 1).read_to_string(&mut txt)?;
            if txt.len() as u64 > MAX_COMPOSE_TEXT_BYTES {
                bail!("compose file '{norm}' exceeds maximum size");
            }
            for (k, v) in parse_compose_images(&txt) {
                bundle.images.insert(k, v);
            }
        } else if norm == "Caddyfile" {
            let mut txt = String::new();
            entry.take(MAX_COMPOSE_TEXT_BYTES + 1).read_to_string(&mut txt)?;
            if txt.len() as u64 > MAX_COMPOSE_TEXT_BYTES {
                bail!("Caddyfile in compose bundle exceeds maximum size");
            }
            if !txt.trim().is_empty() {
                bundle.caddyfile = Some(txt);
            }
        }
    }
    Ok(bundle)
}

/// Extract `service -> image` from a Fluxer `docker-compose.yml` or overlay,
/// unwrapping `${VAR:-default}` to `default`.
pub fn parse_compose_images(yaml_text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(yaml_text) else {
        return out;
    };
    let Some(services) = doc["services"].as_mapping() else {
        return out;
    };
    for (k, v) in services {
        let Some(svc) = k.as_str() else { continue };
        let Some(raw) = v["image"].as_str() else { continue };
        if let Some(resolved) = unwrap_compose_image(raw) {
            if util::validate_image_ref(&resolved).is_ok() {
                out.insert(svc.to_string(), resolved);
            }
        }
    }
    out
}

fn unwrap_compose_image(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // `${FLUXER_POSTGRES_IMAGE:-postgres:16-alpine@sha256:...}` -> `postgres:16-alpine@sha256:...`
    if let Some(inner) = raw.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        if let Some((_, def)) = inner.split_once(":-") {
            if !def.contains("${") && !def.is_empty() {
                return Some(def.to_string());
            }
        }
        return None;
    }
    if raw.contains("${") {
        return None;
    }
    Some(raw.to_string())
}

pub fn parse_dotenv(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim();
            let val = if let Some(inner) = v.strip_prefix('"') {
                // Parse double-quoted value with standard escapes until closing quote.
                let mut buf = String::new();
                let mut chars = inner.chars();
                while let Some(c) = chars.next() {
                    if c == '\\' {
                        match chars.next() {
                            Some('n') => buf.push('\n'),
                            Some('r') => buf.push('\r'),
                            Some('t') => buf.push('\t'),
                            Some('"') => buf.push('"'),
                            Some('\\') => buf.push('\\'),
                            Some(other) => {
                                buf.push('\\');
                                buf.push(other);
                            }
                            None => buf.push('\\'),
                        }
                    } else if c == '"' {
                        break;
                    } else {
                        buf.push(c);
                    }
                }
                buf
            } else if let Some(inner) = v.strip_prefix('\'') {
                // Single-quoted literal until next single quote.
                inner.split_once('\'').map(|(a, _)| a).unwrap_or(inner).to_string()
            } else {
                // Strip unquoted inline `#` comment only when preceded by whitespace.
                let mut end = v.len();
                let mut prev_ws = false;
                for (idx, c) in v.char_indices() {
                    if c == '#' && prev_ws {
                        end = idx;
                        break;
                    }
                    prev_ws = c.is_whitespace();
                }
                v[..end].trim().to_string()
            };
            if !k.is_empty() {
                out.insert(k.to_string(), val);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Settings -> Effective Env & Service Stack Planner
// ---------------------------------------------------------------------------

fn has_url_creds(val: &str) -> bool {
    let Some(pos) = val.find("://") else { return false };
    let after = &val[pos + 3..];
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    authority.contains('@')
}

pub fn is_secret_var(k: &str) -> bool {
    let u = k.to_ascii_uppercase();
    u.contains("SECRET")
        || u.contains("PASSWORD")
        || u.contains("TOKEN")
        || u.contains("PRIVATE_KEY")
        || u.contains("API_KEY")
        || u == "MEILI_MASTER_KEY"
        || u == "LIVEKIT_KEYS"
        || u == "LIVEKIT_CONFIG"
        || u == "FLUXER_LIVEKIT_TURN_SERVERS"
        || u == "FLUXER_ERLANG_COOKIE"
        || u == "FLUXER_S3_ACCESS_KEY_ID"
        || u == "FLUXER_S3_ACCESS_KEY"
        || u == "FLUXER_POSTGRES_URL"
        || u == "STORAGE.SECRET_KEY"
}

pub fn is_secret_entry(k: &str, v: &str) -> bool {
    is_secret_var(k) || has_url_creds(v)
}

/// Named setting -> primary env var mapping (matching `fluxer_rexctl/internal/settings/keys.go`).
pub fn named_setting_to_var(name: &str) -> Option<&'static str> {
    match name {
        "domain" => Some("FLUXER_DOMAIN"),
        "edge.bind" => Some("FLUXER_EDGE_BIND"),
        "edge.listen_address" => Some("FLUXER_EDGE_LISTEN_ADDRESS"),
        "edge.http_port" => Some("FLUXER_HTTP_PORT"),
        "edge.https_port" => Some("FLUXER_HTTPS_PORT"),
        "edge.public_port" => Some("FLUXER_PUBLIC_PORT"),
        "edge.trusted_proxies" => Some("FLUXER_EDGE_TRUSTED_PROXIES"),
        "voice.tcp_port" => Some("FLUXER_LIVEKIT_TCP_PORT"),
        "voice.udp_port" => Some("FLUXER_LIVEKIT_UDP_PORT"),
        "voice.public_ip" => Some("FLUXER_LIVEKIT_NODE_IP"),
        "voice.bundled" => Some("FLUXER_LIVEKIT_BUNDLED"),
        "storage.endpoint" => Some("FLUXER_S3_ENDPOINT"),
        "storage.public_endpoint" => Some("FLUXER_S3_PUBLIC_ENDPOINT"),
        "storage.region" => Some("FLUXER_S3_REGION"),
        "storage.path_style" => Some("FLUXER_S3_FORCE_PATH_STYLE"),
        "storage.access_key" => Some("FLUXER_S3_ACCESS_KEY"),
        "storage.secret_key" => Some("FLUXER_S3_SECRET_KEY"),
        "storage.backend" => Some("FLUXER_STORAGE_BACKEND"),
        "kv.mode" => Some("FLUXER_KV_MODE"),
        "rust.process" => Some("FLUXER_RUST_PROCESS"),
        "network.http_proxy" => Some("HTTP_PROXY"),
        "network.https_proxy" => Some("HTTPS_PROXY"),
        "network.no_proxy" => Some("NO_PROXY"),
        "sso.allow_private_addresses" => Some("FLUXER_SSO_ALLOW_PRIVATE_ADDRESSES"),
        "media.signed_attachments" => Some("FLUXER_MEDIA_PROXY_ATTACHMENT_SIGNATURE_MODE"),
        "images.postgres" => Some("FLUXER_POSTGRES_IMAGE"),
        "images.valkey" => Some("FLUXER_VALKEY_IMAGE"),
        "images.nats" => Some("FLUXER_NATS_IMAGE"),
        "images.meilisearch" => Some("FLUXER_MEILISEARCH_IMAGE"),
        "images.seaweedfs" => Some("FLUXER_SEAWEEDFS_IMAGE"),
        "images.livekit" => Some("FLUXER_LIVEKIT_IMAGE"),
        "images.edge" => Some("FLUXER_CADDY_IMAGE"),
        _ => None,
    }
}

fn is_raw_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !name.as_bytes()[0].is_ascii_digit()
}

/// Compute the effective environment map from `FluxerStack.settings` and `FluxerStack.secrets`.
pub fn effective_env(stack: &FluxerStack) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    // 1. Secrets first (lower precedence than explicit settings if both exist)
    for (k, v) in &stack.secrets {
        if !v.is_empty() {
            env.insert(k.clone(), v.clone());
        }
    }

    // 2. Named settings
    for (k, v) in &stack.settings {
        if v.is_empty() {
            continue;
        }
        if k == "voice.public_ip" {
            env.insert("FLUXER_LIVEKIT_NODE_IP".into(), v.clone());
            env.insert("FLUXER_LIVEKIT_USE_EXTERNAL_IP".into(), "false".into());
        } else if let Some(var) = named_setting_to_var(k) {
            env.insert(var.into(), v.clone());
        } else if is_raw_env_name(k) {
            env.insert(k.clone(), v.clone());
        }
    }

    // 3. Derived domain/origin variables
    let domain = stack.domain.trim().to_ascii_lowercase();
    let scheme = env
        .get("FLUXER_PUBLIC_SCHEME")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https".into());
    let public_port = env
        .get("FLUXER_PUBLIC_PORT")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| if scheme == "http" { "80".into() } else { "443".into() });
    let origin = env
        .get("FLUXER_PUBLIC_ORIGIN")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if (scheme == "https" && public_port == "443") || (scheme == "http" && public_port == "80") {
                format!("{scheme}://{domain}")
            } else {
                format!("{scheme}://{domain}:{public_port}")
            }
        });

    env.insert("FLUXER_DOMAIN".into(), domain.clone());
    env.insert("FLUXER_BASE_DOMAIN".into(), domain);
    env.insert("FLUXER_PUBLIC_SCHEME".into(), scheme);
    env.insert("FLUXER_PUBLIC_PORT".into(), public_port);
    env.insert("FLUXER_PUBLIC_ORIGIN".into(), origin.clone());

    // Mirror rexctl's S3 access/secret env aliases (FLUXER_S3_ACCESS_KEY -> FLUXER_S3_ACCESS_KEY_ID)
    if let Some(ak) = env.get("FLUXER_S3_ACCESS_KEY").cloned() {
        env.entry("FLUXER_S3_ACCESS_KEY_ID".into()).or_insert(ak);
    }
    if let Some(sk) = env.get("FLUXER_S3_SECRET_KEY").cloned() {
        env.entry("FLUXER_S3_SECRET_ACCESS_KEY".into()).or_insert(sk);
    }

    // Mirror LiveKit key aliases
    if let Some(lk) = env.get("LIVEKIT_API_KEY").cloned() {
        env.entry("FLUXER_LIVEKIT_API_KEY".into()).or_insert(lk);
    }
    if let Some(ls) = env.get("LIVEKIT_API_SECRET").cloned() {
        env.entry("FLUXER_LIVEKIT_API_SECRET".into()).or_insert(ls);
    }

    // Mirror Meilisearch master key
    if let Some(mk) = env.get("MEILI_MASTER_KEY").cloned() {
        env.entry("FLUXER_SEARCH_API_KEY".into()).or_insert(mk);
    }

    // Mirror Postgres password
    if let Some(pw) = env.get("POSTGRES_PASSWORD").cloned() {
        env.entry("FLUXER_POSTGRES_PASSWORD".into()).or_insert(pw);
    }

    env
}

fn default_image(service: &str) -> String {
    match service {
        "edge" => "caddy:2.11-alpine".into(),
        "postgres" => "postgres:16-alpine".into(),
        "valkey" => "valkey/valkey:9.1-alpine".into(),
        "nats" => "nats:2.14-alpine".into(),
        "meilisearch" => "getmeili/meilisearch:v1.53".into(),
        "seaweedfs" => "chrislusf/seaweedfs:4.52".into(),
        "livekit" => "livekit/livekit-server:v1.12.0".into(),
        "api" | "worker" => "ghcr.io/fluxerapp/fluxer-api:v1".into(),
        "gateway" => "ghcr.io/fluxerapp/fluxer-gateway:v1".into(),
        "media-proxy" => "ghcr.io/fluxerapp/fluxer-media-proxy:v1".into(),
        "push" => "ghcr.io/fluxerapp/fluxer-push:v1".into(),
        "static-proxy" => "ghcr.io/fluxerapp/fluxer-static:v1".into(),
        "app-proxy" => "ghcr.io/fluxerapp/fluxer-app-proxy-self-hosted:v1".into(),
        "admin" => "ghcr.io/fluxerapp/fluxer-admin:v1".into(),
        "snowflakes" => "ghcr.io/fluxerapp/fluxer-snowflakes:v1".into(),
        "users" => "ghcr.io/fluxerapp/fluxer-users:v1".into(),
        "gifs" => "ghcr.io/fluxerapp/fluxer-gifs:v1".into(),
        "messages" => "ghcr.io/fluxerapp/fluxer-messages:v1".into(),
        "unfurl" => "ghcr.io/fluxerapp/fluxer-unfurl:v1".into(),
        "rust" => "ghcr.io/fluxerapp/fluxer-server:v1".into(),
        other => format!("ghcr.io/fluxerapp/fluxer-{other}:v1"),
    }
}

fn image_setting_key(service: &str) -> Option<(&'static str, &'static str)> {
    match service {
        "postgres" => Some(("images.postgres", "FLUXER_POSTGRES_IMAGE")),
        "valkey" => Some(("images.valkey", "FLUXER_VALKEY_IMAGE")),
        "nats" => Some(("images.nats", "FLUXER_NATS_IMAGE")),
        "meilisearch" => Some(("images.meilisearch", "FLUXER_MEILISEARCH_IMAGE")),
        "seaweedfs" => Some(("images.seaweedfs", "FLUXER_SEAWEEDFS_IMAGE")),
        "livekit" => Some(("images.livekit", "FLUXER_LIVEKIT_IMAGE")),
        "edge" => Some(("images.edge", "FLUXER_CADDY_IMAGE")),
        _ => None,
    }
}

fn resolve_service_image(
    service: &str,
    stack: &FluxerStack,
    bundle_images: &BTreeMap<String, String>,
) -> String {
    // Explicit operator image override from rexctl settings
    if let Some((named, raw)) = image_setting_key(service) {
        if let Some(v) = stack.settings.get(named).or_else(|| stack.settings.get(raw)) {
            if !v.trim().is_empty() {
                return v.trim().to_string();
            }
        }
    }
    // Release compose bundle pinned digest image
    if let Some(img) = bundle_images.get(service) {
        return maybe_rewrite_registry(img, stack.settings.get("images.registry"));
    }
    // Cached image from backup's compose files
    if let Some(img) = stack.image_overrides.get(service) {
        return maybe_rewrite_registry(img, stack.settings.get("images.registry"));
    }
    default_image(service)
}

fn maybe_rewrite_registry(img: &str, registry: Option<&String>) -> String {
    let Some(reg) = registry.map(|s| s.trim().trim_end_matches('/')).filter(|s| !s.is_empty()) else {
        return img.to_string();
    };
    if img.starts_with(&format!("{reg}/")) {
        return img.to_string();
    }
    let Some((name, digest)) = img.split_once('@') else {
        return img.to_string();
    };
    if !digest.starts_with("sha256:") {
        return img.to_string();
    }
    let stripped = match name.split_once('/') {
        Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => {
            rest.to_string()
        }
        Some(_) => name.to_string(),
        None => format!("library/{name}"),
    };
    format!("{reg}/{stripped}@{digest}")
}

/// One planned latrix app representing a Fluxer service.
#[derive(Debug, Clone)]
pub struct ServiceSpec {
    pub service: String,
    pub config: AppConfig,
    pub image: String,
    pub secrets: BTreeMap<String, String>,
    /// Deployment order tier: 1=infra, 2=rust, 3=core, 4=edge
    pub tier: u8,
    /// `(rexctl_volume_short_name, latrix_volume_name)` if this service owns a restorable volume.
    pub backup_volume: Option<(String, String)>,
}

fn split_env_and_secrets(all: BTreeMap<String, String>) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    let mut env = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    for (k, v) in all {
        if v.is_empty() {
            continue;
        }
        if is_secret_entry(&k, &v) {
            secrets.insert(k, v);
        } else {
            env.insert(k, v);
        }
    }
    (env, secrets)
}

fn get_or<'a>(env: &'a BTreeMap<String, String>, key: &str, default: &'a str) -> String {
    env.get(key)
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(default)
        .to_string()
}

fn mem_limit(env: &BTreeMap<String, String>, key: &str, default: &str) -> String {
    let raw = get_or(env, key, default);
    // Normalize lowercase "mb"/"gb" from compose (e.g. "2560mb", "5gb") to valid latrix size.
    let upper = raw.trim().to_ascii_uppercase();
    if util::parse_size_mb(&upper).is_ok() {
        upper
    } else {
        default.to_string()
    }
}

/// Build the shared Fluxer application environment (matching `x-fluxer-env` in docker-compose.yml).
fn build_common_fluxer_env(stack: &FluxerStack, eff: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let domain = &stack.domain;
    let origin = get_or(eff, "FLUXER_PUBLIC_ORIGIN", &format!("https://{domain}"));
    let scheme = get_or(eff, "FLUXER_PUBLIC_SCHEME", "https");
    let pub_port = get_or(eff, "FLUXER_PUBLIC_PORT", "443");
    let admin_base = get_or(eff, "FLUXER_ADMIN_BASE_PATH", "/admin");

    let mut m = BTreeMap::new();
    // Pass through any explicit FLUXER_* settings/secrets first so defaults fill in blanks.
    for (k, v) in eff {
        if (k.starts_with("FLUXER_")
            || matches!(
                k.as_str(),
                "LOG_LEVEL" | "RUST_LOG" | "HTTP_PROXY" | "HTTPS_PROXY" | "NO_PROXY"
            ))
            && !v.is_empty()
        {
            m.insert(k.clone(), v.clone());
        }
    }

    let no_proxy_base = "localhost,127.0.0.1,::1,edge,postgres,valkey,nats,meilisearch,seaweedfs,livekit,api,worker,gateway,media-proxy,push,static-proxy,app-proxy,snowflakes,users,gifs,messages,unfurl,admin,rust";
    let no_proxy = match eff.get("NO_PROXY").filter(|s| !s.is_empty()) {
        Some(extra) => format!("{no_proxy_base},{extra}"),
        None => no_proxy_base.into(),
    };

    m.insert("FLUXER_ENV".into(), "production".into());
    m.insert("FLUXER_SELF_HOSTED".into(), "true".into());
    m.insert("FLUXER_DATABASE_BACKEND".into(), "postgres".into());
    m.entry("FLUXER_POSTGRES_HOST".into()).or_insert_with(|| "postgres".into());
    m.entry("FLUXER_POSTGRES_DATABASE".into()).or_insert_with(|| "fluxer".into());
    m.entry("FLUXER_POSTGRES_USERNAME".into()).or_insert_with(|| "fluxer".into());
    if let Some(pw) = eff.get("POSTGRES_PASSWORD").or_else(|| eff.get("FLUXER_POSTGRES_PASSWORD")) {
        m.insert("FLUXER_POSTGRES_PASSWORD".into(), pw.clone());
    }

    m.insert("NO_PROXY".into(), no_proxy.clone());
    m.insert("no_proxy".into(), no_proxy);
    if let Some(p) = eff.get("HTTP_PROXY").filter(|s| !s.is_empty()) {
        m.insert("http_proxy".into(), p.clone());
    }
    if let Some(p) = eff.get("HTTPS_PROXY").filter(|s| !s.is_empty()) {
        m.insert("https_proxy".into(), p.clone());
    }

    m.insert("FLUXER_BASE_DOMAIN".into(), domain.clone());
    m.insert("FLUXER_PUBLIC_SCHEME".into(), scheme);
    m.insert("FLUXER_PUBLIC_PORT".into(), pub_port);
    m.insert("FLUXER_PUBLIC_ORIGIN".into(), origin.clone());
    m.entry("FLUXER_TRUST_CLIENT_IP_HEADER".into()).or_insert_with(|| "true".into());

    m.entry("FLUXER_APP_ENDPOINT".into()).or_insert_with(|| origin.clone());
    let media_ep = m
        .get("FLUXER_MEDIA_ENDPOINT")
        .cloned()
        .unwrap_or_else(|| format!("{origin}/media"));
    m.insert("FLUXER_MEDIA_ENDPOINT".into(), media_ep.clone());
    m.entry("FLUXER_MEDIA_PROXY_PUBLIC_ENDPOINT".into()).or_insert_with(|| media_ep.clone());
    m.entry("FLUXER_MEDIA_PROXY_UPLOAD_RELAY_ENDPOINT".into()).or_insert(media_ep);
    m.entry("FLUXER_ADMIN_ENDPOINT".into())
        .or_insert_with(|| format!("{origin}{admin_base}"));
    m.entry("FLUXER_MARKETING_ENDPOINT".into()).or_insert_with(|| origin.clone());

    if stack.kv_postgres {
        m.insert("FLUXER_KV_MODE".into(), "postgres".into());
    } else {
        m.entry("FLUXER_KV_URL".into())
            .or_insert_with(|| "redis://valkey:6379/0".into());
    }
    let nats_url = get_or(eff, "FLUXER_NATS_URL", "nats://nats:4222");
    m.insert("FLUXER_NATS_URL".into(), nats_url.clone());
    m.entry("FLUXER_NATS_JETSTREAM_URL".into()).or_insert_with(|| nats_url.clone());
    m.entry("FLUXER_SVC_NATS_URL".into()).or_insert(nats_url);
    m.entry("FLUXER_SVC_SHARD_COUNT".into()).or_insert_with(|| "1".into());

    m.entry("FLUXER_SEARCH_ENGINE".into()).or_insert_with(|| "meilisearch".into());
    m.entry("FLUXER_SEARCH_URL".into())
        .or_insert_with(|| "http://meilisearch:7700".into());
    if let Some(mk) = eff.get("MEILI_MASTER_KEY").or_else(|| eff.get("FLUXER_SEARCH_API_KEY")) {
        m.insert("FLUXER_SEARCH_API_KEY".into(), mk.clone());
    }

    // Object storage: Cloudflare R2 / external S3 vs bundled SeaweedFS
    if !stack.external_object_store {
        m.entry("FLUXER_S3_ENDPOINT".into())
            .or_insert_with(|| "http://seaweedfs:8333".into());
    }
    if let Some(ep) = m.get("FLUXER_S3_ENDPOINT").cloned() {
        m.entry("FLUXER_S3_PUBLIC_ENDPOINT".into()).or_insert(ep);
    }
    m.entry("FLUXER_S3_REGION".into()).or_insert_with(|| "us-east-1".into());
    m.entry("FLUXER_S3_FORCE_PATH_STYLE".into()).or_insert_with(|| "true".into());
    m.entry("FLUXER_S3_BUCKET_CDN".into()).or_insert_with(|| "fluxer".into());
    m.entry("FLUXER_S3_BUCKET_UPLOADS".into()).or_insert_with(|| "fluxer-uploads".into());
    m.entry("FLUXER_S3_BUCKET_REPORTS".into()).or_insert_with(|| "fluxer-reports".into());
    m.entry("FLUXER_S3_BUCKET_HARVESTS".into()).or_insert_with(|| "fluxer-harvests".into());
    m.entry("FLUXER_API_PRESIGNED_HARVEST_DOWNLOADS_ENABLED".into())
        .or_insert_with(|| "false".into());
    if let Some(ak) = eff.get("FLUXER_S3_ACCESS_KEY_ID").or_else(|| eff.get("FLUXER_S3_ACCESS_KEY")) {
        m.insert("FLUXER_S3_ACCESS_KEY_ID".into(), ak.clone());
    }
    if let Some(sk) = eff.get("FLUXER_S3_SECRET_ACCESS_KEY").or_else(|| eff.get("FLUXER_S3_SECRET_KEY")) {
        m.insert("FLUXER_S3_SECRET_ACCESS_KEY".into(), sk.clone());
    }

    // Voice / LiveKit
    m.entry("FLUXER_LIVEKIT_ENABLED".into()).or_insert_with(|| "true".into());
    m.insert(
        "FLUXER_LIVEKIT_BUNDLED".into(),
        if stack.bundled_voice { "true" } else { "false" }.into(),
    );
    m.entry("FLUXER_LIVEKIT_INTERNAL_URL".into())
        .or_insert_with(|| "http://livekit:7880".into());
    m.entry("FLUXER_LIVEKIT_URL".into())
        .or_insert_with(|| format!("{origin}/livekit"));
    m.entry("FLUXER_LIVEKIT_DEFAULT_REGION".into()).or_insert_with(|| {
        r#"{"id":"default","name":"Default","emoji":"🌍","latitude":0,"longitude":0}"#.into()
    });
    m.entry("FLUXER_LIVEKIT_TURN_SERVERS".into()).or_insert_with(|| "[]".into());
    if let Some(k) = eff.get("LIVEKIT_API_KEY").or_else(|| eff.get("FLUXER_LIVEKIT_API_KEY")) {
        m.insert("FLUXER_LIVEKIT_API_KEY".into(), k.clone());
    }
    if let Some(s) = eff.get("LIVEKIT_API_SECRET").or_else(|| eff.get("FLUXER_LIVEKIT_API_SECRET")) {
        m.insert("FLUXER_LIVEKIT_API_SECRET".into(), s.clone());
    }

    // Passkeys, VAPID, email defaults, internal endpoints
    m.entry("FLUXER_EMAIL_FROM_EMAIL".into())
        .or_insert_with(|| format!("noreply@{domain}"));
    m.entry("FLUXER_VAPID_EMAIL".into())
        .or_insert_with(|| format!("admin@{domain}"));
    m.entry("FLUXER_PASSKEY_RP_ID".into()).or_insert_with(|| domain.clone());
    m.entry("FLUXER_PASSKEY_ADDITIONAL_ALLOWED_ORIGINS".into())
        .or_insert_with(|| origin);
    m.insert("FLUXER_INTERNAL_API_ENDPOINT".into(), "http://api:8080".into());
    m.insert(
        "FLUXER_INTERNAL_MEDIA_PROXY_ENDPOINT".into(),
        "http://media-proxy:8080".into(),
    );

    m
}

/// Build the portable Caddy startup command that materializes `Caddyfile` and
/// any `caddy.d/*.caddy` drop-ins inside the container before `exec caddy run`.
pub fn caddy_bootstrap_command(caddyfile: &str, dropins: &BTreeMap<String, String>) -> Command {
    let b64 = base64::engine::general_purpose::STANDARD;
    let cf_b64 = b64.encode(caddyfile.as_bytes());
    let mut script = format!(
        "mkdir -p /etc/caddy/conf.d/sites && printf '%s' '{cf_b64}' | base64 -d > /etc/caddy/Caddyfile"
    );
    for (rel, body) in dropins {
        let Ok(safe) = safe_rel_path(rel) else { continue };
        let clean = canonical_arc_path(&safe);
        if clean.is_empty() || clean.chars().any(|c| c.is_control()) {
            continue;
        }
        let target = format!("/etc/caddy/conf.d/{clean}");
        let target_q = util::shell_quote(&target);
        if let Some((parent, _)) = target.rsplit_once('/') {
            let parent_q = util::shell_quote(parent);
            script.push_str(&format!(" && mkdir -p {parent_q}"));
        }
        let encoded = b64.encode(body.as_bytes());
        script.push_str(&format!(" && printf '%s' '{encoded}' | base64 -d > {target_q}"));
    }
    script.push_str(" && exec caddy run --config /etc/caddy/Caddyfile --adapter caddyfile");
    Command::Shell(script)
}

fn validate_s3_bucket(name: &str) -> Result<&str> {
    let b = name.trim();
    if b.len() < 3
        || b.len() > 63
        || !b.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'.'))
        || !b.as_bytes()[0].is_ascii_alphanumeric()
        || !b.as_bytes()[b.len() - 1].is_ascii_alphanumeric()
        || b.contains("..")
    {
        bail!("invalid S3 bucket name '{name}'");
    }
    Ok(b)
}

fn validate_seaweed_ttl(ttl: &str) -> Result<&str> {
    let t = ttl.trim();
    if t == "off" {
        return Ok(t);
    }
    let Some(unit) = t.chars().last() else {
        bail!("invalid SeaweedFS TTL '{ttl}'");
    };
    let num = &t[..t.len() - unit.len_utf8()];
    if !matches!(unit, 'm' | 'h' | 'd' | 'w' | 'M' | 'y')
        || num.is_empty()
        || !num.bytes().all(|b| b.is_ascii_digit())
    {
        bail!("invalid SeaweedFS TTL '{ttl}' (expected 'off' or <number>[m|h|d|w|M|y])");
    }
    Ok(t)
}

fn validate_nats_size(val: &str, name: &str) -> Result<String> {
    let v = val.trim();
    if v.is_empty()
        || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
        || !v.as_bytes()[0].is_ascii_digit()
    {
        bail!("invalid {name} '{val}'");
    }
    Ok(v.to_string())
}

/// One-shot SeaweedFS init script (executed inside the running `seaweedfs` container).
pub fn seaweedfs_init_script(eff: &BTreeMap<String, String>) -> Result<String> {
    let ak = eff
        .get("FLUXER_S3_ACCESS_KEY")
        .or_else(|| eff.get("FLUXER_S3_ACCESS_KEY_ID"))
        .cloned()
        .unwrap_or_default();
    let sk = eff
        .get("FLUXER_S3_SECRET_KEY")
        .or_else(|| eff.get("FLUXER_S3_SECRET_ACCESS_KEY"))
        .cloned()
        .unwrap_or_default();
    if ak.chars().any(|c| c.is_control() || c.is_whitespace())
        || sk.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        bail!("SeaweedFS S3 credentials must not contain whitespace or control characters");
    }
    let b_cdn = get_or(eff, "FLUXER_S3_BUCKET_CDN", "fluxer");
    let b_up = get_or(eff, "FLUXER_S3_BUCKET_UPLOADS", "fluxer-uploads");
    let b_rep = get_or(eff, "FLUXER_S3_BUCKET_REPORTS", "fluxer-reports");
    let b_har = get_or(eff, "FLUXER_S3_BUCKET_HARVESTS", "fluxer-harvests");
    let b_cdn = validate_s3_bucket(&b_cdn)?;
    let b_up = validate_s3_bucket(&b_up)?;
    let b_rep = validate_s3_bucket(&b_rep)?;
    let b_har = validate_s3_bucket(&b_har)?;
    let ttl_raw = get_or(eff, "FLUXER_SEAWEEDFS_UPLOADS_TTL", "1d");
    let ttl = validate_seaweed_ttl(&ttl_raw)?;

    let cfg_line = format!(
        "s3.configure -user=fluxer -access_key={} -secret_key={} -actions=Admin,Read,Write,List,Tagging -apply",
        ak, sk
    );
    let cfg_line_q = util::shell_quote(&cfg_line);
    Ok(format!(
        r#"set -e
buckets='{b_cdn} {b_up} {b_rep} {b_har}'
for attempt in $(seq 1 30); do
  listed=$(printf '%s\n' 's3.bucket.list' | timeout 10 weed shell -master=127.0.0.1:9333 2>&1 || true)
  missing=""
  for b in $buckets; do
    printf '%s\n' "$listed" | awk -v b="$b" '$1 == b {{ found=1 }} END {{ exit !found }}' || missing="${{missing:+$missing }}$b"
  done
  if [ -z "$missing" ]; then
    printf '%s\n' {cfg_line_q} | timeout 10 weed shell -master=127.0.0.1:9333 >/dev/null
    if [ '{ttl}' = 'off' ]; then
      printf '%s\n' 'fs.configure -locationPrefix=/buckets/{b_up}/ -delete -apply' | timeout 10 weed shell -master=127.0.0.1:9333 >/dev/null
    else
      printf '%s\n' 'fs.configure -locationPrefix=/buckets/{b_up}/ -ttl={ttl} -apply' | timeout 10 weed shell -master=127.0.0.1:9333 >/dev/null
    fi
    echo "buckets ready"
    exit 0
  fi
  for b in $missing; do
    printf 's3.bucket.create -name %s\n' "$b" | timeout 10 weed shell -master=127.0.0.1:9333 >/dev/null 2>&1 || true
  done
  sleep 2
done
echo "seaweedfs init timed out" >&2
exit 1"#
    ))
}

/// Plan every latrix app needed to run this `FluxerStack`.
pub fn plan_stack(
    stack: &FluxerStack,
    bundle_images: &BTreeMap<String, String>,
) -> Result<Vec<ServiceSpec>> {
    let eff = effective_env(stack);
    let common = build_common_fluxer_env(stack, &eff);
    let group = &stack.project;
    let copies = stack.copies.max(1);
    let regions: Vec<String> = stack.region.iter().cloned().collect();

    let app_name = |svc: &str| format!("{group}-{svc}");
    let base_cfg = |svc: &str, mem: &str, cpu: f64| -> AppConfig {
        AppConfig {
            app: app_name(svc),
            group: Some(group.clone()),
            service: Some(svc.to_string()),
            regions: regions.clone(),
            scale: ScaleConfig {
                count: Some(1),
                min: None,
                max: None,
                cpu,
                memory: mem.to_string(),
            },
            deploy: DeployConfig {
                strategy: "rolling".into(),
                health_timeout: "180s".into(),
                stop_timeout: "30s".into(),
            },
            ..Default::default()
        }
    };

    let mut specs = vec![];

    // -----------------------------------------------------------------------
    // Tier 1: Stateful infrastructure & voice
    // -----------------------------------------------------------------------

    // 1. postgres
    {
        let mut cfg = base_cfg("postgres", &mem_limit(&eff, "FLUXER_POSTGRES_MEMORY_LIMIT", "2GB"), 1.0);
        cfg.shm_size = Some(mem_limit(&eff, "FLUXER_POSTGRES_SHM_SIZE", "1GB"));
        cfg.ports.push(PortConfig { port: 5432, public: false, public_port: None, protocol: "tcp".into() });
        cfg.volumes.push(VolumeConfig {
            name: "postgres-data".into(),
            path: "/var/lib/postgresql/data".into(),
            copies,
            sync: "30s".into(),
            pre_sync: None,
            size: Some("20GB".into()),
        });
        let pg_args = vec![
            "postgres".into(),
            "-c".into(), format!("max_connections={}", get_or(&eff, "FLUXER_POSTGRES_SERVER_MAX_CONNECTIONS", "150")),
            "-c".into(), format!("shared_buffers={}", get_or(&eff, "FLUXER_POSTGRES_SHARED_BUFFERS", "256MB")),
            "-c".into(), format!("effective_cache_size={}", get_or(&eff, "FLUXER_POSTGRES_EFFECTIVE_CACHE_SIZE", "1GB")),
            "-c".into(), format!("work_mem={}", get_or(&eff, "FLUXER_POSTGRES_WORK_MEM", "8MB")),
            "-c".into(), format!("maintenance_work_mem={}", get_or(&eff, "FLUXER_POSTGRES_MAINTENANCE_WORK_MEM", "128MB")),
            "-c".into(), format!("random_page_cost={}", get_or(&eff, "FLUXER_POSTGRES_RANDOM_PAGE_COST", "1.1")),
            "-c".into(), format!("jit={}", get_or(&eff, "FLUXER_POSTGRES_JIT", "off")),
            "-c".into(), format!("wal_compression={}", get_or(&eff, "FLUXER_POSTGRES_WAL_COMPRESSION", "zstd")),
            "-c".into(), format!("shared_preload_libraries={}", get_or(&eff, "FLUXER_POSTGRES_SHARED_PRELOAD_LIBRARIES", "pg_stat_statements")),
        ];
        cfg.command = Some(Command::Exec(pg_args));
        let mut raw_env = BTreeMap::new();
        raw_env.insert("POSTGRES_DB".into(), get_or(&eff, "FLUXER_POSTGRES_DATABASE", "fluxer"));
        raw_env.insert("POSTGRES_USER".into(), get_or(&eff, "FLUXER_POSTGRES_USERNAME", "fluxer"));
        if let Some(pw) = eff.get("POSTGRES_PASSWORD").or_else(|| eff.get("FLUXER_POSTGRES_PASSWORD")) {
            raw_env.insert("POSTGRES_PASSWORD".into(), pw.clone());
        }
        let (env, secrets) = split_env_and_secrets(raw_env);
        cfg.env = env;
        let image = resolve_service_image("postgres", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "postgres".into(),
            config: cfg,
            image,
            secrets,
            tier: 1,
            backup_volume: None, // Restored via pg_restore
        });
    }

    // 2. valkey (unless kv.mode == postgres)
    if !stack.kv_postgres {
        let mut cfg = base_cfg("valkey", &mem_limit(&eff, "FLUXER_VALKEY_MEMORY_LIMIT", "256MB"), 0.25);
        cfg.ports.push(PortConfig { port: 6379, public: false, public_port: None, protocol: "tcp".into() });
        cfg.volumes.push(VolumeConfig {
            name: "valkey-data".into(),
            path: "/data".into(),
            copies,
            sync: "30s".into(),
            pre_sync: None,
            size: Some("2GB".into()),
        });
        cfg.command = Some(Command::Exec(vec![
            "valkey-server".into(),
            "--appendonly".into(), "yes".into(),
            "--appendfsync".into(), get_or(&eff, "FLUXER_VALKEY_APPENDFSYNC", "everysec"),
            "--dir".into(), "/data".into(),
            "--save".into(), get_or(&eff, "FLUXER_VALKEY_SAVE", ""),
            "--maxmemory".into(), get_or(&eff, "FLUXER_VALKEY_MAXMEMORY", "192mb"),
            "--maxmemory-policy".into(), get_or(&eff, "FLUXER_VALKEY_MAXMEMORY_POLICY", "noeviction"),
        ]));
        let image = resolve_service_image("valkey", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "valkey".into(),
            config: cfg,
            image,
            secrets: BTreeMap::new(),
            tier: 1,
            backup_volume: Some(("valkey-data".into(), "valkey-data".into())),
        });
    }

    // 3. nats
    {
        let mut cfg = base_cfg("nats", &mem_limit(&eff, "FLUXER_NATS_MEMORY_LIMIT", "256MB"), 0.25);
        cfg.ports.push(PortConfig { port: 4222, public: false, public_port: None, protocol: "tcp".into() });
        cfg.ports.push(PortConfig { port: 8222, public: false, public_port: None, protocol: "tcp".into() });
        cfg.volumes.push(VolumeConfig {
            name: "nats-data".into(),
            path: "/data".into(),
            copies,
            sync: "30s".into(),
            pre_sync: None,
            size: Some("10GB".into()),
        });
        cfg.env.insert("GOMEMLIMIT".into(), get_or(&eff, "FLUXER_NATS_GOMEMLIMIT", "200MiB"));
        cfg.env.insert(
            "FLUXER_NATS_MAX_MEMORY_STORE".into(),
            validate_nats_size(&get_or(&eff, "FLUXER_NATS_MAX_MEMORY_STORE", "64MB"), "FLUXER_NATS_MAX_MEMORY_STORE")?,
        );
        cfg.env.insert(
            "FLUXER_NATS_MAX_FILE_STORE".into(),
            validate_nats_size(&get_or(&eff, "FLUXER_NATS_MAX_FILE_STORE", "10GB"), "FLUXER_NATS_MAX_FILE_STORE")?,
        );
        cfg.command = Some(Command::Shell(
            r#"printf 'http_port: 8222\njetstream {\n  store_dir: /data\n  max_memory_store: %s\n  max_file_store: %s\n}\n' "$FLUXER_NATS_MAX_MEMORY_STORE" "$FLUXER_NATS_MAX_FILE_STORE" > /tmp/nats.conf && exec nats-server -c /tmp/nats.conf"#.into(),
        ));
        let image = resolve_service_image("nats", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "nats".into(),
            config: cfg,
            image,
            secrets: BTreeMap::new(),
            tier: 1,
            backup_volume: Some(("nats-data".into(), "nats-data".into())),
        });
    }

    // 4. meilisearch
    {
        let mut cfg = base_cfg("meilisearch", &mem_limit(&eff, "FLUXER_MEILISEARCH_MEMORY_LIMIT", "1536MB"), 0.5);
        cfg.ports.push(PortConfig { port: 7700, public: false, public_port: None, protocol: "tcp".into() });
        cfg.volumes.push(VolumeConfig {
            name: "meilisearch-data".into(),
            path: "/meili_data".into(),
            copies,
            sync: "60s".into(),
            pre_sync: None,
            size: Some("10GB".into()),
        });
        let mut raw_env = BTreeMap::new();
        raw_env.insert("MEILI_ENV".into(), get_or(&eff, "FLUXER_MEILISEARCH_ENV", "production"));
        raw_env.insert("MEILI_NO_ANALYTICS".into(), get_or(&eff, "FLUXER_MEILISEARCH_NO_ANALYTICS", "true"));
        raw_env.insert("MEILI_UPGRADE_DB".into(), "true".into());
        raw_env.insert("MEILI_MAX_INDEXING_MEMORY".into(), get_or(&eff, "FLUXER_MEILISEARCH_MAX_INDEXING_MEMORY", "256mb"));
        raw_env.insert("MEILI_MAX_INDEXING_THREADS".into(), get_or(&eff, "FLUXER_MEILISEARCH_MAX_INDEXING_THREADS", "2"));
        raw_env.insert("MEILI_LOG_LEVEL".into(), get_or(&eff, "FLUXER_MEILISEARCH_LOG_LEVEL", "WARN"));
        if let Some(mk) = eff.get("MEILI_MASTER_KEY").or_else(|| eff.get("FLUXER_SEARCH_API_KEY")) {
            raw_env.insert("MEILI_MASTER_KEY".into(), mk.clone());
        }
        let (env, secrets) = split_env_and_secrets(raw_env);
        cfg.env = env;
        let image = resolve_service_image("meilisearch", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "meilisearch".into(),
            config: cfg,
            image,
            secrets,
            tier: 1,
            backup_volume: Some(("meilisearch-data".into(), "meilisearch-data".into())),
        });
    }

    // 5. seaweedfs (only when using bundled object storage — skipped for Cloudflare R2 / external S3)
    let is_filesystem_storage = eff
        .get("FLUXER_STORAGE_BACKEND")
        .map(|s| s.eq_ignore_ascii_case("filesystem"))
        .unwrap_or(false);
    if !stack.external_object_store && !is_filesystem_storage {
        let mut cfg = base_cfg("seaweedfs", &mem_limit(&eff, "FLUXER_SEAWEEDFS_MEMORY_LIMIT", "1GB"), 0.5);
        cfg.ports.push(PortConfig { port: 8333, public: false, public_port: None, protocol: "tcp".into() });
        cfg.ports.push(PortConfig { port: 9333, public: false, public_port: None, protocol: "tcp".into() });
        cfg.volumes.push(VolumeConfig {
            name: "seaweedfs-data".into(),
            path: "/data".into(),
            copies,
            sync: "60s".into(),
            pre_sync: None,
            size: Some("50GB".into()),
        });
        cfg.env.insert("GOMEMLIMIT".into(), get_or(&eff, "FLUXER_SEAWEEDFS_GOMEMLIMIT", "768MiB"));
        cfg.env.insert("WEED_MASTER_VOLUME_GROWTH_COPY_1".into(), get_or(&eff, "FLUXER_SEAWEEDFS_VOLUME_GROWTH", "1"));
        cfg.env.insert("WEED_FILER_OPTIONS_MAX_FILE_NAME_LENGTH".into(), "1024".into());
        cfg.command = Some(Command::Exec(vec![
            "server".into(),
            "-s3".into(),
            "-s3.iam=false".into(),
            "-dir=/data".into(),
            format!("-master.telemetry={}", get_or(&eff, "FLUXER_SEAWEEDFS_TELEMETRY", "false")),
            format!("-master.volumeSizeLimitMB={}", get_or(&eff, "FLUXER_SEAWEEDFS_VOLUME_SIZE_LIMIT_MB", "1024")),
            format!("-master.garbageThreshold={}", get_or(&eff, "FLUXER_SEAWEEDFS_GARBAGE_THRESHOLD", "0.1")),
            format!("-volume.max={}", get_or(&eff, "FLUXER_SEAWEEDFS_VOLUME_MAX", "10000")),
            format!("-s3.concurrentFileUploadLimit={}", get_or(&eff, "FLUXER_SEAWEEDFS_S3_CONCURRENT_UPLOADS", "5")),
        ]));
        let image = resolve_service_image("seaweedfs", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "seaweedfs".into(),
            config: cfg,
            image,
            secrets: BTreeMap::new(),
            tier: 1,
            backup_volume: Some(("seaweedfs-data".into(), "seaweedfs-data".into())),
        });
    }

    // 6. livekit (bundled voice)
    if stack.bundled_voice {
        let tcp_port: u16 = get_or(&eff, "FLUXER_LIVEKIT_TCP_PORT", "7881")
            .parse()
            .context("invalid FLUXER_LIVEKIT_TCP_PORT")?;
        let udp_port: u16 = get_or(&eff, "FLUXER_LIVEKIT_UDP_PORT", "7882")
            .parse()
            .context("invalid FLUXER_LIVEKIT_UDP_PORT")?;
        if tcp_port == 0 || udp_port == 0 || tcp_port == 7880 {
            bail!("invalid LiveKit voice ports (tcp={tcp_port}, udp={udp_port})");
        }
        let use_ext = !matches!(
            get_or(&eff, "FLUXER_LIVEKIT_USE_EXTERNAL_IP", "true").trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "no" | "off"
        );
        let node_ip = eff.get("FLUXER_LIVEKIT_NODE_IP").cloned().unwrap_or_default();
        let stun1 = get_or(&eff, "FLUXER_LIVEKIT_STUN_PRIMARY", "stun.l.google.com:19302");
        let stun2 = get_or(&eff, "FLUXER_LIVEKIT_STUN_SECONDARY", "stun1.l.google.com:19302");
        let turn_raw = get_or(&eff, "FLUXER_LIVEKIT_TURN_SERVERS", "[]");
        let turn_val: serde_yaml::Value = serde_yaml::from_str(&turn_raw)
            .unwrap_or_else(|_| serde_yaml::Value::Sequence(vec![]));
        let lk_key = eff.get("LIVEKIT_API_KEY").or_else(|| eff.get("FLUXER_LIVEKIT_API_KEY")).cloned().unwrap_or_default();
        let lk_sec = eff.get("LIVEKIT_API_SECRET").or_else(|| eff.get("FLUXER_LIVEKIT_API_SECRET")).cloned().unwrap_or_default();
        let lk_log = get_or(&eff, "FLUXER_LIVEKIT_LOG_LEVEL", "info");

        let mut cfg = base_cfg("livekit", &mem_limit(&eff, "FLUXER_LIVEKIT_MEMORY_LIMIT", "512MB"), 0.5);
        cfg.ports.push(PortConfig { port: 7880, public: false, public_port: None, protocol: "tcp".into() });
        cfg.ports.push(PortConfig { port: tcp_port, public: true, public_port: None, protocol: "tcp".into() });
        cfg.ports.push(PortConfig { port: udp_port, public: true, public_port: None, protocol: "udp".into() });

        let mut rtc_map = serde_yaml::Mapping::new();
        rtc_map.insert("tcp_port".into(), serde_yaml::Value::Number(tcp_port.into()));
        rtc_map.insert("udp_port".into(), serde_yaml::Value::Number(udp_port.into()));
        rtc_map.insert("use_external_ip".into(), serde_yaml::Value::Bool(use_ext));
        rtc_map.insert("node_ip".into(), serde_yaml::Value::String(node_ip));
        rtc_map.insert(
            "stun_servers".into(),
            serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String(stun1),
                serde_yaml::Value::String(stun2),
            ]),
        );
        rtc_map.insert("turn_servers".into(), turn_val);

        let mut webhook_map = serde_yaml::Mapping::new();
        webhook_map.insert("api_key".into(), serde_yaml::Value::String(lk_key.clone()));
        webhook_map.insert(
            "urls".into(),
            serde_yaml::Value::Sequence(vec![serde_yaml::Value::String(
                "http://api:8080/webhooks/livekit".into(),
            )]),
        );

        let mut lk_map = serde_yaml::Mapping::new();
        lk_map.insert("port".into(), serde_yaml::Value::Number(7880u16.into()));
        lk_map.insert("log_level".into(), serde_yaml::Value::String(lk_log));
        lk_map.insert("rtc".into(), serde_yaml::Value::Mapping(rtc_map));
        lk_map.insert("webhook".into(), serde_yaml::Value::Mapping(webhook_map));
        let lk_config = serde_yaml::to_string(&serde_yaml::Value::Mapping(lk_map))
            .context("serializing LIVEKIT_CONFIG")?;

        let mut raw_env = BTreeMap::new();
        raw_env.insert("GOMEMLIMIT".into(), get_or(&eff, "FLUXER_LIVEKIT_GOMEMLIMIT", "435MiB"));
        let lk_keys = if !lk_key.is_empty() && !lk_sec.is_empty() {
            format!("{lk_key}: {lk_sec}")
        } else {
            eff.get("LIVEKIT_KEYS").cloned().unwrap_or_default()
        };
        if !lk_keys.is_empty() {
            raw_env.insert("LIVEKIT_KEYS".into(), lk_keys);
        }
        raw_env.insert("LIVEKIT_CONFIG".into(), lk_config);
        let (env, secrets) = split_env_and_secrets(raw_env);
        cfg.env = env;
        let image = resolve_service_image("livekit", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "livekit".into(),
            config: cfg,
            image,
            secrets,
            tier: 1,
            backup_volume: None,
        });
    }

    // -----------------------------------------------------------------------
    // Tier 2: Rust microservices (unified `rust` OR per-service)
    // -----------------------------------------------------------------------
    let rust_common = |extra: &[(&str, String)]| -> (BTreeMap<String, String>, BTreeMap<String, String>) {
        let mut m = common.clone();
        m.insert("TOKIO_WORKER_THREADS".into(), get_or(&eff, "FLUXER_TOKIO_WORKER_THREADS", "2"));
        m.insert("MALLOC_ARENA_MAX".into(), get_or(&eff, "FLUXER_MALLOC_ARENA_MAX", "2"));
        for (k, v) in extra {
            if !v.is_empty() {
                m.insert((*k).to_string(), v.clone());
            }
        }
        split_env_and_secrets(m)
    };

    if stack.rust_single {
        let mut cfg = base_cfg("rust", &mem_limit(&eff, "FLUXER_RUST_MEMORY_LIMIT", "1GB"), 0.5);
        cfg.aliases = vec!["app-proxy".into(), "admin".into()];
        cfg.ports.push(PortConfig { port: 8080, public: false, public_port: None, protocol: "tcp".into() });
        cfg.ports.push(PortConfig { port: 18083, public: false, public_port: None, protocol: "tcp".into() });
        cfg.ports.push(PortConfig { port: 8090, public: false, public_port: None, protocol: "tcp".into() });
        let origin = get_or(&eff, "FLUXER_PUBLIC_ORIGIN", &format!("https://{}", stack.domain));
        let (env, secrets) = rust_common(&[
            ("FLUXER_RUST_PROCESS", "single".into()),
            ("FLUXER_SERVER_SERVICES", "snowflakes,users,messages,gifs,unfurl,push,app-proxy,admin".into()),
            ("FLUXER_APP_PROXY_PORT", "8080".into()),
            ("FLUXER_ADMIN_PORT", "18083".into()),
            ("FLUXER_ADMIN_BASE_PATH", get_or(&eff, "FLUXER_ADMIN_BASE_PATH", "/admin")),
            ("FLUXER_STATIC_CDN_ENDPOINT", get_or(&eff, "FLUXER_STATIC_CDN_ENDPOINT", &origin)),
            ("DISCOVERY_UPSTREAM_URL", "http://edge:8088/.well-known/fluxer".into()),
            ("DISCOVERY_REFRESH_INTERVAL_MS", get_or(&eff, "DISCOVERY_REFRESH_INTERVAL_MS", "5000")),
            ("FLUXER_MEDIA_PROXY_ENDPOINT", "http://media-proxy:8080".into()),
            ("FLUXER_API_ENDPOINT", "http://api:8080".into()),
        ]);
        cfg.env = env;
        let image = resolve_service_image("rust", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "rust".into(),
            config: cfg,
            image,
            secrets,
            tier: 2,
            backup_volume: None,
        });
    } else {
        for (svc, mem_key, extras) in [
            ("snowflakes", "FLUXER_SNOWFLAKES_MEMORY_LIMIT", vec![("FLUXER_SNOWFLAKES_WORKER_GUARD", "true".into())]),
            ("users", "FLUXER_USERS_MEMORY_LIMIT", vec![("FLUXER_POSTGRES_MAX_CONNECTIONS", get_or(&eff, "FLUXER_USERS_POSTGRES_MAX_CONNECTIONS", "20"))]),
            ("gifs", "FLUXER_GIFS_MEMORY_LIMIT", vec![("FLUXER_GIFS_SHARD_CACHE_MAX_BYTES", get_or(&eff, "FLUXER_GIFS_SHARD_CACHE_MAX_BYTES", "134217728"))]),
            ("messages", "FLUXER_MESSAGES_MEMORY_LIMIT", vec![("FLUXER_POSTGRES_MAX_CONNECTIONS", get_or(&eff, "FLUXER_MESSAGES_POSTGRES_MAX_CONNECTIONS", "20"))]),
            ("unfurl", "FLUXER_UNFURL_MEMORY_LIMIT", vec![("FLUXER_MEDIA_PROXY_ENDPOINT", "http://media-proxy:8080".into())]),
        ] {
            let mut cfg = base_cfg(svc, &mem_limit(&eff, mem_key, "256MB"), 0.25);
            cfg.ports.push(PortConfig { port: 8090, public: false, public_port: None, protocol: "tcp".into() });
            let mut all_extras = vec![
                ("FLUXER_SVC_NAME", svc.to_string()),
                ("FLUXER_SVC_MODE", "combined".to_string()),
            ];
            all_extras.extend(extras);
            let (env, secrets) = rust_common(&all_extras);
            cfg.env = env;
            let image = resolve_service_image(svc, stack, bundle_images);
            cfg.build.image = Some(image.clone());
            cfg.validate()?;
            specs.push(ServiceSpec {
                service: svc.into(),
                config: cfg,
                image,
                secrets,
                tier: 2,
                backup_volume: None,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Tier 3: Core Fluxer services
    // -----------------------------------------------------------------------

    // api
    {
        let mut cfg = base_cfg("api", &mem_limit(&eff, "FLUXER_API_MEMORY_LIMIT", "1536MB"), 0.5);
        cfg.ports.push(PortConfig { port: 8080, public: false, public_port: None, protocol: "tcp".into() });
        let mut m = common.clone();
        m.insert("FLUXER_API_PORT".into(), "8080".into());
        m.insert("FLUXER_POSTGRES_MAX_CONNECTIONS".into(), get_or(&eff, "FLUXER_API_POSTGRES_MAX_CONNECTIONS", "25"));
        m.insert("FLUXER_API_PRESIGNED_ATTACHMENT_UPLOADS_ENABLED".into(), get_or(&eff, "FLUXER_API_PRESIGNED_ATTACHMENT_UPLOADS_ENABLED", "true"));
        m.insert("FLUXER_API_EMBEDDED_WORKER".into(), get_or(&eff, "FLUXER_API_EMBEDDED_WORKER", "false"));
        m.insert("NODE_OPTIONS".into(), "--max-old-space-size-percentage=60".into());
        let (env, secrets) = split_env_and_secrets(m);
        cfg.env = env;
        let image = resolve_service_image("api", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "api".into(),
            config: cfg,
            image,
            secrets,
            tier: 3,
            backup_volume: None,
        });
    }

    // worker
    {
        let mut cfg = base_cfg("worker", &mem_limit(&eff, "FLUXER_WORKER_MEMORY_LIMIT", "1536MB"), 0.5);
        let replicas: u32 = get_or(&eff, "FLUXER_WORKER_REPLICAS", "1").parse().unwrap_or(1).clamp(1, 64);
        cfg.scale.count = Some(replicas);
        cfg.command = Some(Command::Exec(vec!["node".into(), "dist/WorkerEntrypoint.js".into()]));
        let mut m = common.clone();
        m.insert("FLUXER_API_WORKER_MODE".into(), "all_lanes".into());
        m.insert("FLUXER_API_WORKER_ENABLE_CRON_SCHEDULER".into(), "true".into());
        m.insert("FLUXER_POSTGRES_MAX_CONNECTIONS".into(), get_or(&eff, "FLUXER_WORKER_POSTGRES_MAX_CONNECTIONS", "25"));
        m.insert("NODE_OPTIONS".into(), "--max-old-space-size-percentage=55".into());
        let (env, secrets) = split_env_and_secrets(m);
        cfg.env = env;
        let image = resolve_service_image("worker", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "worker".into(),
            config: cfg,
            image,
            secrets,
            tier: 3,
            backup_volume: None,
        });
    }

    // gateway
    {
        let mut cfg = base_cfg("gateway", &mem_limit(&eff, "FLUXER_GATEWAY_MEMORY_LIMIT", "768MB"), 0.5);
        cfg.nofile = Some(65536);
        cfg.ports.push(PortConfig { port: 8080, public: false, public_port: None, protocol: "tcp".into() });
        let mut m = common.clone();
        m.insert("FLUXER_GATEWAY_PORT".into(), "8080".into());
        let origin = get_or(&eff, "FLUXER_PUBLIC_ORIGIN", &format!("https://{}", stack.domain));
        m.entry("FLUXER_GATEWAY_MEDIA_PROXY_ENDPOINT".into())
            .or_insert_with(|| format!("{origin}/media"));
        m.entry("FLUXER_GATEWAY_STATIC_CDN_ENDPOINT".into())
            .or_insert(origin);
        let (env, secrets) = split_env_and_secrets(m);
        cfg.env = env;
        let image = resolve_service_image("gateway", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "gateway".into(),
            config: cfg,
            image,
            secrets,
            tier: 3,
            backup_volume: None,
        });
    }

    // media-proxy
    {
        let mut cfg = base_cfg("media-proxy", &mem_limit(&eff, "FLUXER_MEDIA_PROXY_MEMORY_LIMIT", "768MB"), 0.5);
        cfg.ports.push(PortConfig { port: 8080, public: false, public_port: None, protocol: "tcp".into() });
        let mut m = common.clone();
        m.insert("FLUXER_MEDIA_PROXY_PORT".into(), "8080".into());
        m.insert("TOKIO_WORKER_THREADS".into(), get_or(&eff, "FLUXER_MEDIA_PROXY_TOKIO_WORKER_THREADS", "4"));
        m.insert("FLUXER_MEDIA_PROXY_MODE".into(), "upload".into());
        m.insert("FLUXER_MEDIA_PROXY_STORAGE_BACKEND".into(), "s3".into());
        let origin = get_or(&eff, "FLUXER_PUBLIC_ORIGIN", &format!("https://{}", stack.domain));
        m.entry("FLUXER_MEDIA_PROXY_CORS_ALLOWED_ORIGINS".into()).or_insert(origin);
        m.entry("FLUXER_S3_READ_SIGNED".into()).or_insert_with(|| "true".into());
        m.entry("FLUXER_MEDIA_PROXY_UPLOAD_RELAY_SPOOL_MAX_TOTAL_BYTES".into())
            .or_insert_with(|| "2147483648".into());
        let (env, secrets) = split_env_and_secrets(m);
        cfg.env = env;
        let image = resolve_service_image("media-proxy", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "media-proxy".into(),
            config: cfg,
            image,
            secrets,
            tier: 3,
            backup_volume: None,
        });
    }

    // static-proxy
    {
        let mut cfg = base_cfg("static-proxy", &mem_limit(&eff, "FLUXER_STATIC_PROXY_MEMORY_LIMIT", "256MB"), 0.25);
        cfg.ports.push(PortConfig { port: 8080, public: false, public_port: None, protocol: "tcp".into() });
        let image = resolve_service_image("static-proxy", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "static-proxy".into(),
            config: cfg,
            image,
            secrets: BTreeMap::new(),
            tier: 3,
            backup_volume: None,
        });
    }

    // Split-rust HTTP/worker services: push, app-proxy, admin
    if !stack.rust_single {
        // push
        {
            let mut cfg = base_cfg("push", &mem_limit(&eff, "FLUXER_PUSH_MEMORY_LIMIT", "256MB"), 0.25);
            let (env, secrets) = rust_common(&[]);
            cfg.env = env;
            let image = resolve_service_image("push", stack, bundle_images);
            cfg.build.image = Some(image.clone());
            cfg.validate()?;
            specs.push(ServiceSpec {
                service: "push".into(),
                config: cfg,
                image,
                secrets,
                tier: 3,
                backup_volume: None,
            });
        }

        // app-proxy
        {
            let mut cfg = base_cfg("app-proxy", &mem_limit(&eff, "FLUXER_APP_PROXY_MEMORY_LIMIT", "256MB"), 0.25);
            cfg.ports.push(PortConfig { port: 8080, public: false, public_port: None, protocol: "tcp".into() });
            let (env, secrets) = rust_common(&[
                ("FLUXER_APP_PROXY_PORT", "8080".into()),
                ("DISCOVERY_UPSTREAM_URL", "http://edge:8088/.well-known/fluxer".into()),
                ("DISCOVERY_REFRESH_INTERVAL_MS", get_or(&eff, "DISCOVERY_REFRESH_INTERVAL_MS", "5000")),
            ]);
            cfg.env = env;
            let image = resolve_service_image("app-proxy", stack, bundle_images);
            cfg.build.image = Some(image.clone());
            cfg.validate()?;
            specs.push(ServiceSpec {
                service: "app-proxy".into(),
                config: cfg,
                image,
                secrets,
                tier: 3,
                backup_volume: None,
            });
        }

        // admin
        {
            let mut cfg = base_cfg("admin", &mem_limit(&eff, "FLUXER_ADMIN_MEMORY_LIMIT", "256MB"), 0.25);
            cfg.ports.push(PortConfig { port: 8080, public: false, public_port: None, protocol: "tcp".into() });
            let origin = get_or(&eff, "FLUXER_PUBLIC_ORIGIN", &format!("https://{}", stack.domain));
            let (env, secrets) = rust_common(&[
                ("FLUXER_ADMIN_PORT", "8080".into()),
                ("FLUXER_ADMIN_BASE_PATH", get_or(&eff, "FLUXER_ADMIN_BASE_PATH", "/admin")),
                ("FLUXER_API_ENDPOINT", "http://api:8080".into()),
                ("FLUXER_STATIC_CDN_ENDPOINT", get_or(&eff, "FLUXER_STATIC_CDN_ENDPOINT", &origin)),
            ]);
            cfg.env = env;
            let image = resolve_service_image("admin", stack, bundle_images);
            cfg.build.image = Some(image.clone());
            cfg.validate()?;
            specs.push(ServiceSpec {
                service: "admin".into(),
                config: cfg,
                image,
                secrets,
                tier: 3,
                backup_volume: None,
            });
        }
    }

    // -----------------------------------------------------------------------
    // Tier 4: Edge (Caddy in proxy mode behind latrix's HTTPS ingress & DNS)
    // -----------------------------------------------------------------------
    {
        let mut cfg = base_cfg("edge", &mem_limit(&eff, "FLUXER_CADDY_MEMORY_LIMIT", "384MB"), 0.25);
        cfg.http = Some(HttpConfig {
            port: 8080,
            domains: vec![stack.domain.clone()],
            health: Some("/_health".into()),
            force_https: Some(true),
        });
        cfg.ports.push(PortConfig { port: 8088, public: false, public_port: None, protocol: "tcp".into() });
        let caddyfile = if stack.caddyfile.trim().is_empty() {
            DEFAULT_CADDYFILE
        } else {
            stack.caddyfile.as_str()
        };
        cfg.command = Some(caddy_bootstrap_command(caddyfile, &stack.caddy_dropins));
        cfg.env.insert("FLUXER_EDGE_SITE_ADDRESS".into(), ":8080".into());
        cfg.env.insert("FLUXER_EDGE_TLS_DIRECTIVE".into(), String::new());
        cfg.env.insert(
            "FLUXER_EDGE_TRUSTED_PROXIES".into(),
            get_or(&eff, "FLUXER_EDGE_TRUSTED_PROXIES", "private_ranges"),
        );
        cfg.env.insert("FLUXER_EDGE_ENCODE".into(), get_or(&eff, "FLUXER_EDGE_ENCODE", "zstd gzip"));
        cfg.env.insert(
            "FLUXER_EDGE_PROTOCOLS".into(),
            get_or(&eff, "FLUXER_EDGE_PROTOCOLS", "h1 h2"),
        );
        if let Some(opts) = eff.get("FLUXER_EDGE_GLOBAL_OPTIONS").filter(|s| !s.is_empty()) {
            cfg.env.insert("FLUXER_EDGE_GLOBAL_OPTIONS".into(), opts.clone());
        }
        cfg.env.insert("FLUXER_ADMIN_BASE_PATH".into(), get_or(&eff, "FLUXER_ADMIN_BASE_PATH", "/admin"));
        if stack.rust_single {
            cfg.env.insert("FLUXER_ADMIN_UPSTREAM".into(), "admin:18083".into());
        }
        let image = resolve_service_image("edge", stack, bundle_images);
        cfg.build.image = Some(image.clone());
        cfg.validate()?;
        specs.push(ServiceSpec {
            service: "edge".into(),
            config: cfg,
            image,
            secrets: BTreeMap::new(),
            tier: 4,
            backup_volume: None,
        });
    }

    Ok(specs)
}

/// Services whose images belong to Fluxer releases and are safe to roll during
/// automated upgrades (note: Postgres major upgrades are guarded separately).
pub fn is_fluxer_app_service(svc: &str) -> bool {
    matches!(
        svc,
        "rust"
            | "snowflakes"
            | "users"
            | "gifs"
            | "messages"
            | "unfurl"
            | "api"
            | "worker"
            | "gateway"
            | "media-proxy"
            | "static-proxy"
            | "push"
            | "app-proxy"
            | "admin"
            | "edge"
            | "livekit"
            | "meilisearch"
            | "nats"
            | "valkey"
            | "seaweedfs"
            | "postgres"
    )
}

/// Human-friendly storage backend summary.
pub fn storage_summary(stack: &FluxerStack) -> String {
    let backend = stack
        .settings
        .get("storage.backend")
        .or_else(|| stack.settings.get("FLUXER_STORAGE_BACKEND"))
        .map(|s| s.as_str())
        .unwrap_or("s3");
    if backend.eq_ignore_ascii_case("filesystem") {
        return "filesystem (local volume)".into();
    }
    if stack.external_object_store {
        let ep = stack
            .settings
            .get("storage.endpoint")
            .or_else(|| stack.settings.get("FLUXER_S3_ENDPOINT"))
            .map(|s| s.as_str())
            .unwrap_or("external S3");
        if ep.contains("r2.cloudflarestorage.com") {
            format!("Cloudflare R2 ({ep})")
        } else {
            format!("external S3 ({ep})")
        }
    } else {
        "SeaweedFS (bundled)".into()
    }
}

/// Names of secrets that should be masked in CLI output.
pub fn mask_value(key: &str, val: &str) -> String {
    let secret_named = matches!(key, "storage.secret_key" | "storage.access_key") || is_secret_entry(key, val);
    if secret_named {
        let chars: Vec<char> = val.chars().collect();
        if chars.len() <= 8 {
            "***".into()
        } else {
            let head: String = chars[..3].iter().collect();
            let tail: String = chars[chars.len() - 3..].iter().collect();
            format!("{head}…{tail}")
        }
    } else {
        val.to_string()
    }
}

/// Return all service names that belong to a Fluxer stack.
pub fn service_names_from_plan(specs: &[ServiceSpec]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = vec![];
    for s in specs {
        if seen.insert(s.service.clone()) {
            out.push(s.service.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_r2_stack() -> FluxerStack {
        let mut settings = BTreeMap::new();
        settings.insert("domain".into(), "chat.example.com".into());
        settings.insert("storage.endpoint".into(), "https://abc123.r2.cloudflarestorage.com".into());
        settings.insert("storage.public_endpoint".into(), "https://cdn.example.com".into());
        settings.insert("storage.region".into(), "auto".into());
        settings.insert("storage.path_style".into(), "true".into());
        settings.insert("storage.access_key".into(), "r2accesskey123".into());
        settings.insert("storage.secret_key".into(), "r2secretkey456".into());
        settings.insert("voice.bundled".into(), "true".into());

        let mut secrets = BTreeMap::new();
        secrets.insert("POSTGRES_PASSWORD".into(), "pgpass".into());
        secrets.insert("MEILI_MASTER_KEY".into(), "meilikey".into());
        secrets.insert("LIVEKIT_API_KEY".into(), "lkkey".into());
        secrets.insert("LIVEKIT_API_SECRET".into(), "lksecret".into());

        FluxerStack {
            project: "fluxer".into(),
            domain: "chat.example.com".into(),
            release: "2026.1124.80040".into(),
            previous_release: None,
            auto_upgrade: true,
            upgrade_interval_hours: 6,
            last_check: 0,
            last_upgrade: 0,
            last_error: None,
            latest_available: None,
            settings,
            secrets,
            caddyfile: DEFAULT_CADDYFILE.into(),
            caddyfile_custom: false,
            caddy_dropins: BTreeMap::new(),
            services: vec![],
            external_object_store: true,
            bundled_voice: true,
            kv_postgres: false,
            rust_single: false,
            copies: 2,
            region: None,
            image_overrides: BTreeMap::new(),
            created_at: 100,
            updated_at: 100,
        }
    }

    #[test]
    fn r2_and_bundled_livekit_plan() {
        let st = sample_r2_stack();
        let specs = plan_stack(&st, &BTreeMap::new()).unwrap();
        let names: Vec<&str> = specs.iter().map(|s| s.service.as_str()).collect();
        assert!(!names.contains(&"seaweedfs"), "external R2 skips seaweedfs");
        assert!(names.contains(&"livekit"), "bundled voice includes livekit");
        assert!(names.contains(&"postgres"));
        assert!(names.contains(&"valkey"));
        assert!(names.contains(&"nats"));
        assert!(names.contains(&"meilisearch"));
        assert!(names.contains(&"api"));
        assert!(names.contains(&"edge"));

        let api = specs.iter().find(|s| s.service == "api").unwrap();
        assert_eq!(
            api.config.env.get("FLUXER_S3_ENDPOINT").map(|s| s.as_str()),
            Some("https://abc123.r2.cloudflarestorage.com")
        );
        assert_eq!(api.config.env.get("FLUXER_S3_REGION").map(|s| s.as_str()), Some("auto"));
        assert_eq!(api.secrets.get("FLUXER_S3_SECRET_ACCESS_KEY").map(|s| s.as_str()), Some("r2secretkey456"));
        assert_eq!(api.secrets.get("FLUXER_POSTGRES_PASSWORD").map(|s| s.as_str()), Some("pgpass"));

        let lk = specs.iter().find(|s| s.service == "livekit").unwrap();
        assert_eq!(lk.config.udp_ports(), vec![(7882, 7882)]);
        assert!(lk.config.ports.iter().any(|p| p.port == 7881 && p.public && p.protocol == "tcp"));
        assert!(lk.secrets.contains_key("LIVEKIT_KEYS"));

        let edge = specs.iter().find(|s| s.service == "edge").unwrap();
        assert_eq!(edge.config.http.as_ref().unwrap().domains, vec!["chat.example.com"]);
        assert_eq!(edge.config.env.get("FLUXER_EDGE_SITE_ADDRESS").map(|s| s.as_str()), Some(":8080"));
        assert_eq!(storage_summary(&st), "Cloudflare R2 (https://abc123.r2.cloudflarestorage.com)");
    }

    #[test]
    fn backup_roundtrip_and_checksum_verification() {
        let dir = std::env::temp_dir().join(format!("latrix-fx-test-{}", util::random_id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let dump = dir.join("fluxer.dump");
        std::fs::write(&dump, b"PGDMP-fake-dump-payload").unwrap();
        let meili_dir = dir.join("meili");
        std::fs::create_dir_all(&meili_dir).unwrap();
        std::fs::write(meili_dir.join("data.mdb"), b"meili-index").unwrap();

        let mut vols = BTreeMap::new();
        vols.insert("meilisearch-data".into(), meili_dir);

        let st = sample_r2_stack();
        let archive = dir.join("fluxer-backup.tar.zst");
        write_rexctl_backup(&archive, &st, Some(&dump), &vols, "full", "test").unwrap();

        let extracted = extract_and_verify_backup(&archive, true).unwrap();
        assert_eq!(extracted.manifest.domain, "chat.example.com");
        assert_eq!(extracted.manifest.release, "2026.1124.80040");
        assert!(extracted.verified_entries >= 3);
        assert!(extracted.postgres_dump.is_some());
        assert!(extracted.volumes.contains_key("meilisearch-data"));

        let rebuilt = extracted.to_stack(None, None, None, true, None, 2).unwrap();
        assert!(rebuilt.external_object_store);
        assert!(rebuilt.bundled_voice);
        assert_eq!(rebuilt.domain, "chat.example.com");
        assert_eq!(rebuilt.secrets.get("POSTGRES_PASSWORD").map(|s| s.as_str()), Some("pgpass"));

        extracted.cleanup();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_comparison_and_compose_parsing() {
        assert!(is_newer_fluxer("2026.1125.10000", "2026.1124.80040"));
        assert!(!is_newer_fluxer("2026.1124.80040", "2026.1124.80040"));
        assert!(!is_newer_fluxer("2026.1123.90000", "2026.1124.80040"));
        assert_eq!(postgres_major("postgres:16-alpine@sha256:abcd"), Some(16));
        assert_eq!(postgres_major("postgres:17.2-alpine"), Some(17));

        let yaml = r#"
services:
  postgres:
    image: ${FLUXER_POSTGRES_IMAGE:-postgres:16-alpine@sha256:aaa}
  api:
    image: ghcr.io/fluxerapp/fluxer-api@sha256:bbb
"#;
        let imgs = parse_compose_images(yaml);
        assert_eq!(imgs.get("postgres").map(|s| s.as_str()), Some("postgres:16-alpine@sha256:aaa"));
        assert_eq!(imgs.get("api").map(|s| s.as_str()), Some("ghcr.io/fluxerapp/fluxer-api@sha256:bbb"));
    }

    #[test]
    fn rust_single_process_sets_aliases() {
        let mut st = sample_r2_stack();
        st.rust_single = true;
        let specs = plan_stack(&st, &BTreeMap::new()).unwrap();
        let rust = specs.iter().find(|s| s.service == "rust").unwrap();
        assert_eq!(rust.config.aliases, vec!["app-proxy", "admin"]);
        assert!(specs.iter().all(|s| s.service != "snowflakes" && s.service != "app-proxy"));
        let edge = specs.iter().find(|s| s.service == "edge").unwrap();
        assert_eq!(edge.config.env.get("FLUXER_ADMIN_UPSTREAM").map(|s| s.as_str()), Some("admin:18083"));
    }

    #[test]
    fn tampered_backup_rejected_when_verifying() {
        let dir = std::env::temp_dir().join(format!("latrix-fx-tamper-{}", util::random_id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let st = sample_r2_stack();
        let archive = dir.join("good.tar.zst");
        write_rexctl_backup(&archive, &st, None, &BTreeMap::new(), "full", "test").unwrap();

        // Extract, tamper with Caddyfile, re-pack with stale manifest/SHA256SUMS.
        let ext = extract_and_verify_backup(&archive, true).unwrap();
        std::fs::write(ext.work_dir.join("files").join("Caddyfile"), "tampered").unwrap();
        let bad = dir.join("bad.tar.zst");
        {
            let f = std::fs::File::create(&bad).unwrap();
            let enc = zstd::stream::write::Encoder::new(f, 1).unwrap();
            let mut tar = tar::Builder::new(enc);
            tar.append_dir_all(".", &ext.work_dir).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        assert!(extract_and_verify_backup(&bad, true).is_err());
        let ok_skip = extract_and_verify_backup(&bad, false).unwrap();
        assert_eq!(ok_skip.caddyfile.as_deref(), Some("tampered"));
        ok_skip.cleanup();
        ext.cleanup();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upgrade_path_and_seaweedfs_kv_postgres() {
        let rel = FluxerRelease {
            version: "2026.1201.10000".into(),
            min_from: "2026.1120.0".into(),
            schema_changed: true,
            compose_url: String::new(),
        };
        assert!(check_upgrade_path("2026.1124.80040", &rel).is_ok());
        assert!(check_upgrade_path("2026.1110.50000", &rel).is_err());

        let mut st = sample_r2_stack();
        st.external_object_store = false;
        st.settings.remove("storage.endpoint");
        st.kv_postgres = true;
        st.settings.insert("kv.mode".into(), "postgres".into());
        let specs = plan_stack(&st, &BTreeMap::new()).unwrap();
        assert!(specs.iter().any(|s| s.service == "seaweedfs"));
        assert!(!specs.iter().any(|s| s.service == "valkey"));
    }

    #[test]
    fn fluxer_hardening_edge_cases() {
        // UTF-8 safe masking
        assert_eq!(mask_value("storage.secret_key", "пароль_секретный_123"), "пар…123");
        assert_eq!(mask_value("storage.secret_key", "коротк"), "***");

        // Bundled SeaweedFS endpoint detection is host-exact
        assert!(is_bundled_seaweedfs_endpoint("http://seaweedfs:8333"));
        assert!(is_bundled_seaweedfs_endpoint("http://seaweedfs.internal:8333/bucket"));
        assert!(!is_bundled_seaweedfs_endpoint("https://seaweedfs.example.com"));

        // SeaweedFS init script rejects shell metacharacters in bucket names or whitespace in credentials
        let mut eff = BTreeMap::new();
        eff.insert("FLUXER_S3_BUCKET_CDN".into(), "bad;rm -rf /".into());
        assert!(seaweedfs_init_script(&eff).is_err());
        let mut bad_cred = BTreeMap::new();
        bad_cred.insert("FLUXER_S3_ACCESS_KEY".into(), "ak with space".into());
        assert!(seaweedfs_init_script(&bad_cred).is_err());

        // Upgrade path fails closed on unparseable versions
        let rel = FluxerRelease {
            version: "2026.1201.10000".into(),
            min_from: "2026.1120.0".into(),
            schema_changed: true,
            compose_url: String::new(),
        };
        assert!(check_upgrade_path("not-a-version", &rel).is_err());

        // Extra unverified file inside backup archive is rejected when verify=true
        let dir = std::env::temp_dir().join(format!("latrix-fx-extra-{}", util::random_id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let good_st = sample_r2_stack();
        let archive = dir.join("good.tar.zst");
        write_rexctl_backup(&archive, &good_st, None, &BTreeMap::new(), "full", "test").unwrap();
        let ext = extract_and_verify_backup(&archive, true).unwrap();
        std::fs::write(ext.work_dir.join("files").join("injected.txt"), "evil").unwrap();
        let bad = dir.join("extra.tar.zst");
        {
            let f = std::fs::File::create(&bad).unwrap();
            let enc = zstd::stream::write::Encoder::new(f, 1).unwrap();
            let mut tar = tar::Builder::new(enc);
            tar.append_dir_all(".", &ext.work_dir).unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        assert!(extract_and_verify_backup(&bad, true).is_err());
        ext.cleanup();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
