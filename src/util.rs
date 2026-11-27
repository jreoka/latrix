//! Small helpers shared by the CLI and the agent.

use anyhow::{bail, Context, Result};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const API_PORT: u16 = 7470;
pub const REGISTRY_PORT: u16 = 7471;
pub const RSYNC_PORT: u16 = 7472;
pub const WG_PORT: u16 = 51870;
pub const DEV_HTTP_PORT: u16 = 7480;
pub const OVERLAY_PREFIX: &str = "10.77";
pub const VIP_PREFIX: &str = "10.78";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Seconds since the unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn random_id(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

pub fn random_token() -> String {
    random_id(40)
}

/// Parses "30s", "5m", "2h", "1d" or a bare number of seconds.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty duration");
    }
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s, "s"),
    };
    let n: f64 = num.parse().with_context(|| format!("invalid duration '{s}'"))?;
    if !n.is_finite() || n < 0.0 {
        bail!("invalid duration '{s}'");
    }
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" | "sec" | "secs" => n,
        "m" | "min" | "mins" => n * 60.0,
        "h" | "hr" | "hours" => n * 3600.0,
        "d" | "days" => n * 86400.0,
        _ => bail!("invalid duration unit in '{s}' (use ms, s, m, h or d)"),
    };
    Duration::try_from_secs_f64(secs).map_err(|_| anyhow::anyhow!("duration out of range: '{s}'"))
}

/// Parses "512MB", "1GB", "1.5G", "256m" into megabytes.
pub fn parse_size_mb(s: &str) -> Result<u64> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() {
        bail!("empty size");
    }
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s.as_str(), "mb"),
    };
    let n: f64 = num.parse().with_context(|| format!("invalid size '{s}'"))?;
    if !n.is_finite() || n < 0.0 {
        bail!("invalid size '{s}'");
    }
    let mb = match unit {
        "k" | "kb" | "kib" => n / 1024.0,
        "m" | "mb" | "mib" => n,
        "g" | "gb" | "gib" => n * 1024.0,
        "t" | "tb" | "tib" => n * 1024.0 * 1024.0,
        _ => bail!("invalid size unit in '{s}' (use MB or GB)"),
    };
    if !mb.is_finite() || mb > u64::MAX as f64 {
        bail!("size out of range: '{s}'");
    }
    Ok(mb.round() as u64)
}

pub fn human_duration(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86399 => format!("{}h{}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d{}h", secs / 86400, (secs % 86400) / 3600),
    }
}

pub fn ago(ts: u64) -> String {
    if ts == 0 {
        return "never".into();
    }
    format!("{} ago", human_duration(now().saturating_sub(ts)))
}

/// Valid app/volume/machine names: lowercase letters, digits and dashes.
pub fn validate_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 48 {
        bail!("{kind} name must be 1-48 characters");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || name.starts_with('-')
        || name.ends_with('-')
    {
        bail!("{kind} name '{name}' may only contain lowercase letters, digits and dashes");
    }
    Ok(())
}

/// Create a directory (and parents) and restrict the leaf to 0700 on Unix.
pub fn create_private_dir_all(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !path.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

fn write_atomic_impl(path: &Path, data: &[u8], private: bool) -> Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            if private {
                if !dir.exists() {
                    create_private_dir_all(dir)?;
                }
            } else {
                std::fs::create_dir_all(dir)?;
            }
        }
    }
    let tmp = path.with_extension(format!("tmp{}", random_id(10)));
    let write_res = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Write a file atomically (write to temp + fsync + rename).
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    write_atomic_impl(path, data, false)
}

/// Write a sensitive file atomically with mode 0600 set before writing bytes.
pub fn write_atomic_private(path: &Path, data: &[u8]) -> Result<()> {
    write_atomic_impl(path, data, true)
}

/// Safe single-segment identifier for volume/snapshot/tag directory names.
pub fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('.')
        && !id.starts_with('-')
        && !id.contains("..")
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Constant-time equality comparison via SHA-256 digests (does not leak length).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let ha = Sha256::digest(a);
    let hb = Sha256::digest(b);
    let mut diff = 0u8;
    for (x, y) in ha.iter().zip(hb.iter()) {
        diff |= x ^ y;
    }
    diff == 0 && a.len() == b.len()
}

/// Validate a Docker image reference against flag injection and control chars.
pub fn validate_image_ref(image: &str) -> Result<()> {
    let img = image.trim();
    if img.is_empty() || img.len() > 512 {
        bail!("invalid image reference");
    }
    if img.starts_with('-')
        || img.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid image reference '{image}'");
    }
    Ok(())
}

/// Validate a git clone URL (allows https/http/ssh/git@ only, forbids leading `-`).
pub fn validate_git_url(url: &str) -> Result<()> {
    let u = url.trim();
    if u.is_empty() || u.starts_with('-') || u.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid git URL '{url}'");
    }
    let ok = u.starts_with("https://")
        || u.starts_with("http://")
        || u.starts_with("ssh://")
        || (u.starts_with("git@") && u.contains(':'));
    if !ok {
        bail!("unsupported git URL scheme in '{url}' (use https://, http://, ssh://, or git@host:repo)");
    }
    Ok(())
}

/// Validate a git branch/ref name against option injection and invalid ref chars.
pub fn validate_git_branch(branch: &str) -> Result<()> {
    let b = branch.trim();
    if b.is_empty()
        || b.starts_with('-')
        || b.starts_with('/')
        || b.ends_with('/')
        || b.ends_with('.')
        || b.contains("..")
        || b.contains("@{")
        || b.chars().any(|c| {
            c.is_whitespace()
                || c.is_control()
                || matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
        })
    {
        bail!("invalid git branch '{branch}'");
    }
    Ok(())
}

/// Validate an SSH `[user@]host` target against option injection and shell metacharacters.
pub fn validate_ssh_target(target: &str) -> Result<()> {
    let t = target.trim();
    if t.is_empty() || t.starts_with('-') || t.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid SSH target '{target}'");
    }
    let (user, host) = match t.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, t),
    };
    if let Some(u) = user {
        if u.is_empty()
            || u.starts_with('-')
            || !u
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            bail!("invalid SSH user in '{target}'");
        }
    }
    let host_unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host_unbracketed.is_empty()
        || host_unbracketed.starts_with('-')
        || host_unbracketed.contains('@')
    {
        bail!("invalid SSH host in '{target}'");
    }
    if host_unbracketed.parse::<std::net::IpAddr>().is_err()
        && !host_unbracketed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        bail!("invalid SSH host in '{target}'");
    }
    Ok(())
}

/// Redact `user:pass@` credentials in a URL for safe display/logging.
pub fn redact_url_creds(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        let auth_end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let authority = &after[..auth_end];
        if let Some(at) = authority.rfind('@') {
            return format!(
                "{}://***@{}",
                &url[..scheme_end],
                &after[at + 1..]
            );
        }
    }
    url.to_string()
}

/// Shell-quote a single argument for POSIX shells.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@,+".contains(c))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Simple aligned table printer for CLI output.
pub fn print_table(headers: &[&str], rows: Vec<Vec<String>>) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }
    let line = |cells: Vec<String>| {
        let mut out = String::new();
        for (i, c) in cells.iter().enumerate() {
            let w = widths.get(i).copied().unwrap_or(0);
            if i + 1 == cells.len() {
                out.push_str(c);
            } else {
                out.push_str(&format!("{:<w$}  ", c, w = w));
            }
        }
        println!("{}", out.trim_end());
    };
    line(headers.iter().map(|h| h.to_string()).collect());
    for row in rows {
        line(row);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("30s").unwrap().as_secs(), 30);
        assert_eq!(parse_duration("5m").unwrap().as_secs(), 300);
        assert_eq!(parse_duration("2h").unwrap().as_secs(), 7200);
        assert_eq!(parse_duration("15").unwrap().as_secs(), 15);
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size_mb("512MB").unwrap(), 512);
        assert_eq!(parse_size_mb("1GB").unwrap(), 1024);
        assert_eq!(parse_size_mb("1.5g").unwrap(), 1536);
        assert_eq!(parse_size_mb("256").unwrap(), 256);
    }

    #[test]
    fn names() {
        assert!(validate_name("app", "my-app2").is_ok());
        assert!(validate_name("app", "My_App").is_err());
        assert!(validate_name("app", "-bad").is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("abc"), "abc");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn duration_and_size_edge_cases() {
        assert_eq!(parse_duration("500ms").unwrap().as_millis(), 500);
        for bad in ["", "NaN", "inf", "-5s", "99999999999999999999s", "10w"] {
            assert!(parse_duration(bad).is_err(), "expected err for duration '{bad}'");
        }
        assert_eq!(parse_size_mb("2TB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size_mb("2048KB").unwrap(), 2);
        assert_eq!(parse_size_mb("512MiB").unwrap(), 512);
        for bad in ["", "NaN", "inf", "-10MB", "abc"] {
            assert!(parse_size_mb(bad).is_err(), "expected err for size '{bad}'");
        }
    }

    #[test]
    fn security_validators_and_redaction() {
        assert!(safe_id("app__vol-1.2"));
        for bad in ["", "..", "a/b", "a\\b", "-flag", "a b", ".hidden"] {
            assert!(!safe_id(bad), "expected unsafe id '{bad}'");
        }
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
        assert!(!constant_time_eq(b"secret-token", b"secret-tokeN"));
        assert!(!constant_time_eq(b"short", b"longer"));

        assert!(validate_image_ref("ghcr.io/org/app:1.2@sha256:abc").is_ok());
        assert!(validate_image_ref("-oProxyCommand=evil").is_err());
        assert!(validate_image_ref("img with space").is_err());

        assert!(validate_git_url("https://github.com/org/repo.git").is_ok());
        assert!(validate_git_url("git@github.com:org/repo.git").is_ok());
        assert!(validate_git_url("ext::sh -c evil").is_err());
        assert!(validate_git_url("--upload-pack=evil").is_err());

        assert!(validate_git_branch("main").is_ok());
        assert!(validate_git_branch("release/v1.0").is_ok());
        assert!(validate_git_branch("-flag").is_err());
        assert!(validate_git_branch("a..b").is_err());

        assert!(validate_ssh_target("root@203.0.113.10").is_ok());
        assert!(validate_ssh_target("-oProxyCommand=id").is_err());
        assert!(validate_ssh_target("user@host;id").is_err());

        assert_eq!(
            redact_url_creds("https://user:supersecret@github.com/org/repo.git"),
            "https://***@github.com/org/repo.git"
        );
        assert_eq!(
            redact_url_creds("https://github.com/org/repo.git"),
            "https://github.com/org/repo.git"
        );
    }
}
