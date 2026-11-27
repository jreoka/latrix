//! Small helpers shared by the CLI and the agent.

use anyhow::{bail, Context, Result};
use rand::Rng;
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
    let secs = match unit {
        "ms" => n / 1000.0,
        "s" | "sec" | "secs" => n,
        "m" | "min" | "mins" => n * 60.0,
        "h" | "hr" | "hours" => n * 3600.0,
        "d" | "days" => n * 86400.0,
        _ => bail!("invalid duration unit in '{s}' (use ms, s, m, h or d)"),
    };
    Ok(Duration::from_secs_f64(secs))
}

/// Parses "512MB", "1GB", "1.5G", "256m" into megabytes.
pub fn parse_size_mb(s: &str) -> Result<u64> {
    let s = s.trim().to_ascii_lowercase();
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s.as_str(), "mb"),
    };
    let n: f64 = num.parse().with_context(|| format!("invalid size '{s}'"))?;
    let mb = match unit {
        "k" | "kb" | "kib" => n / 1024.0,
        "m" | "mb" | "mib" => n,
        "g" | "gb" | "gib" => n * 1024.0,
        "t" | "tb" | "tib" => n * 1024.0 * 1024.0,
        _ => bail!("invalid size unit in '{s}' (use MB or GB)"),
    };
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

/// Write a file atomically (write to temp + rename).
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp{}", random_id(6)));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
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
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
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
}
