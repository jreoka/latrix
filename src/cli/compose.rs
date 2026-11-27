//! Docker Compose support: each compose service becomes a latrix app in a
//! group named after the stack. Services still reach each other by their
//! compose names (`db`, `redis`, ...) — across machines — via latrix DNS.

use crate::config::*;
use anyhow::{anyhow, bail, Context, Result};
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub struct Converted {
    pub config: AppConfig,
    /// Directory build contexts are relative to.
    pub base: PathBuf,
    pub depends_on: Vec<String>,
    pub warnings: Vec<String>,
}

fn sanitize(s: &str) -> String {
    let s: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let trimmed = s.trim_matches('-');
    let mut out = String::new();
    for c in trimmed.chars() {
        if !(c == '-' && out.ends_with('-')) {
            out.push(c);
        }
    }
    let truncated: String = out.chars().take(48).collect();
    let clean = truncated.trim_end_matches('-');
    if clean.is_empty() {
        "svc".into()
    } else {
        clean.to_string()
    }
}

fn is_loopback_host(host: &str) -> bool {
    let h = host.trim().trim_matches(['[', ']']);
    h.eq_ignore_ascii_case("localhost")
        || h.parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedPort {
    published: Option<u16>,
    container: u16,
    protocol: String,
    loopback_only: bool,
}

/// Parse "8080:80", "127.0.0.1:8080:80/tcp", "[::1]:8080:80/udp", "80".
fn parse_port_full(raw: &str) -> Option<ParsedPort> {
    let raw = raw.trim();
    let (addr_ports, proto) = match raw.rsplit_once('/') {
        Some((a, p)) => (a, p.trim().to_ascii_lowercase()),
        None => (raw, "tcp".into()),
    };
    if !matches!(proto.as_str(), "tcp" | "udp") {
        return None;
    }
    // Reject port ranges like "8000-8010:8000-8010".
    if addr_ports.contains('-') {
        return None;
    }
    let (host, rest) = if let Some(after_open) = addr_ports.strip_prefix('[') {
        let (ip, after_close) = after_open.split_once(']')?;
        let rest = after_close.strip_prefix(':')?;
        (Some(ip), rest)
    } else {
        let parts: Vec<&str> = addr_ports.split(':').collect();
        match parts.as_slice() {
            [c] => return Some(ParsedPort { published: None, container: c.parse().ok()?, protocol: proto, loopback_only: false }),
            [p, c] => return Some(ParsedPort { published: Some(p.parse().ok()?), container: c.parse().ok()?, protocol: proto, loopback_only: false }),
            [h, _, _] => (Some(*h), &addr_ports[h.len() + 1..]),
            _ => return None,
        }
    };
    let (p_str, c_str) = rest.split_once(':')?;
    let published = if p_str.is_empty() { None } else { Some(p_str.parse().ok()?) };
    let container = c_str.parse().ok()?;
    Some(ParsedPort {
        published,
        container,
        protocol: proto,
        loopback_only: host.map(is_loopback_host).unwrap_or(false),
    })
}

fn parse_compose_memory(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    // In Docker Compose, a unitless integer is in bytes (not megabytes).
    if s.bytes().all(|b| b.is_ascii_digit()) {
        let bytes: u64 = s.parse().ok()?;
        if bytes == 0 {
            return None;
        }
        let mb = bytes.div_ceil(1024 * 1024).max(1);
        return Some(format!("{mb}MB"));
    }
    // Explicit unit suffixes accepted by latrix's parse_size_mb (e.g. "512m", "1gb", "512MB", "1GiB").
    if let Ok(mb) = crate::util::parse_size_mb(s) {
        if mb > 0 {
            return Some(format!("{mb}MB"));
        }
    }
    // Remaining byte/sub-MB suffixes like "512b".
    let lower = s.to_ascii_lowercase();
    let num_s = lower.strip_suffix('b')?;
    let val: f64 = num_s.trim().parse().ok()?;
    if !val.is_finite() || val <= 0.0 {
        return None;
    }
    let mb = (val / (1024.0 * 1024.0)).ceil().max(1.0) as u64;
    Some(format!("{mb}MB"))
}

fn is_bind_mount_source(src: &str) -> bool {
    let s = src.trim();
    if s.is_empty() || s.starts_with('.') || s.starts_with('/') || s.starts_with('~') || s.starts_with('\\') {
        return true;
    }
    // Windows drive-letter bind mounts like `C:\data` or `D:/data`
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn parse_env_files(v: &Value) -> Vec<(String, bool)> {
    match v {
        Value::String(s) => vec![(s.clone(), true)],
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|item| match item {
                Value::String(s) => Some((s.clone(), true)),
                Value::Mapping(_) => {
                    let path = as_str(&item["path"])?;
                    let required = item["required"].as_bool().unwrap_or(true);
                    Some((path, required))
                }
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

fn as_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn str_list(v: &Value) -> Vec<String> {
    match v {
        Value::Sequence(s) => s.iter().filter_map(as_str).collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

const HTTP_PORTS: &[u16] = &[80, 443, 3000, 4000, 5000, 8000, 8008, 8080, 8081, 8443, 8888];

/// Parse "8080:80", "127.0.0.1:8080:80/tcp", "80" -> (published, container)
#[cfg(test)]
fn parse_port(s: &str) -> Option<(Option<u16>, u16)> {
    parse_port_full(s).map(|p| (p.published, p.container))
}

pub fn convert(path: &Path) -> Result<Vec<Converted>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let doc: Value = serde_yaml::from_str(&text).context("invalid compose file")?;
    let base = path.parent().map(|p| if p.as_os_str().is_empty() { Path::new(".") } else { p }).unwrap_or(Path::new(".")).to_path_buf();
    let base_abs = std::fs::canonicalize(&base).unwrap_or(base.clone());
    let stack = doc["name"]
        .as_str()
        .map(String::from)
        .or_else(|| base_abs.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "stack".into());
    let stack = sanitize(&stack);
    let services = doc["services"].as_mapping().ok_or_else(|| anyhow!("no services in compose file"))?;
    let mut out = vec![];
    for (k, svc) in services {
        let svc_name = sanitize(k.as_str().unwrap_or("svc"));
        let mut warnings = vec![];
        let app_name = {
            let combined = format!("{stack}-{svc_name}");
            let truncated: String = combined.chars().take(63).collect();
            truncated.trim_end_matches('-').to_string()
        };
        let mut cfg = AppConfig {
            app: app_name,
            group: Some(stack.clone()),
            service: Some(svc_name.clone()),
            ..Default::default()
        };
        // build / image
        match &svc["build"] {
            Value::String(ctx) => cfg.build.context = Some(ctx.clone()),
            Value::Mapping(_) => {
                let b = &svc["build"];
                cfg.build.context = Some(as_str(&b["context"]).unwrap_or_else(|| ".".into()));
                cfg.build.dockerfile = as_str(&b["dockerfile"]);
                cfg.build.target = as_str(&b["target"]);
                match &b["args"] {
                    Value::Mapping(m) => {
                        for (k, v) in m {
                            if let (Some(k), Some(v)) = (as_str(k), as_str(v)) {
                                cfg.build.args.insert(k, v);
                            }
                        }
                    }
                    Value::Sequence(_) => {
                        for a in str_list(&b["args"]) {
                            if let Some((k, v)) = a.split_once('=') {
                                cfg.build.args.insert(k.into(), v.into());
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => match as_str(&svc["image"]) {
                Some(img) => cfg.build.image = Some(img),
                None => bail!("service '{svc_name}' has neither build nor image"),
            },
        }
        // command
        match &svc["command"] {
            Value::String(s) => cfg.command = Some(Command::Shell(s.clone())),
            Value::Sequence(_) => cfg.command = Some(Command::Exec(str_list(&svc["command"]))),
            _ => {}
        }
        if !svc["entrypoint"].is_null() {
            warnings.push("entrypoint is not supported (bake it into the image)".into());
        }
        // environment
        let mut env = BTreeMap::new();
        for (f, required) in parse_env_files(&svc["env_file"]) {
            let p = base.join(&f);
            if !p.exists() && !required {
                continue;
            }
            if let Ok(canon_p) = std::fs::canonicalize(&p) {
                if !canon_p.starts_with(&base_abs) {
                    warnings.push(format!("env_file '{f}' resolves outside the compose directory"));
                }
            }
            let t = std::fs::read_to_string(&p).with_context(|| format!("reading env_file {}", p.display()))?;
            for (k, v) in crate::fluxer::parse_dotenv(&t) {
                env.insert(k, v);
            }
        }
        match &svc["environment"] {
            Value::Mapping(m) => {
                for (k, v) in m {
                    if let Some(k) = as_str(k) {
                        if let Some(val) = as_str(v).or_else(|| std::env::var(&k).ok()) {
                            env.insert(k, val);
                        }
                    }
                }
            }
            Value::Sequence(_) => {
                for e in str_list(&svc["environment"]) {
                    match e.split_once('=') {
                        Some((k, v)) => {
                            env.insert(k.into(), v.into());
                        }
                        None => {
                            if let Ok(v) = std::env::var(&e) {
                                env.insert(e, v);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        cfg.env = env;
        // ports
        let mut mappings: Vec<ParsedPort> = vec![];
        if let Value::Sequence(ports) = &svc["ports"] {
            for p in ports {
                match p {
                    Value::Mapping(_) => {
                        let target = p["target"].as_u64().and_then(|x| u16::try_from(x).ok());
                        let published = as_str(&p["published"]).and_then(|x| x.parse::<u16>().ok());
                        let protocol = as_str(&p["protocol"])
                            .map(|s| s.trim().to_ascii_lowercase())
                            .filter(|s| matches!(s.as_str(), "tcp" | "udp"))
                            .unwrap_or_else(|| "tcp".into());
                        let loopback_only = as_str(&p["host_ip"])
                            .map(|h| is_loopback_host(&h))
                            .unwrap_or(false);
                        if let Some(t) = target {
                            mappings.push(ParsedPort { published, container: t, protocol, loopback_only });
                        }
                    }
                    other => {
                        if let Some(s) = as_str(other) {
                            match parse_port_full(&s) {
                                Some(m) => mappings.push(m),
                                None => warnings.push(format!("could not parse port '{s}'")),
                            }
                        }
                    }
                }
            }
        }
        let http_idx = mappings.iter().position(|m| {
            m.protocol == "tcp"
                && !m.loopback_only
                && (HTTP_PORTS.contains(&m.container)
                    || m.published.map(|p| HTTP_PORTS.contains(&p)).unwrap_or(false))
        });
        for (i, m) in mappings.iter().enumerate() {
            if Some(i) == http_idx {
                cfg.http = Some(HttpConfig {
                    port: m.container,
                    ..Default::default()
                });
            } else {
                let public = if m.loopback_only && m.published.is_some() {
                    warnings.push(format!(
                        "port {} was bound to localhost in compose; keeping it internal on latrix",
                        m.container
                    ));
                    false
                } else {
                    m.published.is_some()
                };
                cfg.ports.push(PortConfig {
                    port: m.container,
                    public,
                    public_port: if public { m.published.filter(|p| *p != m.container) } else { None },
                    protocol: m.protocol.clone(),
                });
            }
        }
        for e in str_list(&svc["expose"]) {
            let (port_s, proto) = match e.split_once('/') {
                Some((p, pr)) => (p, pr.trim().to_ascii_lowercase()),
                None => (e.as_str(), "tcp".into()),
            };
            if let Ok(p) = port_s.parse::<u16>() {
                let protocol = if proto == "udp" { "udp" } else { "tcp" };
                let exists = (protocol == "tcp" && cfg.container_ports().contains(&p))
                    || cfg.ports.iter().any(|x| x.port == p && x.protocol == protocol);
                if !exists {
                    cfg.ports.push(PortConfig { port: p, public: false, public_port: None, protocol: protocol.into() });
                }
            }
        }
        // volumes
        if let Value::Sequence(vols) = &svc["volumes"] {
            for v in vols {
                let (src, target) = match v {
                    Value::Mapping(_) => {
                        let vtype = as_str(&v["type"]).unwrap_or_else(|| "volume".into());
                        if vtype.eq_ignore_ascii_case("tmpfs") {
                            warnings.push(format!(
                                "tmpfs mount '{}' ignored (use container memory/tmpfs)",
                                as_str(&v["target"]).unwrap_or_default()
                            ));
                            continue;
                        }
                        if vtype.eq_ignore_ascii_case("bind") {
                            warnings.push(format!(
                                "bind mount '{}' is not supported across machines — COPY it into the image or use a named volume",
                                as_str(&v["source"]).unwrap_or_default()
                            ));
                            continue;
                        }
                        let src = as_str(&v["source"]).unwrap_or_default();
                        let dst = as_str(&v["target"]).unwrap_or_default();
                        if src.is_empty() || dst.is_empty() {
                            warnings.push("anonymous or incomplete volume mapping ignored".into());
                            continue;
                        }
                        (src, dst)
                    }
                    other => {
                        let s = as_str(other).unwrap_or_default();
                        let parts: Vec<&str> = s.split(':').collect();
                        if parts.len() < 2 {
                            warnings.push(format!("anonymous volume '{s}' ignored"));
                            continue;
                        }
                        (parts[0].to_string(), parts[1].to_string())
                    }
                };
                if is_bind_mount_source(&src) {
                    warnings.push(format!(
                        "bind mount '{src}' is not supported across machines — COPY it into the image or use a named volume"
                    ));
                    continue;
                }
                cfg.volumes.push(VolumeConfig {
                    name: sanitize(&src),
                    path: target,
                    copies: 2,
                    sync: "30s".into(),
                    pre_sync: None,
                    size: None,
                });
            }
        }
        // scale / resources
        if let Some(r) = svc["deploy"]["replicas"].as_u64() {
            cfg.scale.count = Some(r as u32);
        }
        if let Some(c) = as_str(&svc["deploy"]["resources"]["limits"]["cpus"])
            .and_then(|c| c.parse::<f64>().ok())
            .filter(|c| c.is_finite() && *c >= 0.0)
        {
            cfg.scale.cpu = c;
        }
        if let Some(m) = as_str(&svc["deploy"]["resources"]["limits"]["memory"]) {
            match parse_compose_memory(&m) {
                Some(norm) => cfg.scale.memory = norm,
                None => warnings.push(format!("could not parse memory limit '{m}'; using default {}", cfg.scale.memory)),
            }
        }
        if !cfg.volumes.is_empty() && cfg.scale.count.unwrap_or(1) > 1 {
            warnings.push("services with volumes run as a single (replicated) instance".into());
            cfg.scale.count = Some(1);
        }
        let depends_on = match &svc["depends_on"] {
            Value::Mapping(m) => m.keys().filter_map(|k| k.as_str().map(sanitize)).collect(),
            other => str_list(other).iter().map(|s| sanitize(s)).collect(),
        };
        cfg.validate().with_context(|| format!("service '{svc_name}'"))?;
        out.push(Converted {
            config: cfg,
            base: base.clone(),
            depends_on,
            warnings,
        });
    }
    // Deploy dependencies first.
    let mut ordered: Vec<Converted> = vec![];
    let mut remaining = out;
    while !remaining.is_empty() {
        let done: Vec<String> = ordered.iter().map(|c| c.config.service_name().to_string()).collect();
        let idx = remaining
            .iter()
            .position(|c| c.depends_on.iter().all(|d| done.contains(d)))
            .unwrap_or(0);
        ordered.push(remaining.remove(idx));
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_a_typical_stack() {
        let dir = std::env::temp_dir().join(format!("latrix-compose-{}", crate::util::random_id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("docker-compose.yml");
        std::fs::write(
            &f,
            r#"
name: shop
services:
  web:
    build: .
    ports: ["8080:3000"]
    environment:
      DATABASE_URL: postgres://postgres:pw@db:5432/app
    depends_on: [db]
  db:
    image: postgres:16
    environment:
      - POSTGRES_PASSWORD=pw
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata: {}
"#,
        )
        .unwrap();
        let apps = convert(&f).unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].config.app, "shop-db", "dependency first");
        assert_eq!(apps[0].config.volumes[0].name, "pgdata");
        assert_eq!(apps[1].config.app, "shop-web");
        assert_eq!(apps[1].config.http.as_ref().unwrap().port, 3000);
        assert_eq!(apps[1].config.group.as_deref(), Some("shop"));
        assert_eq!(apps[1].config.build.context.as_deref(), Some("."));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ports() {
        assert_eq!(parse_port("8080:80"), Some((Some(8080), 80)));
        assert_eq!(parse_port("127.0.0.1:5432:5432/tcp"), Some((Some(5432), 5432)));
        assert_eq!(parse_port("6379"), Some((None, 6379)));

        let udp = parse_port_full("7777:7777/udp").unwrap();
        assert_eq!((udp.published, udp.container, udp.protocol.as_str(), udp.loopback_only), (Some(7777), 7777, "udp", false));

        let lo4 = parse_port_full("127.0.0.1:5432:5432").unwrap();
        assert!(lo4.loopback_only);

        let lo6 = parse_port_full("[::1]:6379:6379").unwrap();
        assert!(lo6.loopback_only);
        assert_eq!((lo6.published, lo6.container), (Some(6379), 6379));

        assert!(parse_port_full("8000-8010:8000-8010").is_none(), "port ranges rejected");

        assert_eq!(parse_compose_memory("512m").as_deref(), Some("512MB"));
        assert_eq!(parse_compose_memory("1GiB").as_deref(), Some("1024MB"));
        assert_eq!(parse_compose_memory("268435456").as_deref(), Some("256MB"));
    }

    #[test]
    fn loopback_ports_stay_internal() {
        let dir = std::env::temp_dir().join(format!("latrix-compose-lo-{}", crate::util::random_id(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("docker-compose.yml");
        std::fs::write(
            &f,
            "name: app\nservices:\n  db:\n    image: postgres:16\n    ports: [\"127.0.0.1:5432:5432\"]\n",
        )
        .unwrap();
        let apps = convert(&f).unwrap();
        assert_eq!(apps[0].config.ports.len(), 1);
        assert!(!apps[0].config.ports[0].public, "loopback port must remain internal");
        assert!(apps[0].warnings.iter().any(|w| w.contains("localhost")));
        let _ = std::fs::remove_dir_all(dir);
    }
}
