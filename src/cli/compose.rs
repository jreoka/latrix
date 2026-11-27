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
    s.trim_matches('-').to_string()
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
fn parse_port(s: &str) -> Option<(Option<u16>, u16)> {
    let s = s.split('/').next()?;
    let parts: Vec<&str> = s.split(':').collect();
    let container = parts.last()?.parse().ok()?;
    let published = if parts.len() >= 2 { parts[parts.len() - 2].parse().ok() } else { None };
    Some((published, container))
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
        let mut cfg = AppConfig {
            app: format!("{stack}-{svc_name}"),
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
        for f in str_list(&svc["env_file"]) {
            let p = base.join(&f);
            let t = std::fs::read_to_string(&p).with_context(|| format!("reading env_file {}", p.display()))?;
            for line in t.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    env.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
                }
            }
        }
        match &svc["environment"] {
            Value::Mapping(m) => {
                for (k, v) in m {
                    if let Some(k) = as_str(k) {
                        let v = as_str(v).or_else(|| std::env::var(&k).ok()).unwrap_or_default();
                        env.insert(k, v);
                    }
                }
            }
            Value::Sequence(_) => {
                for e in str_list(&svc["environment"]) {
                    match e.split_once('=') {
                        Some((k, v)) => env.insert(k.into(), v.into()),
                        None => env.insert(e.clone(), std::env::var(&e).unwrap_or_default()),
                    };
                }
            }
            _ => {}
        }
        cfg.env = env;
        // ports
        let mut mappings: Vec<(Option<u16>, u16)> = vec![];
        if let Value::Sequence(ports) = &svc["ports"] {
            for p in ports {
                match p {
                    Value::Mapping(_) => {
                        let target = p["target"].as_u64().map(|x| x as u16);
                        let published = as_str(&p["published"]).and_then(|x| x.parse().ok());
                        if let Some(t) = target {
                            mappings.push((published, t));
                        }
                    }
                    other => {
                        if let Some(s) = as_str(other) {
                            match parse_port(&s) {
                                Some(m) => mappings.push(m),
                                None => warnings.push(format!("could not parse port '{s}'")),
                            }
                        }
                    }
                }
            }
        }
        let http_idx = mappings
            .iter()
            .position(|(p, c)| HTTP_PORTS.contains(c) || p.map(|p| HTTP_PORTS.contains(&p)).unwrap_or(false));
        for (i, (published, container)) in mappings.iter().enumerate() {
            if Some(i) == http_idx {
                cfg.http = Some(HttpConfig {
                    port: *container,
                    ..Default::default()
                });
            } else {
                cfg.ports.push(PortConfig {
                    port: *container,
                    public: published.is_some(),
                    public_port: published.filter(|p| p != container),
                });
            }
        }
        for e in str_list(&svc["expose"]) {
            if let Ok(p) = e.split('/').next().unwrap_or("").parse::<u16>() {
                if !cfg.container_ports().contains(&p) {
                    cfg.ports.push(PortConfig { port: p, public: false, public_port: None });
                }
            }
        }
        // volumes
        if let Value::Sequence(vols) = &svc["volumes"] {
            for v in vols {
                let (src, target) = match v {
                    Value::Mapping(_) => (as_str(&v["source"]).unwrap_or_default(), as_str(&v["target"]).unwrap_or_default()),
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
                if src.starts_with('.') || src.starts_with('/') || src.starts_with('~') {
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
        if let Some(c) = as_str(&svc["deploy"]["resources"]["limits"]["cpus"]).and_then(|c| c.parse::<f64>().ok()) {
            cfg.scale.cpu = c;
        }
        if let Some(m) = as_str(&svc["deploy"]["resources"]["limits"]["memory"]) {
            cfg.scale.memory = m;
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
    }
}
