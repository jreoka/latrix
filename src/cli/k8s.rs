//! Kubernetes as a deploy target.
//!
//! A Kubernetes cluster is registered like any other cluster
//! (`latrix k8s add`), and the usual commands work on it. The same
//! latrix.toml becomes standard Kubernetes resources:
//!
//! | latrix.toml            | Kubernetes                                        |
//! |------------------------|---------------------------------------------------|
//! | app (no volumes)       | Deployment (rolling, spread across nodes)         |
//! | app with [[volumes]]   | StatefulSet (1 replica) + PersistentVolumeClaims  |
//! | ports                  | Service `<app>` (+ `<service>` short name)        |
//! | [[ports]] public=true  | Service `<app>-public` of type LoadBalancer       |
//! | [http] domains         | Ingress (+ cert-manager TLS when configured)      |
//! | [scale] min/max        | HorizontalPodAutoscaler                           |
//! | secrets                | Secret `<app>-secrets`                            |
//! | release history        | ConfigMap `<app>-latrix`                          |
//!
//! Everything goes through the `kubectl` on your computer, so any cluster
//! kubectl can reach works (k3s, DOKS, GKE, EKS, AKS, ...). Images are built
//! locally with Docker and pushed to the registry you configure.

use super::profile::{CliConfig, ClusterProfile, K8sTarget};
use super::*;
use crate::config::{AppConfig, Command as AppCommand};
use crate::util::{self, ago, now, parse_size_mb, print_table};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

const MANAGED: &str = "app.kubernetes.io/managed-by=latrix";
const CERT_MANAGER_URL: &str =
    "https://github.com/cert-manager/cert-manager/releases/download/v1.16.2/cert-manager.yaml";

// ---------------------------------------------------------------------------
// kubectl

pub struct Kube {
    pub t: K8sTarget,
}

impl Kube {
    fn base_args(&self, namespaced: bool) -> Vec<String> {
        let mut a = vec![];
        if let Some(k) = &self.t.kubeconfig {
            a.push("--kubeconfig".to_string());
            a.push(k.clone());
        }
        if let Some(c) = &self.t.context {
            a.push("--context".into());
            a.push(c.clone());
        }
        if namespaced {
            a.push("-n".into());
            a.push(self.t.namespace.clone());
        }
        a
    }

    async fn exec(&self, args: &[&str], input: Option<&str>, namespaced: bool) -> Result<String> {
        let mut all = self.base_args(namespaced);
        all.extend(args.iter().map(|s| s.to_string()));
        let mut child = tokio::process::Command::new("kubectl")
            .args(&all)
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("could not run `kubectl` — install it and make sure it can reach your cluster")?;
        if let Some(i) = input {
            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(i.as_bytes()).await {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        return Err(e.into());
                    }
                }
            }
        }
        let out = tokio::time::timeout(std::time::Duration::from_secs(600), child.wait_with_output())
            .await
            .context("kubectl command timed out after 10 minutes")??;
        if !out.status.success() {
            bail!(
                "kubectl {}: {}",
                args.first().copied().unwrap_or(""),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    pub async fn run(&self, args: &[&str]) -> Result<String> {
        self.exec(args, None, true).await
    }

    pub async fn run_global(&self, args: &[&str]) -> Result<String> {
        self.exec(args, None, false).await
    }

    pub async fn apply(&self, yaml: &str) -> Result<String> {
        self.exec(&["apply", "-f", "-"], Some(yaml), true).await
    }

    pub async fn json(&self, args: &[&str]) -> Result<Value> {
        let mut a = args.to_vec();
        a.extend(["-o", "json"]);
        Ok(serde_json::from_str(&self.run(&a).await?)?)
    }

    /// Run kubectl attached to the terminal (logs -f, exec -it).
    pub fn interactive(&self, args: &[&str]) -> Result<std::process::ExitStatus> {
        let mut all = self.base_args(true);
        all.extend(args.iter().map(|s| s.to_string()));
        Ok(std::process::Command::new("kubectl").args(&all).status()?)
    }
}

// ---------------------------------------------------------------------------
// manifests

pub fn labels(cfg: &AppConfig) -> Value {
    let mut l = json!({
        "app.kubernetes.io/name": cfg.app,
        "app.kubernetes.io/managed-by": "latrix",
    });
    if let Some(g) = &cfg.group {
        l["app.kubernetes.io/part-of"] = json!(g);
    }
    l
}

fn selector(cfg: &AppConfig) -> Value {
    json!({ "app.kubernetes.io/name": cfg.app })
}

fn cpu_quantity(cpu: f64) -> String {
    format!("{}m", (cpu * 1000.0).round().max(1.0) as u64)
}

pub fn hosts(cfg: &AppConfig, t: &K8sTarget) -> Vec<String> {
    let mut h: Vec<String> = vec![];
    for d in cfg.http.iter().flat_map(|h| h.domains.iter()) {
        let d = crate::config::normalize_dns_name(d);
        if !d.is_empty() && !h.contains(&d) {
            h.push(d);
        }
    }
    if let (Some(base), Some(_)) = (&t.base_domain, &cfg.http) {
        let sub = format!("{}.{}", cfg.app, crate::config::normalize_dns_name(base));
        if !h.contains(&sub) {
            h.push(sub);
        }
    }
    h
}

fn escape_k8s_env(val: &str) -> String {
    // Kubernetes interprets `$(VAR)` in literal env values; doubling `$` escapes it.
    val.replace('$', "$$")
}

fn workload_kind(cfg: &AppConfig) -> &'static str {
    if cfg.stateful() {
        "StatefulSet"
    } else {
        "Deployment"
    }
}

/// Render the Kubernetes objects for one release of an app.
pub fn render(cfg: &AppConfig, image: &str, version: u64, t: &K8sTarget) -> Vec<Value> {
    let app = &cfg.app;
    let lbl = labels(cfg);
    let ports = cfg.container_ports();
    let (min, max) = cfg.scale.bounds();
    let mut docs = vec![];

    // --- container
    let mut env = vec![json!({"name": "LATRIX_APP", "value": app}), json!({"name": "LATRIX_RELEASE", "value": version.to_string()})];
    if let Some(h) = &cfg.http {
        env.push(json!({"name": "PORT", "value": h.port.to_string()}));
    }
    for (k, v) in &cfg.env {
        env.retain(|e| e["name"] != json!(k));
        env.push(json!({"name": k, "value": escape_k8s_env(v)}));
    }
    let mut seen_cports = std::collections::BTreeSet::new();
    let mut container_ports = vec![];
    for p in &ports {
        if seen_cports.insert((*p, "TCP")) {
            container_ports.push(json!({"containerPort": p, "name": format!("p{p}")}));
        }
    }
    for (_, p) in cfg.udp_ports() {
        if seen_cports.insert((p, "UDP")) {
            container_ports.push(json!({"containerPort": p, "name": format!("u{p}"), "protocol": "UDP"}));
        }
    }
    let mut container = json!({
        "name": app,
        "image": image,
        "env": env,
        "envFrom": [{"secretRef": {"name": format!("{app}-secrets"), "optional": true}}],
        "ports": container_ports,
        "resources": {
            "requests": {"cpu": cpu_quantity(cfg.scale.cpu.max(0.01)), "memory": format!("{}Mi", cfg.scale.memory_mb())},
            "limits": {"memory": format!("{}Mi", cfg.scale.memory_mb())},
        },
    });
    if cfg.scale.cpu > 0.0 {
        container["resources"]["limits"]["cpu"] = json!(cpu_quantity(cfg.scale.cpu));
    }
    if let Some(c) = &cfg.command {
        // Like `docker run image <args>`: replaces CMD, keeps ENTRYPOINT.
        container["args"] = json!(match c {
            AppCommand::Shell(s) => vec!["sh".to_string(), "-c".into(), s.clone()],
            AppCommand::Exec(v) => v.clone(),
        });
    }
    let probe = match &cfg.http {
        Some(h) => match &h.health {
            Some(path) => Some(json!({"httpGet": {"path": path, "port": h.port}})),
            None => Some(json!({"tcpSocket": {"port": h.port}})),
        },
        None => cfg.ports.iter().find(|p| p.protocol == "tcp").map(|p| json!({"tcpSocket": {"port": p.port}})),
    };
    if let Some(mut p) = probe {
        p["periodSeconds"] = json!(5);
        p["failureThreshold"] = json!(3);
        container["readinessProbe"] = p;
    }
    if !cfg.volumes.is_empty() {
        container["volumeMounts"] = json!(cfg
            .volumes
            .iter()
            .map(|v| json!({"name": v.name, "mountPath": v.path}))
            .collect::<Vec<_>>());
    }
    let pod = json!({
        "metadata": {
            "labels": lbl,
            // A new release always rolls the pods (restarts, secret changes).
            "annotations": {"latrix.dev/release": version.to_string()},
        },
        "spec": {
            "terminationGracePeriodSeconds": cfg.deploy.stop_timeout_secs(),
            "containers": [container],
            "topologySpreadConstraints": [{
                "maxSkew": 1,
                "topologyKey": "kubernetes.io/hostname",
                "whenUnsatisfiable": "ScheduleAnyway",
                "labelSelector": {"matchLabels": selector(cfg)},
            }],
        },
    });

    // --- workload
    if cfg.stateful() {
        let claims: Vec<Value> = cfg
            .volumes
            .iter()
            .map(|v| {
                let size = v
                    .size
                    .as_deref()
                    .and_then(|s| parse_size_mb(s).ok())
                    .unwrap_or(10 * 1024)
                    .max(1);
                let mut c = json!({
                    "metadata": {"name": v.name, "labels": lbl},
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {"requests": {"storage": format!("{size}Mi")}},
                    },
                });
                if let Some(sc) = &t.storage_class {
                    c["spec"]["storageClassName"] = json!(sc);
                }
                c
            })
            .collect();
        let headless_name = format!("{app}-headless");
        docs.push(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": app, "labels": lbl},
            "spec": {
                "replicas": cfg.scale.initial().min(1),
                "serviceName": headless_name,
                "selector": {"matchLabels": selector(cfg)},
                "template": pod,
                "volumeClaimTemplates": claims,
            },
        }));
        let headless_ports: Vec<Value> = ports
            .iter()
            .map(|p| json!({"name": format!("p{p}"), "port": p, "targetPort": p}))
            .collect();
        let mut headless_spec = json!({"clusterIP": "None", "selector": selector(cfg)});
        if !headless_ports.is_empty() {
            headless_spec["ports"] = json!(headless_ports);
        }
        docs.push(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": headless_name, "labels": lbl},
            "spec": headless_spec,
        }));
    } else {
        let strategy = if cfg.deploy.rolling() {
            json!({"type": "RollingUpdate", "rollingUpdate": {"maxUnavailable": 0, "maxSurge": "25%"}})
        } else {
            json!({"type": "Recreate"})
        };
        let mut d = json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": app, "labels": lbl},
            "spec": {
                "selector": {"matchLabels": selector(cfg)},
                "strategy": strategy,
                "progressDeadlineSeconds": cfg.deploy.health_timeout_secs().max(30),
                "template": pod,
            },
        });
        if !cfg.scale.autoscale() {
            d["spec"]["replicas"] = json!(cfg.scale.initial());
        }
        docs.push(d);
    }

    // --- services
    if !ports.is_empty() {
        let svc_ports: Vec<Value> = ports
            .iter()
            .map(|p| json!({"name": format!("p{p}"), "port": p, "targetPort": p}))
            .collect();
        docs.push(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": app, "labels": lbl},
            "spec": {"selector": selector(cfg), "ports": svc_ports},
        }));
        // Short name inside a group (compose service names keep working).
        if let Some(s) = &cfg.service {
            if s != app {
                docs.push(json!({
                    "apiVersion": "v1", "kind": "Service",
                    "metadata": {"name": s, "labels": lbl},
                    "spec": {"selector": selector(cfg), "ports": svc_ports},
                }));
            }
        }
    }
    let mut seen_pub = std::collections::BTreeSet::new();
    let public: Vec<Value> = cfg
        .ports
        .iter()
        .filter(|p| p.public)
        .filter_map(|p| {
            let udp = p.protocol == "udp";
            let pub_port = p.public_port.unwrap_or(p.port);
            if !seen_pub.insert((pub_port, udp)) {
                return None;
            }
            Some(json!({
                "name": format!("{}{}", if udp { "u" } else { "p" }, pub_port),
                "port": pub_port,
                "targetPort": p.port,
                "protocol": if udp { "UDP" } else { "TCP" },
            }))
        })
        .collect();
    if !public.is_empty() {
        docs.push(json!({
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": format!("{app}-public"), "labels": lbl},
            "spec": {"type": "LoadBalancer", "selector": selector(cfg), "ports": public},
        }));
    }

    // --- ingress
    let hs = hosts(cfg, t);
    if let (Some(h), false) = (&cfg.http, hs.is_empty()) {
        let mut ing = json!({
            "apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
            "metadata": {"name": app, "labels": lbl, "annotations": {}},
            "spec": {
                "rules": hs.iter().map(|host| json!({
                    "host": host,
                    "http": {"paths": [{
                        "path": "/", "pathType": "Prefix",
                        "backend": {"service": {"name": app, "port": {"number": h.port}}},
                    }]},
                })).collect::<Vec<_>>(),
            },
        });
        if let Some(c) = &t.ingress_class {
            ing["spec"]["ingressClassName"] = json!(c);
        }
        if let Some(issuer) = &t.cluster_issuer {
            ing["metadata"]["annotations"]["cert-manager.io/cluster-issuer"] = json!(issuer);
            ing["spec"]["tls"] = json!([{"hosts": hs, "secretName": format!("{app}-tls")}]);
        }
        docs.push(ing);
    }

    // --- autoscaling (only for stateless workloads with max > 1)
    if cfg.scale.autoscale() && !cfg.stateful() && max > 1 {
        docs.push(json!({
            "apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
            "metadata": {"name": app, "labels": lbl},
            "spec": {
                "scaleTargetRef": {"apiVersion": "apps/v1", "kind": workload_kind(cfg), "name": app},
                "minReplicas": min.max(1), "maxReplicas": max,
                "metrics": [
                    {"type": "Resource", "resource": {"name": "cpu", "target": {"type": "Utilization", "averageUtilization": 75}}},
                    {"type": "Resource", "resource": {"name": "memory", "target": {"type": "Utilization", "averageUtilization": 85}}},
                ],
            },
        }));
    }
    docs
}

pub fn to_yaml(docs: &[Value]) -> Result<String> {
    let mut out = String::new();
    for d in docs {
        out.push_str("---\n");
        out.push_str(&serde_yaml::to_string(d)?);
    }
    Ok(out)
}

fn kind_name(v: &Value) -> (String, String) {
    (
        v["kind"].as_str().unwrap_or_default().to_string(),
        v["metadata"]["name"].as_str().unwrap_or_default().to_string(),
    )
}

/// Objects the previous release had that the new one doesn't (to delete).
pub fn stale(prev: &[Value], cur: &[Value]) -> Vec<(String, String)> {
    let cur: Vec<(String, String)> = cur.iter().map(kind_name).collect();
    prev.iter().map(kind_name).filter(|k| !cur.contains(k)).collect()
}

// ---------------------------------------------------------------------------
// release history (ConfigMap <app>-latrix)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sRelease {
    pub version: u64,
    pub image: String,
    pub config: AppConfig,
    pub created_at: u64,
    pub status: String,
    #[serde(default)]
    pub description: String,
}

async fn load_history(k: &Kube, app: &str) -> Result<Vec<K8sRelease>> {
    match k.json(&["get", "configmap", &format!("{app}-latrix")]).await {
        Ok(v) => match v["data"]["releases.json"].as_str() {
            Some(s) if !s.trim().is_empty() => {
                serde_json::from_str(s).with_context(|| format!("corrupt release history in ConfigMap {app}-latrix"))
            }
            _ => Ok(vec![]),
        },
        Err(e) if e.to_string().contains("NotFound") || e.to_string().contains("not found") => Ok(vec![]),
        Err(e) => Err(e),
    }
}

async fn save_history(k: &Kube, cfg: &AppConfig, mut h: Vec<K8sRelease>) -> Result<()> {
    h.sort_by_key(|r| r.version);
    while h.len() > 10 {
        h.remove(0);
    }
    let cm = json!({
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {"name": format!("{}-latrix", cfg.app), "labels": labels(cfg)},
        "data": {"releases.json": serde_json::to_string(&h)?},
    });
    k.apply(&to_yaml(&[cm])?).await?;
    Ok(())
}

fn current(h: &[K8sRelease]) -> Option<&K8sRelease> {
    h.iter().filter(|r| r.status == "active").max_by_key(|r| r.version)
}

// ---------------------------------------------------------------------------
// build

async fn run_local(program: &str, args: &[String], dir: Option<&Path>) -> Result<()> {
    let mut c = std::process::Command::new(program);
    c.args(args);
    if let Some(d) = dir {
        c.current_dir(d);
    }
    let st = tokio::task::spawn_blocking(move || c.status()).await??;
    if !st.success() {
        bail!("{program} {} failed", args.first().cloned().unwrap_or_default());
    }
    Ok(())
}

struct RemoveDirGuard(std::path::PathBuf);
impl Drop for RemoveDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn confine_subpath(root: &Path, sub: &str, label: &str) -> Result<std::path::PathBuf> {
    let p = Path::new(sub);
    if p.is_absolute() {
        bail!("{label} '{sub}' must be a relative path");
    }
    let joined = root.join(p);
    let canon_root = std::fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))?;
    let canon_target = std::fs::canonicalize(&joined)
        .with_context(|| format!("{label} '{}' does not exist", joined.display()))?;
    if !canon_target.starts_with(&canon_root) {
        bail!("{label} '{sub}' escapes the build root");
    }
    Ok(canon_target)
}

/// Build with local Docker (buildx) and push to the target's registry.
/// The previous `:latest` image doubles as the build cache (inline cache),
/// so builds from any computer reuse layers.
async fn build_and_push(cfg: &AppConfig, base: &Path, t: &K8sTarget) -> Result<String> {
    let reg = t.registry.as_deref().ok_or_else(|| {
        anyhow!(
            "building on Kubernetes needs an image registry the cluster can pull from:\n  \
             latrix k8s add <name> --registry ghcr.io/<you>   (and `docker login` to it)\n  \
             or deploy a prebuilt image with [build] image = \"...\""
        )
    })?;
    let repo = format!("{}/{}", reg.trim_end_matches('/'), cfg.app);
    let tag = format!("{}-{}", now(), util::random_id(4));
    let image = format!("{repo}:{tag}");
    let mut _git_guard: Option<RemoveDirGuard> = None;
    let (ctx, dockerfile) = match &cfg.build.git {
        Some(url) => {
            util::validate_git_url(url)?;
            let tmp = std::env::temp_dir().join(format!("latrix-git-{}", util::random_id(8)));
            _git_guard = Some(RemoveDirGuard(tmp.clone()));
            let mut args = vec!["clone".to_string(), "--depth".into(), "1".into()];
            if let Some(b) = &cfg.build.branch {
                util::validate_git_branch(b)?;
                args.push("--branch".into());
                args.push(b.clone());
            }
            args.push("--".into());
            args.push(url.clone());
            args.push(tmp.display().to_string());
            println!("==> cloning {}", util::redact_url_creds(url));
            run_local("git", &args, None).await?;
            let ctx = confine_subpath(&tmp, cfg.build.context.as_deref().unwrap_or("."), "build.context")?;
            let df = confine_subpath(&ctx, cfg.build.dockerfile.as_deref().unwrap_or("Dockerfile"), "build.dockerfile")?;
            (ctx, df)
        }
        None => {
            let ctx = base.join(cfg.build.context.as_deref().unwrap_or("."));
            let df = ctx.join(cfg.build.dockerfile.as_deref().unwrap_or("Dockerfile"));
            (ctx, df)
        }
    };
    let mut args: Vec<String> = vec![
        "buildx".into(),
        "build".into(),
        "--platform".into(),
        t.platform.clone(),
        "-f".into(),
        dockerfile.display().to_string(),
        "-t".into(),
        image.clone(),
        "-t".into(),
        format!("{repo}:latest"),
        "--cache-from".into(),
        format!("{repo}:latest"),
        "--build-arg".into(),
        "BUILDKIT_INLINE_CACHE=1".into(),
        "--push".into(),
        "--provenance=false".into(),
    ];
    if let Some(tg) = &cfg.build.target {
        args.push("--target".into());
        args.push(tg.clone());
    }
    for (k, v) in &cfg.build.args {
        args.push("--build-arg".into());
        args.push(format!("{k}={v}"));
    }
    args.push(ctx.display().to_string());
    println!("==> building {image} ({}) with local Docker", t.platform);
    let res = run_local("docker", &args, None).await;
    drop(_git_guard);
    res.context("docker build/push failed (is Docker running, and are you logged in to the registry?)")?;
    Ok(image)
}

// ---------------------------------------------------------------------------
// commands

async fn kube_for(t: &K8sTarget) -> Kube {
    Kube { t: t.clone() }
}

async fn apply_docs(k: &Kube, cfg: &AppConfig, image: &str, version: u64) -> Result<Vec<Value>> {
    let docs = render(cfg, image, version, &k.t);
    k.apply(&to_yaml(&docs)?).await?;
    Ok(docs)
}

async fn prune_stale(k: &Kube, old: &[Value], cur: &[Value]) {
    for (kind, name) in stale(old, cur) {
        let _ = k
            .run(&["delete", &kind.to_ascii_lowercase(), &name, "--ignore-not-found"])
            .await;
    }
}

async fn wait_rollout(k: &Kube, cfg: &AppConfig) -> Result<()> {
    let target = format!("{}/{}", workload_kind(cfg).to_ascii_lowercase(), cfg.app);
    let timeout = format!("--timeout={}s", cfg.deploy.health_timeout_secs().max(30) + 30);
    k.run(&["rollout", "status", &target, &timeout]).await.map(|_| ())
}

async fn print_urls(k: &Kube, cfg: &AppConfig) {
    let tls = k.t.cluster_issuer.is_some();
    for h in hosts(cfg, &k.t) {
        println!("  {}://{h}", if tls { "https" } else { "http" });
    }
    if cfg.ports.iter().any(|p| p.public) {
        if let Ok(v) = k.json(&["get", "service", &format!("{}-public", cfg.app)]).await {
            let ing = &v["status"]["loadBalancer"]["ingress"][0];
            let addr = ing["ip"].as_str().or(ing["hostname"].as_str()).unwrap_or("<pending>");
            for p in cfg.ports.iter().filter(|p| p.public) {
                println!("  {}://{addr}:{}", p.protocol, p.public_port.unwrap_or(p.port));
            }
        }
    }
    let ports = cfg.container_ports();
    if let Some(p) = ports.first() {
        println!("  internal: {}:{p} (or {}.{}.svc.cluster.local)", cfg.app, cfg.app, k.t.namespace);
    }
    if cfg.http.is_some() && hosts(cfg, &k.t).is_empty() {
        println!("  (no domains: add [http] domains, or try `kubectl port-forward svc/{} 8080:{}`)", cfg.app, ports[0]);
    }
}

/// Deploy one app to Kubernetes. Rolls back automatically if the rollout fails.
pub async fn deploy(t: &K8sTarget, cfg: &AppConfig, base: &Path, message: Option<String>) -> Result<()> {
    cfg.validate()?;
    let k = kube_for(t).await;
    println!("==> Deploying {} to Kubernetes (namespace {})", cfg.app, t.namespace);
    if cfg.container_ports().is_empty() {
        println!(
            "    note: no [http] or [[ports]] declared, so no Service is created and other apps \
             can't reach it (Kubernetes can't discover the image's EXPOSE ports)"
        );
    }
    let image = match &cfg.build.image {
        Some(i) => i.clone(),
        None => build_and_push(cfg, base, t).await?,
    };
    release(&k, cfg.clone(), image, message.unwrap_or_else(|| "deploy".into())).await
}

async fn release(k: &Kube, cfg: AppConfig, image: String, description: String) -> Result<()> {
    let mut hist = load_history(k, &cfg.app).await?;
    let prev = current(&hist).cloned();
    let prev_docs = prev
        .as_ref()
        .map(|p| render(&p.config, &p.image, p.version, &k.t));
    let version = hist.iter().map(|r| r.version).max().unwrap_or(0) + 1;
    hist.push(K8sRelease {
        version,
        image: image.clone(),
        config: cfg.clone(),
        created_at: now(),
        status: "deploying".into(),
        description,
    });
    save_history(k, &cfg, hist.clone()).await?;
    let new_docs = match apply_docs(k, &cfg, &image, version).await {
        Ok(docs) => docs,
        Err(e) => {
            for r in hist.iter_mut().filter(|r| r.version == version) {
                r.status = "failed".into();
            }
            let _ = save_history(k, &cfg, hist).await;
            return Err(e);
        }
    };
    println!("==> Release v{version} applied, waiting for the rollout");
    let ok = wait_rollout(k, &cfg).await;
    for r in hist.iter_mut() {
        if r.version == version {
            r.status = if ok.is_ok() { "active".into() } else { "failed".into() };
        } else if ok.is_ok() && r.status == "active" {
            r.status = "superseded".into();
        }
    }
    save_history(k, &cfg, hist).await?;
    match ok {
        Ok(()) => {
            if let Some(old) = &prev_docs {
                prune_stale(k, old, &new_docs).await;
            }
            println!("\n✓ {} v{version} is live", cfg.app);
            print_urls(k, &cfg).await;
            Ok(())
        }
        Err(e) => {
            if let Some(p) = prev {
                println!("==> rollout failed, rolling back to v{}", p.version);
                let restored = apply_docs(k, &p.config, &p.image, p.version).await?;
                prune_stale(k, &new_docs, &restored).await;
                let _ = wait_rollout(k, &p.config).await;
            }
            bail!("release v{version} did not become ready ({e:#}).\n  See what happened: latrix logs {}", cfg.app)
        }
    }
}

async fn workload(k: &Kube, app: &str) -> Result<(K8sRelease, String)> {
    let hist = load_history(k, app).await?;
    let cur = current(&hist)
        .or_else(|| hist.iter().max_by_key(|r| r.version))
        .cloned()
        .ok_or_else(|| anyhow!("app '{app}' not found in namespace {}", k.t.namespace))?;
    let kind = workload_kind(&cur.config).to_ascii_lowercase();
    Ok((cur, format!("{kind}/{app}")))
}

fn pod_rows(pods: &Value) -> Vec<Vec<String>> {
    pods["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|p| {
            let cs = &p["status"]["containerStatuses"][0];
            let started = p["status"]["startTime"].as_str().unwrap_or("");
            vec![
                p["metadata"]["name"].as_str().unwrap_or("").to_string(),
                p["metadata"]["annotations"]["latrix.dev/release"].as_str().map(|v| format!("v{v}")).unwrap_or_default(),
                p["spec"]["nodeName"].as_str().unwrap_or("-").to_string(),
                p["status"]["phase"].as_str().unwrap_or("").to_lowercase(),
                if cs["ready"].as_bool().unwrap_or(false) { "✓".into() } else { "✗".into() },
                cs["restartCount"].as_u64().unwrap_or(0).to_string(),
                started.to_string(),
            ]
        })
        .collect()
}

pub async fn status(name: &str, t: &K8sTarget) -> Result<()> {
    let k = kube_for(t).await;
    let nodes = k.json(&["get", "nodes"]).await?;
    let node_list = nodes["items"].as_array().cloned().unwrap_or_default();
    println!(
        "Cluster '{name}' · Kubernetes ({}) · namespace {} · {} node(s)\n",
        t.context.as_deref().unwrap_or("current context"),
        t.namespace,
        node_list.len()
    );
    print_nodes(&nodes);
    println!("\nAPPS");
    let cms = k.json(&["get", "configmap", "-l", MANAGED]).await?;
    let workloads = k.json(&["get", "deployments,statefulsets", "-l", MANAGED]).await?;
    let mut rows = vec![];
    for cm in cms["items"].as_array().cloned().unwrap_or_default() {
        let Some(app) = cm["metadata"]["labels"]["app.kubernetes.io/name"].as_str() else { continue };
        let hist: Vec<K8sRelease> = cm["data"]["releases.json"]
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();
        let Some(cur) = current(&hist).or_else(|| hist.iter().max_by_key(|r| r.version)) else { continue };
        let w = workloads["items"]
            .as_array()
            .and_then(|a| a.iter().find(|w| w["metadata"]["name"] == app).cloned())
            .unwrap_or_default();
        let ready = w["status"]["readyReplicas"].as_u64().unwrap_or(0);
        let want = w["spec"]["replicas"].as_u64().unwrap_or(0);
        rows.push(vec![
            app.to_string(),
            format!("v{} {}", cur.version, cur.status),
            format!("{ready}/{want}"),
            workload_kind(&cur.config).to_string(),
            hosts(&cur.config, t).first().cloned().unwrap_or_else(|| {
                cur.config
                    .container_ports()
                    .first()
                    .map(|p| format!("{app}:{p}"))
                    .unwrap_or_else(|| "-".into())
            }),
        ]);
    }
    if rows.is_empty() {
        println!("  (none yet — `latrix deploy`)");
    } else {
        print_table(&["NAME", "RELEASE", "READY", "KIND", "ADDRESS"], rows);
    }
    Ok(())
}

fn print_nodes(nodes: &Value) {
    let rows = nodes["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|n| {
            let ready = n["status"]["conditions"]
                .as_array()
                .and_then(|c| c.iter().find(|c| c["type"] == "Ready"))
                .map(|c| c["status"] == "True")
                .unwrap_or(false);
            let cordoned = n["spec"]["unschedulable"].as_bool().unwrap_or(false);
            vec![
                n["metadata"]["name"].as_str().unwrap_or("").to_string(),
                if !ready { "NOT READY".into() } else if cordoned { "cordoned".into() } else { "ready".into() },
                n["status"]["capacity"]["cpu"].as_str().unwrap_or("").to_string(),
                n["status"]["capacity"]["memory"].as_str().unwrap_or("").to_string(),
                n["status"]["nodeInfo"]["kubeletVersion"].as_str().unwrap_or("").to_string(),
                n["status"]["nodeInfo"]["osImage"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    print_table(&["NODE", "STATUS", "CPU", "MEMORY", "KUBELET", "OS"], rows);
}

async fn ps(k: &Kube, app: &str) -> Result<()> {
    let (cur, _) = workload(k, app).await?;
    let c = &cur.config;
    println!(
        "{app} · v{} ({}) · {} · {} CPU · {}",
        cur.version,
        cur.status,
        workload_kind(c),
        c.scale.cpu,
        c.scale.memory
    );
    print_urls(k, c).await;
    println!();
    let pods = k
        .json(&["get", "pods", "-l", &format!("app.kubernetes.io/name={app},{MANAGED}")])
        .await?;
    print_table(&["POD", "REL", "NODE", "PHASE", "READY", "RESTARTS", "STARTED"], pod_rows(&pods));
    println!();
    print_history(&load_history(k, app).await?);
    Ok(())
}

fn print_history(h: &[K8sRelease]) {
    let mut h = h.to_vec();
    h.sort_by_key(|r| std::cmp::Reverse(r.version));
    let rows = h
        .iter()
        .map(|r| vec![format!("v{}", r.version), r.status.clone(), ago(r.created_at), r.description.clone(), r.image.clone()])
        .collect();
    print_table(&["VERSION", "STATUS", "CREATED", "DESCRIPTION", "IMAGE"], rows);
}

async fn get_secret(k: &Kube, app: &str) -> Result<(BTreeMap<String, String>, Option<String>)> {
    use base64::Engine;
    let v = match k.json(&["get", "secret", &format!("{app}-secrets")]).await {
        Ok(v) => v,
        Err(e) if e.to_string().contains("NotFound") || e.to_string().contains("not found") => {
            return Ok((BTreeMap::new(), None))
        }
        Err(e) => return Err(e),
    };
    let rv = v["metadata"]["resourceVersion"].as_str().map(String::from);
    let mut out = BTreeMap::new();
    for (key, val) in v["data"].as_object().cloned().unwrap_or_default() {
        let encoded = val
            .as_str()
            .ok_or_else(|| anyhow!("secret key '{key}' in {app}-secrets is not a string"))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .with_context(|| format!("decoding base64 secret '{key}' in {app}-secrets"))?;
        let decoded = String::from_utf8(raw)
            .with_context(|| format!("secret '{key}' in {app}-secrets is not valid UTF-8"))?;
        out.insert(key, decoded);
    }
    Ok((out, rv))
}

fn validate_secret_key(key: &str) -> Result<()> {
    if key.is_empty()
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        bail!("invalid secret key '{key}' (use letters, digits, '_', '-', or '.')");
    }
    Ok(())
}

/// Commands on a Kubernetes target.
pub async fn dispatch(cfg: &CliConfig, name: &str, t: K8sTarget, cmd: Cmd) -> Result<()> {
    let k = kube_for(&t).await;
    match cmd {
        Cmd::Deploy(args) => {
            if let Some(file) = &args.compose {
                let mut failed = vec![];
                for a in compose::convert(file)? {
                    for w in &a.warnings {
                        println!("warning ({}): {w}", a.config.app);
                    }
                    if let Err(e) = deploy(&t, &a.config, &a.base, args.message.clone()).await {
                        println!("✗ {}: {e:#}", a.config.app);
                        failed.push(a.config.app.clone());
                    }
                }
                if !failed.is_empty() {
                    bail!("{} service(s) failed: {}", failed.len(), failed.join(", "));
                }
                return Ok(());
            }
            let (app, base) = super::commands::load_app_for_deploy(&args)?;
            deploy(&t, &app, &base, args.message).await
        }
        Cmd::Status => status(name, &t).await,
        Cmd::Apps { action: None | Some(AppsCmd::List { .. }), .. } => status(name, &t).await,
        Cmd::Apps { action: Some(AppsCmd::Show { app }), .. } => {
            util::validate_name("app", &app)?;
            ps(&k, &app).await
        }
        Cmd::Apps { action: Some(AppsCmd::Destroy(a)), .. } => destroy(&k, &t, a).await,
        Cmd::Ps { app } => {
            util::validate_name("app", &app)?;
            ps(&k, &app).await
        }
        Cmd::Releases { app } => {
            util::validate_name("app", &app)?;
            print_history(&load_history(&k, &app).await?);
            Ok(())
        }
        Cmd::Logs { app, follow, tail, instance } => {
            util::validate_name("app", &app)?;
            let tail = format!("--tail={tail}");
            let target = match &instance {
                Some(pod) => {
                    util::validate_name("instance", pod)?;
                    vec![pod.clone()]
                }
                None => vec![
                    "-l".into(),
                    format!("app.kubernetes.io/name={app},{MANAGED}"),
                    "--prefix".into(),
                    "--max-log-requests=50".into(),
                ],
            };
            let mut a: Vec<String> = vec!["logs".into(), tail, "--timestamps".into()];
            a.extend(target);
            if follow {
                a.push("-f".into());
            }
            let refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
            k.interactive(&refs)?;
            Ok(())
        }
        Cmd::Scale { app, count, min, max, cpu, memory } => {
            util::validate_name("app", &app)?;
            if count.is_none() && min.is_none() && max.is_none() && cpu.is_none() && memory.is_none() {
                bail!("specify at least one of --count, --min, --max, --cpu, or --memory");
            }
            let (cur, _) = workload(&k, &app).await?;
            let mut c = cur.config.clone();
            if let Some(n) = count {
                c.scale.count = Some(n);
                if min.is_none() && max.is_none() {
                    c.scale.min = None;
                    c.scale.max = None;
                }
            }
            if min.is_some() {
                c.scale.min = min;
            }
            if max.is_some() {
                c.scale.max = max;
            }
            let restart = cpu.is_some() || memory.is_some();
            if let Some(x) = cpu {
                if !x.is_finite() || x < 0.0 {
                    bail!("--cpu must be a finite non-negative number");
                }
                c.scale.cpu = x;
            }
            if let Some(m) = memory {
                c.scale.memory = m;
            }
            if c.stateful() && c.scale.bounds().1 > 1 {
                bail!("apps with volumes run a single instance (count 0 or 1)");
            }
            c.validate()?;
            if restart {
                release(&k, c, cur.image, "scale (resources)".into()).await
            } else {
                // Same release: only replica counts change, pods are not restarted.
                let old_docs = render(&cur.config, &cur.image, cur.version, &k.t);
                let new_docs = apply_docs(&k, &c, &cur.image, cur.version).await?;
                prune_stale(&k, &old_docs, &new_docs).await;
                let mut hist = load_history(&k, &app).await?;
                for r in hist.iter_mut().filter(|r| r.version == cur.version) {
                    r.config = c.clone();
                }
                save_history(&k, &c, hist).await?;
                let (lo, hi) = c.scale.bounds();
                if c.scale.autoscale() {
                    println!("{app}: autoscaling between {lo} and {hi}");
                } else {
                    println!("{app}: {lo} instance(s)");
                }
                Ok(())
            }
        }
        Cmd::Restart { app } => {
            util::validate_name("app", &app)?;
            let (cur, _) = workload(&k, &app).await?;
            release(&k, cur.config, cur.image, "restart".into()).await
        }
        Cmd::Rollback { app, version } => {
            util::validate_name("app", &app)?;
            let hist = load_history(&k, &app).await?;
            let active_ver = current(&hist).map(|r| r.version);
            let target = match version {
                Some(v) => hist
                    .iter()
                    .find(|r| r.version == v)
                    .cloned()
                    .ok_or_else(|| anyhow!("release v{v} not found"))?,
                None => match active_ver {
                    Some(cur) => hist
                        .iter()
                        .filter(|r| r.version < cur && r.status != "failed")
                        .max_by_key(|r| r.version)
                        .cloned()
                        .ok_or_else(|| anyhow!("no earlier release to roll back to"))?,
                    None => hist
                        .iter()
                        .filter(|r| r.status != "failed")
                        .max_by_key(|r| r.version)
                        .cloned()
                        .ok_or_else(|| anyhow!("no successful release to roll back to"))?,
                },
            };
            release(&k, target.config, target.image, format!("rollback to v{}", target.version)).await
        }
        Cmd::Destroy(a) => destroy(&k, &t, a).await,
        Cmd::Secrets(s) => {
            use base64::Engine;
            let (app, set, unset, list) = match s {
                SecretsCmd::Set { app, pairs } => {
                    let mut m = BTreeMap::new();
                    for p in pairs {
                        let (a, b) = p.split_once('=').ok_or_else(|| anyhow!("expected KEY=value, got '{p}'"))?;
                        validate_secret_key(a)?;
                        m.insert(a.to_string(), b.to_string());
                    }
                    (app, m, vec![], false)
                }
                SecretsCmd::Unset { app, names } => (app, BTreeMap::new(), names, false),
                SecretsCmd::List { app } => (app, BTreeMap::new(), vec![], true),
            };
            util::validate_name("app", &app)?;
            let (cur, w) = workload(&k, &app).await?;
            let (mut secrets, resource_version) = get_secret(&k, &app).await?;
            if list {
                for key in secrets.keys() {
                    println!("{key}");
                }
                return Ok(());
            }
            secrets.extend(set);
            for u in unset {
                secrets.remove(&u);
            }
            let encoded: BTreeMap<String, String> = secrets
                .into_iter()
                .map(|(k, v)| (k, base64::engine::general_purpose::STANDARD.encode(v.as_bytes())))
                .collect();
            let mut meta = json!({
                "name": format!("{app}-secrets"),
                "labels": labels(&cur.config),
            });
            if let Some(rv) = &resource_version {
                meta["resourceVersion"] = json!(rv);
            }
            let doc = json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": meta,
                "type": "Opaque",
                "data": encoded,
            });
            let yaml = to_yaml(&[doc])?;
            // Atomically create or replace (never delete-then-apply, and never embed plaintext
            // secrets in `kubectl.kubernetes.io/last-applied-configuration`).
            if resource_version.is_some() {
                k.exec(&["replace", "-f", "-"], Some(&yaml), true).await?;
            } else {
                k.exec(&["create", "-f", "-"], Some(&yaml), true).await?;
            }
            k.run(&["rollout", "restart", &w]).await?;
            println!("secrets updated; restarting {app}");
            k.run(&["rollout", "status", &w, "--timeout=300s"]).await.map(|_| ())
        }
        Cmd::Console { app, cmd } => {
            util::validate_name("app", &app)?;
            let (_, w) = workload(&k, &app).await?;
            let mut a = vec!["exec".to_string(), "-it".into(), w, "--".into()];
            if cmd.is_empty() {
                a.push("sh".into());
            } else {
                a.extend(cmd);
            }
            let refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
            let st = k.interactive(&refs)?;
            std::process::exit(st.code().unwrap_or(1));
        }
        Cmd::Volumes { .. } => {
            let out = k.run(&["get", "pvc", "-l", MANAGED]).await?;
            print!("{}", if out.trim().is_empty() { "no volumes\n".to_string() } else { out });
            Ok(())
        }
        Cmd::Certs { .. } => {
            match k.run(&["get", "certificates"]).await {
                Ok(out) => print!("{out}"),
                Err(_) => println!("cert-manager is not installed. Set up HTTPS with `latrix k8s setup-tls --email you@example.com`"),
            }
            Ok(())
        }
        Cmd::Events { .. } => {
            print!("{}", k.run(&["get", "events", "--sort-by=.lastTimestamp"]).await?);
            Ok(())
        }
        Cmd::Machine(MachineCmd::List) => {
            print_nodes(&k.json(&["get", "nodes"]).await?);
            Ok(())
        }
        Cmd::Machine(_) => bail!(
            "'{name}' is a Kubernetes cluster: its nodes are managed by Kubernetes / your provider. \
             `latrix machine list` shows them."
        ),
        Cmd::Upgrade { .. } | Cmd::Settings { .. } | Cmd::Dashboard { .. } | Cmd::Dns { .. } => bail!(
            "this command is for latrix's own clusters; '{name}' is a Kubernetes target (try `latrix status`, or your usual Kubernetes tools)"
        ),
        _ => {
            let _ = cfg;
            bail!("not supported for Kubernetes targets")
        }
    }
}

async fn destroy(k: &Kube, t: &K8sTarget, a: DestroyArgs) -> Result<()> {
    let app = a.app.clone();
    util::validate_name("app", &app)?;
    let purge = !a.keep_volumes;
    if !a.yes {
        print!(
            "Destroy app '{app}' in namespace {}{}? Type the app name to confirm: ",
            t.namespace,
            if purge { " and DELETE its volumes" } else { " (keeping its volumes)" }
        );
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim() != app {
            bail!("aborted");
        }
    }
    let sel = format!("app.kubernetes.io/name={app},{MANAGED}");
    k.run(&["delete", "deployment,statefulset,service,ingress,hpa,configmap,secret", "-l", &sel, "--ignore-not-found"]).await?;
    if purge {
        k.run(&["delete", "pvc", "-l", &sel, "--ignore-not-found"]).await?;
    }
    println!("destroyed {app}{}", if purge { "" } else { " (PersistentVolumeClaims kept)" });
    Ok(())
}

// ---------------------------------------------------------------------------
// `latrix k8s ...`

pub async fn k8s_cmd(cl: Option<&str>, c: K8sCmd) -> Result<()> {
    let mut cfg = CliConfig::load()?;
    match c {
        K8sCmd::Add { name, context, kubeconfig, namespace, registry, ingress_class, storage_class, platform, base_domain } => {
            util::validate_name("cluster", &name)?;
            let t = K8sTarget {
                context,
                kubeconfig,
                namespace,
                registry,
                ingress_class,
                cluster_issuer: cfg.clusters.get(&name).and_then(|p| p.kubernetes.as_ref()).and_then(|k| k.cluster_issuer.clone()),
                storage_class,
                platform,
                base_domain,
            };
            let k = Kube { t: t.clone() };
            let nodes = k.json(&["get", "nodes"]).await.context("cannot reach the Kubernetes cluster with kubectl")?;
            let n = nodes["items"].as_array().map(|a| a.len()).unwrap_or(0);
            if k.run_global(&["get", "namespace", &t.namespace]).await.is_err() {
                k.run_global(&["create", "namespace", &t.namespace]).await?;
                println!("created namespace {}", t.namespace);
            }
            if let Some(existing) = cfg.clusters.get(&name) {
                if existing.kubernetes.is_none() {
                    bail!("'{name}' is already a latrix cluster; pick another name");
                }
            }
            cfg.clusters.insert(
                name.clone(),
                ClusterProfile { token: String::new(), local: false, machines: vec![], default_key: None, kubernetes: Some(t.clone()) },
            );
            if cfg.current.is_none() {
                cfg.current = Some(name.clone());
            }
            cfg.save()?;
            println!("✓ added Kubernetes cluster '{name}' ({n} node(s), namespace {})", t.namespace);
            if t.registry.is_none() {
                println!("  note: to build images (not just deploy prebuilt ones) add --registry ghcr.io/<you>");
            }
            println!("  deploy with: latrix --cluster {name} deploy   (or `latrix cluster use {name}`)");
            println!("  HTTPS:       latrix --cluster {name} k8s setup-tls --email you@example.com");
            Ok(())
        }
        K8sCmd::Export { config, compose, image } => {
            let t = cfg
                .profile(cl)
                .ok()
                .and_then(|(_, p)| p.kubernetes)
                .unwrap_or_else(|| K8sTarget {
                    namespace: super::profile::default_namespace(),
                    platform: super::profile::default_platform(),
                    ..Default::default()
                });
            let apps: Vec<AppConfig> = match compose {
                Some(f) => compose::convert(&f)?.into_iter().map(|c| c.config).collect(),
                None => vec![AppConfig::load(&config)?],
            };
            for a in apps {
                let img = image
                    .clone()
                    .or_else(|| a.build.image.clone())
                    .unwrap_or_else(|| format!("{}/{}:latest", t.registry.as_deref().unwrap_or("REGISTRY"), a.app));
                print!("{}", to_yaml(&render(&a, &img, 1, &t))?);
            }
            Ok(())
        }
        K8sCmd::SetupTls { email, issuer } => {
            let (name, mut p) = cfg.profile(cl)?;
            let mut t = p.kubernetes.clone().ok_or_else(|| anyhow!("'{name}' is not a Kubernetes target (see `latrix k8s add`)"))?;
            let k = Kube { t: t.clone() };
            if k.run_global(&["get", "crd", "clusterissuers.cert-manager.io"]).await.is_err() {
                println!("==> installing cert-manager");
                k.run_global(&["apply", "-f", CERT_MANAGER_URL]).await?;
                println!("==> waiting for cert-manager to start");
                k.run_global(&["-n", "cert-manager", "wait", "--for=condition=Available", "deployment", "--all", "--timeout=300s"]).await?;
            } else {
                println!("==> cert-manager already installed");
            }
            let mut solver = json!({"http01": {"ingress": {}}});
            if let Some(c) = &t.ingress_class {
                solver["http01"]["ingress"]["ingressClassName"] = json!(c);
            }
            let ci = json!({
                "apiVersion": "cert-manager.io/v1", "kind": "ClusterIssuer",
                "metadata": {"name": issuer},
                "spec": {"acme": {
                    "server": "https://acme-v02.api.letsencrypt.org/directory",
                    "email": email,
                    "privateKeySecretRef": {"name": format!("{issuer}-account")},
                    "solvers": [solver],
                }},
            });
            // The webhook may need a few seconds after becoming Available.
            let yaml = to_yaml(&[ci])?;
            let mut last = None;
            for _ in 0..12 {
                match k.exec(&["apply", "-f", "-"], Some(&yaml), false).await {
                    Ok(_) => {
                        last = None;
                        break;
                    }
                    Err(e) => {
                        last = Some(e);
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
            if let Some(e) = last {
                return Err(e);
            }
            t.cluster_issuer = Some(issuer.clone());
            p.kubernetes = Some(t);
            cfg.clusters.insert(name.clone(), p);
            cfg.save()?;
            println!("✓ HTTPS ready: apps with [http] domains get Let's Encrypt certificates (issuer '{issuer}').");
            println!("  Redeploy existing apps to add TLS to their Ingress. Your cluster needs an ingress controller.");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> K8sTarget {
        K8sTarget {
            namespace: "default".into(),
            platform: "linux/amd64".into(),
            cluster_issuer: Some("letsencrypt".into()),
            ingress_class: Some("traefik".into()),
            ..Default::default()
        }
    }

    fn kinds(docs: &[Value]) -> Vec<(String, String)> {
        docs.iter().map(kind_name).collect()
    }

    #[test]
    fn web_app() {
        let cfg: AppConfig = toml::from_str(
            "app = \"web\"\n[http]\nport = 3000\ndomains = [\"web.example.com\"]\nhealth = \"/healthz\"\n[scale]\ncount = 3\n",
        )
        .unwrap();
        let docs = render(&cfg, "img:1", 4, &target());
        let k = kinds(&docs);
        assert!(k.contains(&("Deployment".into(), "web".into())));
        assert!(k.contains(&("Service".into(), "web".into())));
        assert!(k.contains(&("Ingress".into(), "web".into())));
        assert!(!k.iter().any(|(kind, _)| kind == "HorizontalPodAutoscaler"));
        let d = &docs[0];
        assert_eq!(d["spec"]["replicas"], 3);
        assert_eq!(d["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["path"], "/healthz");
        assert_eq!(d["spec"]["template"]["metadata"]["annotations"]["latrix.dev/release"], "4");
        let ing = docs.iter().find(|d| d["kind"] == "Ingress").unwrap();
        assert_eq!(ing["spec"]["tls"][0]["secretName"], "web-tls");
        assert_eq!(ing["spec"]["ingressClassName"], "traefik");
        // round-trips through YAML
        let y = to_yaml(&docs).unwrap();
        assert!(y.contains("kind: Deployment"));
    }

    #[test]
    fn stateful_autoscale_and_compose_names() {
        let cfg: AppConfig = toml::from_str(
            "app = \"shop-db\"\ngroup = \"shop\"\nservice = \"db\"\n[[ports]]\nport = 5432\n[[volumes]]\nname = \"data\"\npath = \"/var/lib/postgresql/data\"\nsize = \"20GB\"\n",
        )
        .unwrap();
        cfg.validate().unwrap();
        let docs = render(&cfg, "postgres:16", 1, &target());
        let k = kinds(&docs);
        assert!(k.contains(&("StatefulSet".into(), "shop-db".into())));
        assert!(k.contains(&("Service".into(), "db".into())), "short compose name");
        let sts = &docs[0];
        assert_eq!(sts["spec"]["volumeClaimTemplates"][0]["spec"]["resources"]["requests"]["storage"], "20480Mi");

        let auto: AppConfig = toml::from_str("app = \"api\"\n[http]\nport = 80\n[scale]\nmin = 2\nmax = 5\n").unwrap();
        let docs = render(&auto, "img", 1, &target());
        assert!(docs[0]["spec"].get("replicas").is_none(), "HPA owns replicas");
        let hpa = docs.iter().find(|d| d["kind"] == "HorizontalPodAutoscaler").unwrap();
        assert_eq!(hpa["spec"]["minReplicas"], 2);
        assert_eq!(hpa["spec"]["maxReplicas"], 5);
    }

    #[test]
    fn stale_objects_are_pruned() {
        let a: AppConfig = toml::from_str("app = \"x\"\n[http]\nport = 80\ndomains = [\"x.com\"]\n[[ports]]\nport = 25\npublic = true\n").unwrap();
        let b: AppConfig = toml::from_str("app = \"x\"\n[http]\nport = 80\n").unwrap();
        let s = stale(&render(&a, "i", 1, &target()), &render(&b, "i", 2, &target()));
        assert!(s.contains(&("Ingress".into(), "x".into())));
        assert!(s.contains(&("Service".into(), "x-public".into())));
        assert!(!s.contains(&("Deployment".into(), "x".into())));
    }

    #[test]
    fn env_dollar_escaping_headless_service_and_stateful_no_hpa() {
        let cfg: AppConfig = toml::from_str(
            r#"
app = "db"
[env]
PASS = "p$ss$(VAR)"
[scale]
min = 1
max = 3
[[ports]]
port = 5432
[[volumes]]
name = "data"
path = "/data"
"#,
        )
        .unwrap();
        let docs = render(&cfg, "postgres:16", 1, &target());
        let k = kinds(&docs);
        assert!(k.contains(&("StatefulSet".into(), "db".into())));
        assert!(k.contains(&("Service".into(), "db-headless".into())));
        assert!(!k.iter().any(|(kind, _)| kind == "HorizontalPodAutoscaler"), "stateful app must not get HPA");

        let headless = docs.iter().find(|d| d["metadata"]["name"] == "db-headless").unwrap();
        assert_eq!(headless["spec"]["clusterIP"], "None");

        let sts = &docs[0];
        let env = sts["spec"]["template"]["spec"]["containers"][0]["env"].as_array().unwrap();
        let pass = env.iter().find(|e| e["name"] == "PASS").unwrap();
        assert_eq!(pass["value"], "p$$ss$$(VAR)");
    }
}
