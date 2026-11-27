//! `latrix doctor` — checks every machine over SSH and explains problems.
//! Works even when the agent or the mesh is broken (it only needs SSH).

use super::client::Client;
use super::profile::CliConfig;
use super::ssh::Ssh;
use crate::api_types::StatusView;
use anyhow::{bail, Result};

const SCRIPT: &str = r#"
ov=$(grep -o '"overlay_ip": *"[^"]*"' /var/lib/latrix/node.json 2>/dev/null | cut -d'"' -f4)
check() { if sh -c "$2" >/dev/null 2>&1; then echo "CHECK|ok|$1|"; else echo "CHECK|fail|$1|$3"; fi; }
check "latrix agent running" "systemctl is-active --quiet latrix" "restart it: systemctl restart latrix   (logs: journalctl -u latrix -n 50)"
check "Docker running" "docker info" "start it: systemctl restart docker"
check "agent API answering" "curl -fsS -m 3 http://127.0.0.1:7470/v1/local/ping" "the agent is up but not answering; see journalctl -u latrix -n 50"
check "WireGuard interface latrix0" "ip link show latrix0" "the kernel could not create it: modprobe wireguard; then systemctl restart latrix"
check "mesh address $ov on latrix0" "ip -4 addr show dev latrix0 | grep -q 'inet $ov/'" "mesh setup failed; see the agent log lines below"
check "image registry running" "docker ps -q --filter name=latrix-registry --filter status=running | grep -q ." "it is restarted automatically within 30s; if not: docker logs latrix-registry"
check "registry on 127.0.0.1:7471 (builds push here)" "curl -fsS -m 3 http://127.0.0.1:7471/v2/" "wait 30s after upgrading, then run doctor again"
check "registry on $ov:7471 (other machines pull here)" "curl -fsS -m 3 http://$ov:7471/v2/" "needs the mesh address above"
check "Docker trusts the mesh registries" "docker info 2>/dev/null | grep -q '10.77.0.0/16'" "add \"insecure-registries\": [\"10.77.0.0/16\"] to /etc/docker/daemon.json, then systemctl restart docker"
check "free disk space above 2 GB" "[ \$(df -Pk /var/lib/latrix | awk 'NR==2{print \$4}') -gt 2097152 ]" "free some space: docker system prune"
echo "INFO|system|$(. /etc/os-release; echo $PRETTY_NAME), kernel $(uname -r)"
echo "INFO|docker|$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
echo "INFO|latrix|$(/usr/local/bin/latrix --version 2>/dev/null)"
echo "INFO|mesh peers|$(wg show latrix0 peers 2>/dev/null | wc -l)"
journalctl -u latrix -n 300 --no-pager -o cat 2>/dev/null | grep -E "WARN|ERROR" | sed 's/\x1b\[[0-9;]*m//g' | tail -6 | sed 's/^/LOG|/'
"#;

fn paint(ok: bool) -> &'static str {
    let color = super::deploy::tty_width().is_some();
    match (ok, color) {
        (true, true) => "\x1b[32m✓\x1b[0m",
        (false, true) => "\x1b[31m✗\x1b[0m",
        (true, false) => "ok ",
        (false, false) => "FAIL",
    }
}

pub async fn doctor(cfg: &CliConfig, cl: Option<&str>, only: Option<&str>) -> Result<()> {
    let (name, p) = cfg.profile(cl)?;
    if p.local {
        bail!("`latrix doctor` checks servers; the local cluster runs right here (see the `latrix dev` output)");
    }
    if p.kubernetes.is_some() {
        bail!("'{name}' is a Kubernetes target; use kubectl to inspect it");
    }
    let mut problems = 0;
    for m in p.machines.iter().filter(|m| only.map(|o| o == m.name).unwrap_or(true)) {
        println!("\n{} ({})", m.name, m.ssh);
        let ssh = Ssh::new(&m.ssh, m.port, m.key.clone());
        let out = match ssh.run_input("bash -s", Some(SCRIPT.as_bytes())).await {
            Ok(o) => o,
            Err(e) => {
                println!("  {} SSH: {e:#}", paint(false));
                problems += 1;
                continue;
            }
        };
        let mut logs = vec![];
        for line in out.lines() {
            let parts: Vec<&str> = line.splitn(4, '|').collect();
            match parts.as_slice() {
                ["CHECK", "ok", what, _] => println!("  {} {what}", paint(true)),
                ["CHECK", _, what, hint] => {
                    problems += 1;
                    println!("  {} {what}", paint(false));
                    if !hint.is_empty() {
                        println!("      → {hint}");
                    }
                }
                ["INFO", what, value, ..] => println!("    {what}: {value}"),
                ["LOG", rest @ ..] => logs.push(rest.join("|")),
                _ => {}
            }
        }
        if !logs.is_empty() {
            println!("    recent agent warnings:");
            for l in logs {
                println!("      {l}");
            }
        }
    }
    // Cluster-level view, if reachable.
    if let Ok(c) = Client::connect(&p).await {
        if let Ok(st) = c.get::<StatusView>("/v1/status").await {
            let down: Vec<String> = st.machines.iter().filter(|m| !m.alive).map(|m| m.machine.name.clone()).collect();
            println!(
                "\ncluster: leader {}, {} machine(s){}",
                st.leader
                    .and_then(|l| st.machines.iter().find(|m| m.machine.id == l))
                    .map(|m| m.machine.name.clone())
                    .unwrap_or_else(|| "none".into()),
                st.machines.len(),
                if down.is_empty() { String::new() } else { format!(", unreachable from the leader: {}", down.join(", ")) }
            );
            problems += down.len();
        }
    }
    println!();
    if problems == 0 {
        println!("{} everything looks healthy", paint(true));
    } else {
        println!("{} {problems} problem(s) found (see the hints above)", paint(false));
    }
    Ok(())
}
