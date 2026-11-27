//! API client. For remote clusters the CLI opens an SSH tunnel to any machine
//! (your SSH key is the only credential you need) and the agent there
//! forwards cluster requests to the leader.

use super::profile::{ClusterProfile, MachineSsh};
use super::ssh::Ssh;
use crate::api_types::ApiErrorBody;
use crate::util::API_PORT;
use anyhow::{anyhow, bail, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

pub struct Tunnel {
    child: Child,
    pub port: u16,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

impl Tunnel {
    pub fn open(m: &MachineSsh, local_port: Option<u16>) -> Result<Tunnel> {
        let port = match local_port {
            Some(0) => bail!("local port must be non-zero"),
            Some(p) => p,
            None => free_port()?,
        };
        let ssh = Ssh::new(&m.ssh, m.port, m.key.clone());
        crate::util::validate_ssh_target(&ssh.target)?;
        let mut args = vec![
            "-N".to_string(),
            "-o".into(),
            "ExitOnForwardFailure=yes".into(),
            // Fail fast so a dead machine doesn't stall every command.
            "-o".into(),
            "ConnectTimeout=6".into(),
            "-L".into(),
            format!("127.0.0.1:{port}:127.0.0.1:{API_PORT}"),
            "-p".into(),
            m.port.to_string(),
        ];
        args.extend(ssh.common_args());
        args.push("--".into());
        args.push(ssh.target.clone());
        let mut child = std::process::Command::new("ssh")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("could not run ssh: {e}"))?;
        let start = Instant::now();
        loop {
            if let Ok(Some(st)) = child.try_wait() {
                let mut err = String::new();
                if let Some(mut e) = child.stderr.take() {
                    use std::io::Read;
                    let _ = e.read_to_string(&mut err);
                }
                bail!("ssh tunnel to {} exited ({st}): {}", m.ssh, err.trim());
            }
            if std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(200),
            )
            .is_ok()
            {
                // Verify ssh is still alive (not an unrelated process already on `port`).
                if let Ok(Some(st)) = child.try_wait() {
                    let mut err = String::new();
                    if let Some(mut e) = child.stderr.take() {
                        use std::io::Read;
                        let _ = e.read_to_string(&mut err);
                    }
                    bail!("ssh tunnel to {} exited ({st}): {}", m.ssh, err.trim());
                }
                // Drain stderr in the background so verbose ssh messages can never fill the pipe buffer.
                if let Some(mut stderr) = child.stderr.take() {
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
                    });
                }
                return Ok(Tunnel { child, port });
            }
            if start.elapsed() > Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                bail!("timed out opening ssh tunnel to {}", m.ssh);
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    pub fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }
}

pub struct Client {
    pub base: String,
    /// Machine the tunnel goes through ("local" for the dev cluster).
    #[allow(dead_code)]
    pub via: String,
    token: String,
    pub http: reqwest::Client,
    _tunnel: Option<Tunnel>,
}

impl Client {
    pub async fn connect(p: &ClusterProfile) -> Result<Client> {
        let http = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        if p.local {
            let c = Client {
                base: format!("http://127.0.0.1:{API_PORT}"),
                via: "local".into(),
                token: p.token.clone(),
                http,
                _tunnel: None,
            };
            c.ping().await.map_err(|_| {
                anyhow!("the local cluster is not running — start it with `latrix dev` in another terminal")
            })?;
            return Ok(c);
        }
        if p.machines.is_empty() {
            bail!("this cluster has no machines yet — add one with `latrix machine add root@<ip>`");
        }
        let mut errors = vec![];
        for m in &p.machines {
            match Tunnel::open(m, None) {
                Ok(t) => {
                    let c = Client {
                        base: format!("http://127.0.0.1:{}", t.port),
                        via: m.name.clone(),
                        token: p.token.clone(),
                        http: http.clone(),
                        _tunnel: Some(t),
                    };
                    match c.ping().await {
                        Ok(()) => return Ok(c),
                        Err(e) => errors.push(format!("{}: agent not responding ({e})", m.name)),
                    }
                }
                Err(e) => errors.push(format!("{}: {e}", m.name)),
            }
        }
        bail!("could not reach any machine of the cluster:\n  {}", errors.join("\n  "))
    }

    async fn ping(&self) -> Result<()> {
        let r = self
            .http
            .get(format!("{}/v1/local/ping", self.base))
            .bearer_auth(&self.token)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if !r.status().is_success() {
            bail!("{}", r.status());
        }
        Ok(())
    }

    pub fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(&self.token)
    }

    async fn decode<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            if let Ok(e) = serde_json::from_str::<ApiErrorBody>(&text) {
                bail!("{}", e.error);
            }
            bail!("{status}: {}", text.trim());
        }
        serde_json::from_str(&text).map_err(|e| anyhow!("unexpected response ({e}): {}", text.chars().take(200).collect::<String>()))
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let r = self.request(reqwest::Method::GET, path).timeout(Duration::from_secs(30)).send().await?;
        Self::decode(r).await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        let r = self
            .request(reqwest::Method::POST, path)
            .timeout(Duration::from_secs(60))
            .json(body)
            .send()
            .await?;
        Self::decode(r).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let r = self.request(reqwest::Method::DELETE, path).timeout(Duration::from_secs(60)).send().await?;
        Self::decode(r).await
    }
}
