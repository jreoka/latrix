//! Thin wrapper around the system `ssh` / `scp` so your existing keys,
//! agent and ~/.ssh/config just work.

use crate::util::{shell_quote, validate_ssh_target};
use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Clone)]
pub struct Ssh {
    pub target: String,
    pub port: u16,
    pub key: Option<String>,
    /// Separate known_hosts file (the agent uses its own).
    pub known_hosts: Option<String>,
}

impl Ssh {
    pub fn new(target: &str, port: u16, key: Option<String>) -> Ssh {
        let target = if target.contains('@') { target.to_string() } else { format!("root@{target}") };
        Ssh { target, port, key, known_hosts: None }
    }

    /// Forget any old host key for this host (cloud IPs get reused by new servers).
    pub fn forget_host_key(&self) {
        let host = self.host();
        if host.is_empty() || host.starts_with('-') || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return;
        }
        let host_entry = if self.port != 22 {
            format!("[{host}]:{}", self.port)
        } else {
            host.to_string()
        };
        let mut cmd = std::process::Command::new("ssh-keygen");
        cmd.arg("-R").arg(&host_entry);
        if let Some(f) = &self.known_hosts {
            cmd.arg("-f").arg(f);
        }
        let _ = cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
    }

    pub fn host(&self) -> &str {
        self.target.split_once('@').map(|(_, h)| h).unwrap_or(&self.target)
    }

    pub fn is_root(&self) -> bool {
        self.target.starts_with("root@")
    }

    pub fn common_args(&self) -> Vec<String> {
        let mut a = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=15".into(),
            "-o".into(),
            "ServerAliveInterval=15".into(),
        ];
        if let Some(k) = &self.key {
            a.push("-i".into());
            a.push(k.clone());
        }
        if let Some(f) = &self.known_hosts {
            a.push("-o".into());
            a.push(format!("UserKnownHostsFile={f}"));
        }
        a
    }

    fn ssh_args(&self) -> Result<Vec<String>> {
        validate_ssh_target(&self.target)?;
        let mut a = vec!["-p".to_string(), self.port.to_string()];
        a.extend(self.common_args());
        a.push("--".into());
        a.push(self.target.clone());
        Ok(a)
    }

    /// Wrap a command so it runs as root.
    pub fn root_cmd(&self, cmd: &str) -> String {
        if self.is_root() {
            cmd.to_string()
        } else {
            format!("sudo -n sh -c {}", shell_quote(cmd))
        }
    }

    pub async fn run(&self, cmd: &str) -> Result<String> {
        self.run_input(cmd, None).await
    }

    pub async fn run_input(&self, cmd: &str, input: Option<&[u8]>) -> Result<String> {
        let mut args = self.ssh_args()?;
        args.push(self.root_cmd(cmd));
        let mut child = tokio::process::Command::new("ssh")
            .args(&args)
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("could not run `ssh` — is OpenSSH installed?")?;
        let writer = input.map(|data| {
            let mut stdin = child.stdin.take().unwrap();
            let owned = data.to_vec();
            tokio::spawn(async move {
                let res = stdin.write_all(&owned).await;
                let _ = stdin.shutdown().await;
                res
            })
        });
        let out = child.wait_with_output().await?;
        if let Some(w) = writer {
            if let Ok(Err(e)) = w.await {
                if e.kind() != std::io::ErrorKind::BrokenPipe && out.status.success() {
                    return Err(e.into());
                }
            }
        }
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let hint = if err.contains("sudo") && err.contains("password") {
                "\n  hint: the SSH user needs passwordless sudo (or use root@...)"
            } else if err.contains("Permission denied") {
                "\n  hint: make sure your SSH key is authorized on the machine (ssh-copy-id), or pass --key"
            } else {
                ""
            };
            bail!("ssh {}: {}{hint}", self.target, err.trim());
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Run a script (stdin) and print its output indented as it arrives.
    pub async fn stream_script(&self, script: &str, prefix: &str) -> Result<()> {
        let mut args = self.ssh_args()?;
        args.push(self.root_cmd("bash -s"));
        let mut child = tokio::process::Command::new("ssh")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().unwrap();
        let data = script.as_bytes().to_vec();
        let writer = tokio::spawn(async move {
            let res = stdin.write_all(&data).await;
            let _ = stdin.shutdown().await;
            res
        });
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        let p1 = prefix.to_string();
        let p2 = prefix.to_string();
        let a = tokio::spawn(async move {
            let mut l = BufReader::new(out).lines();
            while let Ok(Some(line)) = l.next_line().await {
                println!("{p1}{line}");
            }
        });
        let b = tokio::spawn(async move {
            let mut l = BufReader::new(err).lines();
            let mut tail = vec![];
            while let Ok(Some(line)) = l.next_line().await {
                if line.starts_with("[latrix]") {
                    println!("{p2}{line}");
                } else {
                    tail.push(line);
                    if tail.len() > 30 {
                        tail.remove(0);
                    }
                }
            }
            tail
        });
        let status = child.wait().await?;
        let _ = writer.await;
        let _ = a.await;
        let tail = b.await.unwrap_or_default();
        if !status.success() {
            bail!("setup script failed on {}:\n{}", self.target, tail.join("\n"));
        }
        Ok(())
    }

    pub async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        validate_ssh_target(&self.target)?;
        let scp_target = match self.target.split_once('@') {
            Some((u, h)) if h.contains(':') && !h.starts_with('[') => format!("{u}@[{h}]:{remote}"),
            None if self.target.contains(':') && !self.target.starts_with('[') => format!("[{}]:{remote}", self.target),
            _ => format!("{}:{remote}", self.target),
        };
        let mut args = vec!["-q".to_string(), "-P".into(), self.port.to_string()];
        args.extend(self.common_args());
        args.push("--".into());
        args.push(local.display().to_string());
        args.push(scp_target);
        let out = tokio::process::Command::new("scp")
            .args(&args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output()
            .await
            .context("could not run `scp`")?;
        if !out.status.success() {
            bail!("scp to {} failed: {}", self.target, String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }

    /// Interactive session (inherits the terminal, prompts allowed).
    pub fn interactive(&self, cmd: Option<&str>) -> Result<std::process::ExitStatus> {
        validate_ssh_target(&self.target)?;
        let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        let mut args = vec![
            if tty { "-t" } else { "-T" }.to_string(),
            "-p".into(),
            self.port.to_string(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
        ];
        if let Some(k) = &self.key {
            args.push("-i".into());
            args.push(k.clone());
        }
        args.push("--".into());
        args.push(self.target.clone());
        if let Some(c) = cmd {
            args.push(self.root_cmd(c));
        }
        Ok(std::process::Command::new("ssh").args(&args).status()?)
    }
}
