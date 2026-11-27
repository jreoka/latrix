//! Thin wrapper around the system `ssh` / `scp` so your existing keys,
//! agent and ~/.ssh/config just work.

use crate::util::shell_quote;
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Clone)]
pub struct Ssh {
    pub target: String,
    pub port: u16,
    pub key: Option<String>,
}

impl Ssh {
    pub fn new(target: &str, port: u16, key: Option<String>) -> Ssh {
        let target = if target.contains('@') { target.to_string() } else { format!("root@{target}") };
        Ssh { target, port, key }
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
        a
    }

    fn ssh_args(&self) -> Vec<String> {
        let mut a = vec!["-p".to_string(), self.port.to_string()];
        a.extend(self.common_args());
        a.push(self.target.clone());
        a
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
        let mut args = self.ssh_args();
        args.push(self.root_cmd(cmd));
        let mut child = tokio::process::Command::new("ssh")
            .args(&args)
            .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("could not run `ssh` — is OpenSSH installed?")?;
        if let Some(data) = input {
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(data).await?;
            drop(stdin);
        }
        let out = child.wait_with_output().await?;
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
        let mut args = self.ssh_args();
        args.push(self.root_cmd("bash -s"));
        let mut child = tokio::process::Command::new("ssh")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(script.as_bytes()).await?;
        drop(stdin);
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
        let _ = a.await;
        let tail = b.await.unwrap_or_default();
        if !status.success() {
            bail!("setup script failed on {}:\n{}", self.target, tail.join("\n"));
        }
        Ok(())
    }

    pub async fn upload(&self, local: &Path, remote: &str) -> Result<()> {
        let mut args = vec!["-q".to_string(), "-P".into(), self.port.to_string()];
        args.extend(self.common_args());
        args.push(local.display().to_string());
        args.push(format!("{}:{remote}", self.target));
        let out = tokio::process::Command::new("scp")
            .args(&args)
            .stdin(Stdio::null())
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
        let mut args = vec![
            "-t".to_string(),
            "-p".into(),
            self.port.to_string(),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
        ];
        if let Some(k) = &self.key {
            args.push("-i".into());
            args.push(k.clone());
        }
        args.push(self.target.clone());
        if let Some(c) = cmd {
            args.push(self.root_cmd(c));
        }
        Ok(std::process::Command::new("ssh").args(&args).status()?)
    }
}
