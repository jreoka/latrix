//! SSH keys that may log in to every machine (`latrix keys`).
//!
//! The list lives in the cluster state; every agent writes it into
//! /root/.ssh/authorized_keys, so a key added once works on every machine,
//! including ones bought later. Revoked keys are removed everywhere. Keys that
//! were already in the file stay untouched unless they are revoked.

use super::Agent;
use anyhow::{bail, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

const MARK: &str = "latrix-managed";

/// "ssh-ed25519 AAAA... comment" -> "ssh-ed25519 AAAA..." (what identifies a key).
pub fn key_id(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    // Options before the key type are allowed in authorized_keys.
    let i = parts.iter().position(|p| is_key_type(p))?;
    let b64 = parts.get(i + 1)?;
    Some(format!("{} {}", parts[i], b64))
}

fn is_key_type(t: &str) -> bool {
    t.starts_with("ssh-") || t.starts_with("ecdsa-sha2-") || t.starts_with("sk-")
}

/// Check that `k` looks like an SSH public key.
pub fn validate(k: &str) -> Result<String> {
    let k = k.trim();
    let parts: Vec<&str> = k.split_whitespace().collect();
    if parts.len() < 2 || !is_key_type(parts[0]) || parts[1].len() < 40 {
        bail!("'{}' is not an SSH public key (it looks like \"ssh-ed25519 AAAA... you@laptop\")", short(k));
    }
    if k.contains("PRIVATE KEY") {
        bail!("that's a private key; use the .pub file");
    }
    Ok(k.to_string())
}

pub fn short(k: &str) -> String {
    let parts: Vec<&str> = k.split_whitespace().collect();
    match parts.as_slice() {
        [t, b, rest @ ..] => {
            let tail = &b[b.len().saturating_sub(8)..];
            let comment = rest.join(" ");
            format!("{t} …{tail}{}", if comment.is_empty() { String::new() } else { format!(" {comment}") })
        }
        _ => k.chars().take(40).collect(),
    }
}

/// The new authorized_keys content, or None when nothing changes.
pub fn merge(current: &str, wanted: &[String], revoked: &[String]) -> Option<String> {
    let wanted_ids: Vec<String> = wanted.iter().filter_map(|k| key_id(k)).collect();
    let revoked_ids: Vec<String> = revoked.iter().filter_map(|k| key_id(k)).collect();
    let mut out: Vec<String> = vec![];
    let mut have: Vec<String> = vec![];
    for line in current.lines() {
        let id = key_id(line);
        if let Some(id) = &id {
            if revoked_ids.contains(id) {
                continue;
            }
            if line.trim_end().ends_with(MARK) && !wanted_ids.contains(id) {
                continue; // removed from the list
            }
            have.push(id.clone());
        }
        out.push(line.to_string());
    }
    for id in wanted_ids {
        if !have.contains(&id) && !revoked_ids.contains(&id) {
            out.push(format!("{id} {MARK}"));
            have.push(id);
        }
    }
    let mut new = out.join("\n");
    if !new.is_empty() {
        new.push('\n');
    }
    (new != current).then_some(new)
}

fn sync_file(path: &Path, wanted: &[String], revoked: &[String]) -> Result<bool> {
    let current = std::fs::read_to_string(path).unwrap_or_default();
    let Some(new) = merge(&current, wanted, revoked) else { return Ok(false) };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    crate::util::write_atomic(path, new.as_bytes())?;
    super::set_private(path);
    Ok(true)
}

pub async fn run(agent: Arc<Agent>) {
    if agent.dev {
        return;
    }
    let mut rx = agent.changed.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(120));
    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = rx.changed() => {},
        }
        let s = agent.snapshot();
        if s.ssh_keys.is_empty() && s.revoked_ssh_keys.is_empty() {
            continue;
        }
        match sync_file(Path::new("/root/.ssh/authorized_keys"), &s.ssh_keys, &s.revoked_ssh_keys) {
            Ok(true) => info!("updated /root/.ssh/authorized_keys ({} latrix keys)", s.ssh_keys.len()),
            Ok(false) => {}
            Err(e) => warn!("could not update authorized_keys: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa me@laptop";
    const B: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb backup";
    const C: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCccccccccccccccccccccccccccc hetzner";

    #[test]
    fn adds_removes_and_revokes() {
        let file = format!("{C}\n");
        // add A and B; C (installed by the provider) stays
        let f1 = merge(&file, &[A.into(), B.into()], &[]).unwrap();
        assert!(f1.starts_with(C));
        assert_eq!(f1.lines().count(), 3);
        assert!(merge(&f1, &[A.into(), B.into()], &[]).is_none(), "idempotent");
        // B removed from the list: only its managed line goes
        let f2 = merge(&f1, &[A.into()], &[]).unwrap();
        assert_eq!(f2.lines().count(), 2);
        assert!(!f2.contains("AAAAIBbbb"));
        // revoking C removes it even though latrix didn't add it
        let f3 = merge(&f2, &[A.into()], &[C.into()]).unwrap();
        assert_eq!(f3.lines().count(), 1);
        // a key already present (with options) isn't added twice
        let f4 = format!("no-pty {A}\n");
        assert!(merge(&f4, &[A.into()], &[]).is_none());
    }

    #[test]
    fn validation() {
        assert!(validate(A).is_ok());
        assert!(validate("hello").is_err());
        assert!(validate("-----BEGIN OPENSSH PRIVATE KEY-----").is_err());
    }
}
