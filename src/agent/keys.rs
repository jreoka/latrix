//! SSH keys that may log in to every machine (`latrix keys`).
//!
//! The list lives in the cluster state; every agent writes it into
//! /root/.ssh/authorized_keys, so a key added once works on every machine,
//! including ones bought later. Revoked keys are removed everywhere. Keys that
//! were already in the file stay untouched unless they are revoked.

use super::Agent;
use crate::util;
use anyhow::{bail, Result};
use base64::Engine;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

const MARK: &str = "latrix-managed";

/// Split an `authorized_keys` line into tokens respecting double-quoted SSH options
/// (e.g. `command="foo ssh-rsa bar" ssh-ed25519 AAAA...`).
fn split_key_tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            cur.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            cur.push(ch);
            continue;
        }
        if ch.is_whitespace() && !in_quotes {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// "ssh-ed25519 AAAA... comment" -> "ssh-ed25519 AAAA..." (what identifies a key).
pub fn key_id(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let parts = split_key_tokens(line);
    // Options before the key type are allowed in authorized_keys.
    let i = parts.iter().position(|p| is_key_type(p))?;
    let b64 = parts.get(i + 1)?;
    if b64.len() < 16 {
        return None;
    }
    Some(format!("{} {}", parts[i], b64))
}

fn is_key_type(t: &str) -> bool {
    matches!(
        t,
        "ssh-ed25519"
            | "ssh-rsa"
            | "ssh-dss"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
    )
}

/// Check that `k` looks like an SSH public key and normalize it to a single line.
pub fn validate(k: &str) -> Result<String> {
    let k = k.trim();
    if k.contains("PRIVATE KEY") {
        bail!("that's a private key; use the .pub file");
    }
    if k.contains(['\n', '\r', '\0']) {
        bail!("SSH public key must be a single line");
    }
    let parts: Vec<&str> = k.split_whitespace().collect();
    if parts.len() < 2 || !is_key_type(parts[0]) || parts[1].len() < 40 {
        bail!(
            "'{}' is not an SSH public key (it looks like \"ssh-ed25519 AAAA... you@laptop\")",
            short(k)
        );
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|_| anyhow::anyhow!("'{}' has invalid base64 key data", short(k)))?;
    if decoded.len() < 32 {
        bail!("'{}' is too short to be a valid SSH public key", short(k));
    }
    Ok(parts.join(" "))
}

pub fn short(k: &str) -> String {
    let parts: Vec<&str> = k.split_whitespace().collect();
    match parts.as_slice() {
        [t, b, rest @ ..] => {
            let tail: String = b.chars().rev().take(8).collect::<Vec<_>>().into_iter().rev().collect();
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
    let mark_suffix = format!(" {MARK}");
    for line in current.lines() {
        let id = key_id(line);
        if let Some(id) = &id {
            if revoked_ids.contains(id) {
                continue;
            }
            if line.trim_end().ends_with(&mark_suffix) && !wanted_ids.contains(id) {
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
    let current = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => bail!("refusing to modify {} after read error: {e}", path.display()),
    };
    let Some(new) = merge(&current, wanted, revoked) else { return Ok(false) };
    // Lockout protection: never wipe the last valid SSH key from authorized_keys.
    let had_keys = current.lines().any(|l| key_id(l).is_some());
    let has_keys = new.lines().any(|l| key_id(l).is_some());
    if had_keys && !has_keys {
        bail!("refusing to write empty {} (would lock out SSH access)", path.display());
    }
    if let Some(dir) = path.parent() {
        util::create_private_dir_all(dir)?;
    }
    util::write_atomic_private(path, new.as_bytes())?;
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
        assert!(validate(&format!("{A}\n{B}")).is_err(), "newline injection rejected");
        assert!(validate("ssh-ed25519 not-valid-base64!!!").is_err());
        assert!(validate("ssh-ed25519 AAAA").is_err(), "too-short key blob rejected");
        assert!(validate(&format!("command=\"echo hello world\",no-pty {A}")).is_err(), "options rejected in added keys");
    }

    #[test]
    fn quoted_options_and_utf8_short() {
        let existing = format!("command=\"echo hello world\",no-pty {A}\n");
        assert!(merge(&existing, &[A.into()], &[]).is_none(), "dedups key behind quoted options");
        let utf8_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 日本語コメント";
        assert!(short(utf8_key).contains("日本語コメント"));
        let long_utf8 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(short(long_utf8).contains("…"));
    }
}
