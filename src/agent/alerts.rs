//! Alerts: warnings (machine down, deploy rolled back, certificate trouble,
//! disk full, crash loops, ...) are posted to `settings.alert_webhook` —
//! Discord, Slack, or anything that accepts a JSON POST. Batched every 20
//! seconds; the same message is sent at most once an hour.

use super::Agent;
use crate::util::now;
use anyhow::bail;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::warn;

fn webhook_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .expect("webhook client")
    })
}

/// Validate a webhook URL against SSRF targets (loopback, link-local, metadata, overlay).
pub fn validate_webhook_url(raw: &str) -> anyhow::Result<()> {
    let parsed = reqwest::Url::parse(raw.trim()).map_err(|e| anyhow::anyhow!("invalid alert_webhook URL: {e}"))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        bail!("alert_webhook must use https:// (or http://)");
    }
    let Some(host) = parsed.host_str() else {
        bail!("alert_webhook URL must have a host");
    };
    let hl = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if hl == "localhost" || hl.ends_with(".localhost") || hl.ends_with(".internal") {
        bail!("alert_webhook cannot point to loopback or internal hosts");
    }
    if let Ok(ip) = hl.parse::<IpAddr>() {
        let forbidden = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.octets()[0] == 10 && matches!(v4.octets()[1], 77 | 78)
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || ((v6.segments()[0] & 0xffc0) == 0xfe80)
            }
        };
        if forbidden {
            bail!("alert_webhook cannot target loopback, link-local, or cluster overlay IP '{ip}'");
        }
    }
    Ok(())
}

pub fn queue(agent: &Agent, msg: &str) {
    let mut q = agent.alert_queue.lock().unwrap();
    q.push(msg.to_string());
    if q.len() > 100 {
        q.remove(0);
    }
}

pub async fn send(agent: &Agent, url: &str, lines: &[String]) -> anyhow::Result<()> {
    validate_webhook_url(url)?;
    let cluster = agent.snapshot().cluster.clone();
    let mut text = format!("latrix ({cluster}):");
    for l in lines {
        text.push_str("\n• ");
        text.push_str(l);
    }
    // Truncate by character count (safe for multi-byte UTF-8 like `•` and `—`,
    // and respects Discord's 2000-character limit).
    if text.chars().count() > 1900 {
        text = text.chars().take(1900).collect();
        text.push('…');
    }
    // "content" for Discord, "text" for Slack and most others.
    let body = serde_json::json!({ "content": text, "text": text });
    let r = webhook_client().post(url.trim()).json(&body).send().await?;
    if !r.status().is_success() {
        bail!("webhook answered {}", r.status());
    }
    Ok(())
}

pub async fn run(agent: Arc<Agent>) {
    let mut sent: HashMap<String, u64> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;
        if !agent.is_leader() {
            continue;
        }
        let url = agent.snapshot().settings.alert_webhook.clone();
        if url.is_empty() {
            agent.alert_queue.lock().unwrap().clear();
            continue;
        }
        let pending: Vec<String> = std::mem::take(&mut *agent.alert_queue.lock().unwrap());
        if pending.is_empty() {
            continue;
        }
        let t = now();
        sent.retain(|_, at| t.saturating_sub(*at) < 3600);
        let mut lines = vec![];
        for m in pending {
            if !sent.contains_key(&m) && !lines.contains(&m) {
                lines.push(m);
            }
        }
        if lines.is_empty() {
            continue;
        }
        match send(&agent, &url, &lines).await {
            Ok(()) => {
                for m in lines {
                    sent.insert(m, t);
                }
            }
            Err(e) => {
                warn!("alert webhook: {e:#}");
            }
        }
    }
}
