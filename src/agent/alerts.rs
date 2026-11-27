//! Alerts: warnings (machine down, deploy rolled back, certificate trouble,
//! disk full, crash loops, ...) are posted to `settings.alert_webhook` —
//! Discord, Slack, or anything that accepts a JSON POST. Batched every 20
//! seconds; the same message is sent at most once an hour.

use super::Agent;
use crate::util::now;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

pub fn queue(agent: &Agent, msg: &str) {
    let mut q = agent.alert_queue.lock().unwrap();
    q.push(msg.to_string());
    if q.len() > 100 {
        q.remove(0);
    }
}

pub async fn send(agent: &Agent, url: &str, lines: &[String]) -> anyhow::Result<()> {
    let cluster = agent.snapshot().cluster.clone();
    let mut text = format!("latrix ({cluster}):");
    for l in lines {
        text.push_str("\n• ");
        text.push_str(l);
    }
    if text.len() > 1900 {
        text.truncate(1900);
        text.push('…');
    }
    // "content" for Discord, "text" for Slack and most others.
    let body = serde_json::json!({ "content": text, "text": text });
    let r = agent.http.post(url).json(&body).timeout(Duration::from_secs(10)).send().await?;
    if !r.status().is_success() {
        anyhow::bail!("webhook answered {}", r.status());
    }
    Ok(())
}

pub async fn run(agent: Arc<Agent>) {
    let mut sent: HashMap<String, u64> = HashMap::new();
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;
        let url = agent.snapshot().settings.alert_webhook.clone();
        let pending: Vec<String> = std::mem::take(&mut *agent.alert_queue.lock().unwrap());
        if url.is_empty() || !agent.is_leader() || pending.is_empty() {
            continue;
        }
        let t = now();
        sent.retain(|_, at| t.saturating_sub(*at) < 3600);
        let mut lines = vec![];
        for m in pending {
            if !sent.contains_key(&m) && !lines.contains(&m) {
                sent.insert(m.clone(), t);
                lines.push(m);
            }
        }
        if lines.is_empty() {
            continue;
        }
        if let Err(e) = send(&agent, &url, &lines).await {
            warn!("alert webhook: {e:#}");
        }
    }
}
