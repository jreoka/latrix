//! Automatic HTTPS. The leader obtains Let's Encrypt certificates (HTTP-01)
//! for every domain in the cluster and stores them in the replicated state,
//! so every machine can terminate TLS. Challenge tokens are replicated too,
//! so it doesn't matter which machine Let's Encrypt connects to.

use super::Agent;
use crate::util::{now, random_id};
use anyhow::{anyhow, bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

const RENEW_BEFORE: u64 = 30 * 86400;
/// Certificates no app uses are kept this long (redeploying within it
/// avoids Let's Encrypt's 5-per-week duplicate certificate limit).
const KEEP_UNUSED: u64 = 7 * 86400;

/// Compute all eligible HTTP domains directly from cluster state rather than
/// derived proxy routes, so leader failover never treats active certs as unused
/// and non-HTTP apps never request certificates.
fn desired_domains(s: &crate::state::ClusterState) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    let base = crate::config::normalize_dns_name(&s.settings.base_domain);
    for (name, app) in &s.apps {
        let Some(cfg) = app.config() else { continue };
        let Some(http) = &cfg.http else { continue };
        for d in &http.domains {
            let norm = crate::config::normalize_dns_name(d);
            if eligible(&norm) {
                domains.push(norm);
            }
        }
        if !base.is_empty() {
            let sub = format!("{name}.{base}");
            if eligible(&sub) {
                domains.push(sub);
            }
        }
    }
    domains.sort();
    domains.dedup();
    domains
}

/// True when a certificate should be renewed, adapting to short-lived certs
/// (e.g. 6-day validity) without tight re-issuance loops.
fn needs_renewal(c: &crate::state::Cert, t: u64) -> bool {
    if c.issued_at > 0 && t.saturating_sub(c.issued_at) < 3600 && c.not_after > t {
        return false;
    }
    let lifetime = c.not_after.saturating_sub(c.issued_at);
    let renew_before = if lifetime > 0 {
        RENEW_BEFORE.min((lifetime / 3).max(3600))
    } else {
        RENEW_BEFORE
    };
    c.not_after <= t.saturating_add(renew_before)
}

pub async fn run(agent: Arc<Agent>) {
    if agent.dev {
        return;
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
    let mut backoff: HashMap<String, Instant> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(120));
    loop {
        let woken = tokio::select! {
            _ = tick.tick() => false,
            _ = agent.acme_wake.notified() => true,
        };
        if !agent.is_leader() {
            continue;
        }
        if woken {
            // Cloudflare DNS just updated: give records a brief moment to propagate and clear DNS backoffs.
            tokio::time::sleep(Duration::from_secs(5)).await;
            let pending = agent.acme_pending.lock().unwrap().clone();
            backoff.retain(|d, _| {
                pending
                    .get(d)
                    .map(|(reason, _)| !reason.contains("does not point"))
                    .unwrap_or(false)
            });
        }
        let s = agent.snapshot();
        // Sweep any stale HTTP-01 challenge tokens left behind by a previous leader crash.
        if !s.acme_challenges.is_empty() {
            let _ = agent
                .mutate(|st| {
                    st.acme_challenges.clear();
                    Ok(())
                })
                .await;
        }
        let domains = desired_domains(&s);
        cleanup(&agent, &s, &domains).await;
        agent.acme_pending.lock().unwrap().retain(|d, _| domains.contains(d));
        let want_staging = s.settings.acme_staging;
        for d in domains {
            if !agent.is_leader() {
                break;
            }
            let cur = agent.snapshot();
            if cur.settings.acme_staging != want_staging {
                break;
            }
            if let Some(c) = cur.certs.get(&d) {
                if c.staging == want_staging && !needs_renewal(c, now()) {
                    continue;
                }
            }
            if backoff.get(&d).map(|t| Instant::now() < *t).unwrap_or(false) {
                continue;
            }
            agent
                .acme_pending
                .lock()
                .unwrap()
                .insert(d.clone(), ("requesting now".into(), now()));
            match issue(&agent, &d).await {
                Ok(()) => {
                    agent.event("info", format!("certificate issued for {d}"));
                    backoff.remove(&d);
                    agent.acme_pending.lock().unwrap().remove(&d);
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    let wait = if msg.contains("does not point") { 600 } else { 3600 };
                    agent.event("warn", format!("certificate for {d}: {msg} (retrying in {}m)", wait / 60));
                    backoff.insert(d.clone(), Instant::now() + Duration::from_secs(wait));
                    agent.acme_pending.lock().unwrap().insert(d.clone(), (msg, now() + wait));
                }
            }
        }
    }
}

/// Forget certificates no app has used for a week (or that have expired).
async fn cleanup(agent: &Arc<Agent>, s: &crate::state::ClusterState, in_use: &[String]) {
    let t = now();
    let needs_change = s.certs.values().any(|c| {
        let used = in_use.contains(&c.domain);
        (used && c.unused_since != 0)
            || (!used && (c.unused_since == 0 || t.saturating_sub(c.unused_since) > KEEP_UNUSED || c.not_after < t))
    });
    if !needs_change {
        return;
    }
    let in_use = in_use.to_vec();
    let removed = agent
        .mutate(move |s| Ok(apply_cleanup(&mut s.certs, &in_use, t)))
        .await
        .unwrap_or_default();
    for d in removed {
        agent.event("info", format!("removed the certificate for {d} (no app uses it any more)"));
    }
}

/// Mark unused certificates, clear the mark when a domain is used again, and
/// drop ones unused for a week or expired. Returns the removed domains.
pub fn apply_cleanup(
    certs: &mut std::collections::BTreeMap<String, crate::state::Cert>,
    in_use: &[String],
    t: u64,
) -> Vec<String> {
    let mut removed = vec![];
    for c in certs.values_mut() {
        if in_use.contains(&c.domain) {
            c.unused_since = 0;
        } else if c.not_after < t || (c.unused_since != 0 && t.saturating_sub(c.unused_since) > KEEP_UNUSED) {
            removed.push(c.domain.clone());
        } else if c.unused_since == 0 {
            c.unused_since = t;
        }
    }
    certs.retain(|d, _| !removed.contains(d));
    removed
}

fn eligible(d: &str) -> bool {
    let d = crate::config::normalize_dns_name(d);
    !d.is_empty()
        && !d.ends_with(".localhost")
        && !d.ends_with(".internal")
        && !d.contains('*')
        && !d
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | ':' | '?' | '#' | '@'))
        && d.parse::<std::net::IpAddr>().is_err()
        && d.contains('.')
}

async fn set_challenge(agent: &Arc<Agent>, token: &str, value: Option<&str>) -> Result<()> {
    let (t, v) = (token.to_string(), value.map(|v| v.to_string()));
    agent
        .mutate(move |s| {
            match v {
                Some(v) => s.acme_challenges.insert(t, v),
                None => s.acme_challenges.remove(&t),
            };
            Ok(())
        })
        .await
}

fn creds_match_env(json: &str, staging: bool) -> bool {
    let is_staging = json.contains("acme-staging");
    is_staging == staging
}

async fn issue(agent: &Arc<Agent>, domain: &str) -> Result<()> {
    let domain = crate::config::normalize_dns_name(domain);
    if !eligible(&domain) {
        bail!("domain '{domain}' is not eligible for ACME");
    }

    // 1. Make sure the domain actually reaches this cluster before asking
    //    Let's Encrypt (avoids burning rate limits on DNS that isn't set yet).
    let probe = random_id(32);
    let expect = random_id(32);
    set_challenge(agent, &probe, Some(&expect)).await?;
    let probe_res = async {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let got = agent
            .http
            .get(format!("http://{domain}/.well-known/acme-challenge/{probe}"))
            .timeout(Duration::from_secs(8))
            .send()
            .await;
        match got {
            Ok(r) => r.text().await.map(|t| t.trim() == expect).unwrap_or(false),
            Err(_) => false,
        }
    }
    .await;
    let _ = set_challenge(agent, &probe, None).await;
    let ok = probe_res;

    // If HTTP-01 can't reach us directly (e.g. Cloudflare proxy orange cloud with
    // Always-HTTPS, or DNS still propagating), fall back to DNS-01 via Cloudflare
    // when a Cloudflare token manages this domain's zone.
    let cf_dns01 = if !ok {
        super::cloudflare::find_zone_for_domain(agent, &domain).await
    } else {
        None
    };
    if !ok && cf_dns01.is_none() {
        bail!("DNS for {domain} does not point at this cluster yet (add an A record for one of your machines, or configure Cloudflare DNS with `latrix dns cloudflare <token>`)");
    }
    if !agent.is_leader() {
        bail!("lost leadership before ACME order");
    }

    // 2. Account (stored separately for production and staging so toggling acme_staging works cleanly).
    let s = agent.snapshot();
    let staging = s.settings.acme_staging;
    let url = if staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };
    let stored = if staging {
        s.acme_staging_account.as_ref()
    } else {
        s.acme_account.as_ref()
    };
    let account = match stored
        .filter(|json| creds_match_env(json, staging))
        .and_then(|a| serde_json::from_str::<AccountCredentials>(a).ok())
    {
        Some(creds) => Account::builder()?.from_credentials(creds).await?,
        None => {
            let contact = if s.settings.acme_email.is_empty() {
                vec![]
            } else {
                vec![format!("mailto:{}", s.settings.acme_email)]
            };
            let contact_refs: Vec<&str> = contact.iter().map(|c| c.as_str()).collect();
            let (account, creds) = Account::builder()?
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    url.to_owned(),
                    None,
                )
                .await?;
            let json = serde_json::to_string(&creds)?;
            agent
                .mutate(move |s| {
                    if staging {
                        s.acme_staging_account = Some(json);
                    } else {
                        s.acme_account = Some(json);
                    }
                    Ok(())
                })
                .await?;
            account
        }
    };

    // 3. Order + HTTP-01 (or Cloudflare DNS-01) challenges.
    //    Wrap BOTH authorization setup and polling so every HTTP token and
    //    Cloudflare TXT record is guaranteed to be cleaned up on any error.
    info!(
        "requesting certificate for {domain} ({}{})",
        if cf_dns01.is_some() { "dns-01 via Cloudflare" } else { "http-01" },
        if staging { ", staging" } else { "" }
    );
    let ids = [Identifier::Dns(domain.clone())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await?;
    let mut http_tokens: Vec<String> = vec![];
    let mut dns_records: Vec<(String, String, String)> = vec![]; // (token, zone_id, record_id)
    let result: Result<(String, String)> = async {
        {
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                if !agent.is_leader() {
                    bail!("lost leadership during ACME authorization");
                }
                let mut authz = a?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => bail!("authorization is {other:?}"),
                }
                if let Some((cf_token, _, zone)) = &cf_dns01 {
                    let mut ch = authz
                        .challenge(ChallengeType::Dns01)
                        .ok_or_else(|| anyhow!("no dns-01 challenge offered"))?;
                    let txt = ch.key_authorization().dns_value();
                    let cf = super::cloudflare::CfClient::new(agent.http.clone(), cf_token);
                    let rec_id = cf.create_acme_txt(&zone.id, &domain, &txt).await?;
                    dns_records.push((cf_token.clone(), zone.id.clone(), rec_id));
                    // Give Cloudflare edge DNS a moment to propagate the TXT record.
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    ch.set_ready().await?;
                } else {
                    let mut ch = authz
                        .challenge(ChallengeType::Http01)
                        .ok_or_else(|| anyhow!("no http-01 challenge offered"))?;
                    let token = ch.token.clone();
                    let key_auth = ch.key_authorization().as_str().to_string();
                    set_challenge(agent, &token, Some(&key_auth)).await?;
                    http_tokens.push(token);
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    ch.set_ready().await?;
                }
            }
        }
        let policy = if cf_dns01.is_some() {
            RetryPolicy::new().timeout(Duration::from_secs(90))
        } else {
            RetryPolicy::default()
        };
        let status = order.poll_ready(&policy).await?;
        if status != OrderStatus::Ready {
            let mut details = vec![];
            let mut auths = order.authorizations();
            while let Some(Ok(authz)) = auths.next().await {
                for ch in &authz.challenges {
                    if let Some(err) = &ch.error {
                        details.push(format!("{:?}: {}", ch.r#type, err));
                    }
                }
            }
            if details.is_empty() {
                bail!("order is {status:?}");
            } else {
                bail!("order is {status:?} ({})", details.join("; "));
            }
        }
        if !agent.is_leader() {
            bail!("lost leadership before ACME finalize");
        }
        let key_pem = order.finalize().await?;
        let cert_pem = order.poll_certificate(&policy).await?;
        Ok((key_pem, cert_pem))
    }
    .await;

    for t in &http_tokens {
        let _ = set_challenge(agent, t, None).await;
    }
    for (cf_token, zone_id, rec_id) in &dns_records {
        let cf = super::cloudflare::CfClient::new(agent.http.clone(), cf_token);
        let _ = cf.delete_record(zone_id, rec_id).await;
    }

    let (key_pem, cert_pem) = result?;
    let not_after = not_after(&cert_pem).context("invalid X.509 certificate returned by ACME")?;
    super::proxy::load_cert(&cert_pem, &key_pem)
        .context("ACME returned certificate/key pair that failed TLS validation")?;

    let d = domain.clone();
    agent
        .mutate(move |s| {
            s.certs.insert(
                d.clone(),
                crate::state::Cert {
                    domain: d,
                    cert_pem,
                    key_pem,
                    not_after,
                    issued_at: now(),
                    unused_since: 0,
                    staging,
                },
            );
            Ok(())
        })
        .await?;
    Ok(())
}

fn not_after(pem: &str) -> Result<u64> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow!("{e}"))?;
    if p.label != "CERTIFICATE" {
        bail!("expected PEM CERTIFICATE block, got {}", p.label);
    }
    let cert = p.parse_x509().context("parsing certificate")?;
    let ts = cert.validity().not_after.timestamp();
    if ts < 0 {
        warn!("certificate has a negative expiry");
    }
    Ok(ts.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(d: &str, not_after: u64) -> crate::state::Cert {
        crate::state::Cert {
            domain: d.into(),
            cert_pem: String::new(),
            key_pem: String::new(),
            not_after,
            issued_at: 0,
            unused_since: 0,
            staging: false,
        }
    }

    #[test]
    fn unused_certs_are_kept_a_week_then_removed() {
        let day = 86400;
        let mut certs: std::collections::BTreeMap<_, _> = [
            ("used.com".to_string(), cert("used.com", 90 * day)),
            ("gone.com".to_string(), cert("gone.com", 90 * day)),
            ("expired.com".to_string(), cert("expired.com", day)),
        ]
        .into();
        let used = vec!["used.com".to_string()];
        // day 2: gone.com is marked, the expired unused one goes right away
        assert_eq!(apply_cleanup(&mut certs, &used, 2 * day), vec!["expired.com"]);
        assert_eq!(certs["gone.com"].unused_since, 2 * day);
        assert_eq!(certs["used.com"].unused_since, 0);
        // day 5: still kept
        assert!(apply_cleanup(&mut certs, &used, 5 * day).is_empty());
        // redeployed on day 6: the mark is cleared
        let both = vec!["used.com".to_string(), "gone.com".to_string()];
        apply_cleanup(&mut certs, &both, 6 * day);
        assert_eq!(certs["gone.com"].unused_since, 0);
        // removed again on day 7, deleted more than a week later
        apply_cleanup(&mut certs, &used, 7 * day);
        assert!(apply_cleanup(&mut certs, &used, 13 * day).is_empty());
        assert_eq!(apply_cleanup(&mut certs, &used, 15 * day), vec!["gone.com"]);
        assert_eq!(certs.len(), 1);
    }
}
