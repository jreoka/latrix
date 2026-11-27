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

pub async fn run(agent: Arc<Agent>) {
    if agent.dev {
        return;
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
    let mut backoff: HashMap<String, Instant> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(120));
    loop {
        tick.tick().await;
        if !agent.is_leader() {
            continue;
        }
        let s = agent.snapshot();
        let routes = agent.routes.read().unwrap().clone();
        let mut domains: Vec<String> = routes
            .apps
            .values()
            .flat_map(|r| r.hosts.iter().cloned())
            .filter(|d| eligible(d))
            .collect();
        domains.sort();
        domains.dedup();
        for d in domains {
            if let Some(c) = s.certs.get(&d) {
                if c.not_after > now() + RENEW_BEFORE {
                    continue;
                }
            }
            if backoff.get(&d).map(|t| Instant::now() < *t).unwrap_or(false) {
                continue;
            }
            match issue(&agent, &d).await {
                Ok(()) => {
                    agent.event("info", format!("certificate issued for {d}"));
                    backoff.remove(&d);
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    let wait = if msg.contains("does not point") { 600 } else { 3600 };
                    agent.event("warn", format!("certificate for {d}: {msg} (retrying in {}m)", wait / 60));
                    backoff.insert(d.clone(), Instant::now() + Duration::from_secs(wait));
                }
            }
        }
    }
}

fn eligible(d: &str) -> bool {
    !d.ends_with(".localhost")
        && !d.ends_with(".internal")
        && !d.contains('*')
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

async fn issue(agent: &Arc<Agent>, domain: &str) -> Result<()> {
    // 1. Make sure the domain actually reaches this cluster before asking
    //    Let's Encrypt (avoids burning rate limits on DNS that isn't set yet).
    let probe = random_id(32);
    let expect = random_id(32);
    set_challenge(agent, &probe, Some(&expect)).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let got = agent
        .http
        .get(format!("http://{domain}/.well-known/acme-challenge/{probe}"))
        .timeout(Duration::from_secs(8))
        .send()
        .await;
    let ok = match got {
        Ok(r) => r.text().await.map(|t| t.trim() == expect).unwrap_or(false),
        Err(_) => false,
    };
    set_challenge(agent, &probe, None).await?;
    if !ok {
        bail!("DNS for {domain} does not point at this cluster yet (add an A record for one of your machines)");
    }

    // 2. Account (created once, stored in the cluster state).
    let s = agent.snapshot();
    let url = if s.settings.acme_staging {
        LetsEncrypt::Staging.url()
    } else {
        LetsEncrypt::Production.url()
    };
    let account = match s.acme_account.as_ref().and_then(|a| serde_json::from_str::<AccountCredentials>(a).ok()) {
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
                    s.acme_account = Some(json);
                    Ok(())
                })
                .await?;
            account
        }
    };

    // 3. Order + HTTP-01 challenges.
    info!("requesting certificate for {domain}");
    let ids = [Identifier::Dns(domain.to_string())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await?;
    let mut tokens = vec![];
    {
        let mut auths = order.authorizations();
        while let Some(a) = auths.next().await {
            let mut authz = a?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => bail!("authorization is {other:?}"),
            }
            let mut ch = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow!("no http-01 challenge offered"))?;
            let token = ch.token.clone();
            let key_auth = ch.key_authorization().as_str().to_string();
            set_challenge(agent, &token, Some(&key_auth)).await?;
            tokens.push(token);
            tokio::time::sleep(Duration::from_secs(3)).await;
            ch.set_ready().await?;
        }
    }
    let result = async {
        let status = order.poll_ready(&RetryPolicy::default()).await?;
        if status != OrderStatus::Ready {
            bail!("order is {status:?}");
        }
        let key_pem = order.finalize().await?;
        let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;
        Ok((key_pem, cert_pem))
    }
    .await;
    for t in &tokens {
        let _ = set_challenge(agent, t, None).await;
    }
    let (key_pem, cert_pem) = result?;
    let not_after = not_after(&cert_pem).unwrap_or(now() + 60 * 86400);
    let d = domain.to_string();
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
                },
            );
            Ok(())
        })
        .await?;
    Ok(())
}

fn not_after(pem: &str) -> Result<u64> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|e| anyhow!("{e}"))?;
    let cert = p.parse_x509().context("parsing certificate")?;
    let ts = cert.validity().not_after.timestamp();
    if ts < 0 {
        warn!("certificate has a negative expiry");
    }
    Ok(ts.max(0) as u64)
}
