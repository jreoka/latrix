//! Tiny DNS server for containers: answers `<app>.internal` and
//! `<service>.<group>.internal` with the app's virtual IP and forwards
//! everything else to the machine's normal resolver.

use super::Agent;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

pub async fn run(agent: Arc<Agent>) {
    let addr: SocketAddr = format!("{}:53", agent.me.overlay_ip).parse().unwrap();
    let sock = loop {
        match UdpSocket::bind(addr).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                debug!("dns: cannot bind {addr}: {e} (retrying)");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    let upstream = upstream_resolver();
    info!("internal DNS on {addr} (upstream {upstream})");
    let mut buf = vec![0u8; 1500];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        let query = buf[..n].to_vec();
        let agent = agent.clone();
        let sock = sock.clone();
        let upstream = upstream.clone();
        tokio::spawn(async move {
            let resp = match answer_local(&agent, &query) {
                Some(r) => Some(r),
                None => forward(&upstream, &query).await,
            };
            if let Some(r) = resp {
                let _ = sock.send_to(&r, peer).await;
            }
        });
    }
}

fn upstream_resolver() -> String {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|s| s.trim().to_string())
        .find(|ip| !ip.starts_with("10.77.") && ip.parse::<std::net::IpAddr>().is_ok())
        .map(|ip| if ip.contains(':') { format!("[{ip}]:53") } else { format!("{ip}:53") })
        .unwrap_or_else(|| "1.1.1.1:53".into())
}

async fn forward(upstream: &str, query: &[u8]) -> Option<Vec<u8>> {
    let bind = if upstream.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.send_to(query, upstream).await.ok()?;
    let mut buf = vec![0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(4), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => {
            warn!("dns: upstream {upstream} did not answer");
            None
        }
    }
}

/// Parse the (single) question: returns (lowercase name, qtype, end offset).
pub fn parse_question(q: &[u8]) -> Option<(String, u16, usize)> {
    if q.len() < 12 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut i = 12;
    let mut labels = vec![];
    loop {
        let len = *q.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label = q.get(i + 1..i + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        i += 1 + len;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    Some((labels.join("."), qtype, i + 4))
}

pub fn build_answer(q: &[u8], end: usize, ip: Option<Ipv4Addr>, nxdomain: bool) -> Vec<u8> {
    let mut r = Vec::with_capacity(end + 16);
    r.extend_from_slice(&q[0..2]); // id
    let rd = q[2] & 0x01;
    r.push(0x84 | rd); // QR + AA + RD
    r.push(if nxdomain { 0x83 } else { 0x80 }); // RA + rcode
    r.extend_from_slice(&[0, 1]); // qdcount
    r.extend_from_slice(&[0, ip.is_some() as u8]); // ancount
    r.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    r.extend_from_slice(&q[12..end]);
    if let Some(ip) = ip {
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    r
}

fn answer_local(agent: &Agent, q: &[u8]) -> Option<Vec<u8>> {
    let (name, qtype, end) = parse_question(q)?;
    if !(name == "internal" || name.ends_with(".internal")) {
        return None;
    }
    let routes = agent.routes.read().unwrap().clone();
    let vip = routes.dns.get(&name).and_then(|v| v.parse::<Ipv4Addr>().ok());
    Some(match (vip, qtype) {
        (Some(ip), 1) => build_answer(q, end, Some(ip), false),
        (Some(_), _) => build_answer(q, end, None, false),
        (None, _) => build_answer(q, end, None, true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in name.split('.') {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn roundtrip() {
        let q = query("web.internal", 1);
        let (name, t, end) = parse_question(&q).unwrap();
        assert_eq!(name, "web.internal");
        assert_eq!(t, 1);
        let r = build_answer(&q, end, Some("10.78.0.2".parse().unwrap()), false);
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[7], 1); // one answer
        assert_eq!(&r[r.len() - 4..], &[10, 78, 0, 2]);
        let nx = build_answer(&q, end, None, true);
        assert_eq!(nx[3] & 0x0f, 3);
    }
}
