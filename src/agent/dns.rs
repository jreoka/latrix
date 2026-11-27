//! Tiny DNS server for containers: answers `<app>.internal` and
//! `<service>.<group>.internal` with the app's virtual IP and forwards
//! everything else to the machine's normal resolver.

use super::Agent;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

pub async fn run(agent: Arc<Agent>) {
    let Ok(ip) = agent.me.overlay_ip.parse::<IpAddr>() else {
        warn!("dns: invalid overlay IP '{}'", agent.me.overlay_ip);
        return;
    };
    let addr = SocketAddr::new(ip, 53);
    let sock = loop {
        match UdpSocket::bind(addr).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                debug!("dns: cannot bind {addr}: {e} (retrying)");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    let upstreams = Arc::new(upstream_resolvers());
    info!("internal DNS on {addr} (upstream {})", upstreams.join(", "));
    let permits = Arc::new(Semaphore::new(256));
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                debug!("dns: recv_from error: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        // Drop truncated packets or DNS response packets (QR=1) to prevent amplification/FD exhaustion.
        if n < 12 || (buf[2] & 0x80) != 0 {
            continue;
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let query = buf[..n].to_vec();
        let agent = agent.clone();
        let sock = sock.clone();
        let upstreams = upstreams.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let resp = match answer_local(&agent, &query) {
                Some(r) => Some(r),
                None => forward_any(&upstreams, &query).await,
            };
            if let Some(r) = resp {
                let _ = sock.send_to(&r, peer).await;
            }
        });
    }
}

fn upstream_resolvers() -> Vec<String> {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let overlay_prefix = format!("{}.", crate::util::OVERLAY_PREFIX);
    let mut list: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let clean = l.split(['#', ';']).next().unwrap_or("").trim();
            let rest = clean.strip_prefix("nameserver")?;
            if !rest.starts_with(char::is_whitespace) {
                return None;
            }
            rest.split_whitespace().next().map(str::to_string)
        })
        .filter(|ip| !ip.starts_with(&overlay_prefix) && ip.parse::<IpAddr>().is_ok())
        .map(|ip| if ip.contains(':') { format!("[{ip}]:53") } else { format!("{ip}:53") })
        .collect();
    list.dedup();
    if list.is_empty() {
        list.push("1.1.1.1:53".into());
        list.push("8.8.8.8:53".into());
    }
    list
}

async fn forward_any(upstreams: &[String], query: &[u8]) -> Option<Vec<u8>> {
    for u in upstreams {
        if let Some(resp) = forward(u, query).await {
            return Some(resp);
        }
    }
    None
}

async fn forward(upstream: &str, query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let bind = if upstream.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    // Connecting the UDP socket ensures the kernel rejects packets from any other peer.
    sock.connect(upstream).await.ok()?;
    sock.send(query).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            warn!("dns: upstream {upstream} did not answer");
            return None;
        };
        match tokio::time::timeout(rem, sock.recv(&mut buf)).await {
            Ok(Ok(n)) if n >= 12 && buf[0..2] == query[0..2] && (buf[2] & 0x80) != 0 => {
                return Some(buf[..n].to_vec());
            }
            Ok(Ok(_)) => continue, // ignore mismatched txid or non-response
            _ => {
                warn!("dns: upstream {upstream} did not answer");
                return None;
            }
        }
    }
}

/// Parse the (single) question: returns (lowercase name, qtype, end offset).
pub fn parse_question(q: &[u8]) -> Option<(String, u16, usize)> {
    if q.len() < 12
        || (q[2] & 0x80) != 0 // must be a query (QR=0)
        || (q[2] & 0x78) != 0 // standard query (OPCODE=0)
        || u16::from_be_bytes([q[4], q[5]]) != 1
    {
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
    if q.len() < i + 4 {
        return None; // truncated question (no QCLASS)
    }
    let qtype = u16::from_be_bytes([q[i], q[i + 1]]);
    let qclass = u16::from_be_bytes([q[i + 2], q[i + 3]]);
    if qclass != 1 {
        return None;
    }
    Some((labels.join("."), qtype, i + 4))
}

pub fn build_answer(q: &[u8], end: usize, ip: Option<Ipv4Addr>, nxdomain: bool) -> Vec<u8> {
    if q.len() < 12 || end < 12 || end > q.len() {
        return Vec::new();
    }
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

    #[test]
    fn parse_question_rejects_malformed_and_responses() {
        // Too short
        assert!(parse_question(&[0u8; 11]).is_none());

        // Response packet (QR=1) must be rejected so we never reflect/amplify
        let mut resp = query("web.internal", 1);
        resp[2] |= 0x80;
        assert!(parse_question(&resp).is_none());

        // Non-zero OPCODE rejected
        let mut op = query("web.internal", 1);
        op[2] |= 0x08;
        assert!(parse_question(&op).is_none());

        // Non-IN QCLASS (CH = 3) rejected
        let mut ch = query("web.internal", 1);
        let n = ch.len();
        ch[n - 1] = 3;
        assert!(parse_question(&ch).is_none());
    }
}
