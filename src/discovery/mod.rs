//! Host discovery (liveness).
//!
//! Phase 1 ships **TCP-ping** discovery: probe a small set of common ports and
//! treat a host as "up" if any probe elicits a response — whether the port is
//! open (handshake) or closed (RST). Only hosts that drop every probe are
//! considered down. This is read-only and non-intrusive.
//!
//! ICMP echo and ARP discovery require raw sockets and are gated behind a
//! privileged feature flag in a later phase. Because TCP-ping has false
//! negatives (a fully firewalled-but-live host looks down), discovery is
//! opt-in via `--ping`; by default every in-scope host is scanned.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinSet;

/// Ports probed to decide liveness (HTTP, HTTPS, SSH, RDP, SMB).
const PING_PORTS: [u16; 5] = [80, 443, 22, 3389, 445];

/// Return the subset of `targets` that appear to be up, preserving input order.
///
/// `concurrency` bounds how many hosts are probed at once; `timeout` is the
/// per-connection timeout for each liveness probe.
pub async fn tcp_ping(targets: Vec<IpAddr>, timeout: Duration, concurrency: usize) -> Vec<IpAddr> {
    let concurrency = concurrency.max(1);
    let mut set: JoinSet<(usize, IpAddr, bool)> = JoinSet::new();
    // (index, ip, is_up) so we can restore input order afterwards.
    let mut up: Vec<(usize, IpAddr)> = Vec::new();

    for (idx, ip) in targets.into_iter().enumerate() {
        while set.len() >= concurrency {
            if let Some(Ok((i, ip, alive))) = set.join_next().await {
                if alive {
                    up.push((i, ip));
                }
            }
        }
        set.spawn(async move {
            let alive = is_alive(ip, timeout).await;
            (idx, ip, alive)
        });
    }
    while let Some(joined) = set.join_next().await {
        if let Ok((i, ip, alive)) = joined {
            if alive {
                up.push((i, ip));
            }
        }
    }

    up.sort_unstable_by_key(|(i, _)| *i);
    up.into_iter().map(|(_, ip)| ip).collect()
}

/// A host is alive if any ping port responds (open or refused). Probes run
/// concurrently and we short-circuit on the first response.
async fn is_alive(ip: IpAddr, timeout: Duration) -> bool {
    let mut set: JoinSet<bool> = JoinSet::new();
    for port in PING_PORTS {
        let addr = SocketAddr::new(ip, port);
        set.spawn(async move { responded(addr, timeout).await });
    }
    while let Some(joined) = set.join_next().await {
        if matches!(joined, Ok(true)) {
            set.abort_all();
            return true;
        }
    }
    false
}

/// True if the address responded to a connect attempt in any way other than a
/// timeout (i.e. handshake succeeded or connection was refused).
async fn responded(addr: SocketAddr, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => true,                                         // open
        Ok(Err(e)) => e.kind() == std::io::ErrorKind::ConnectionRefused, // closed but alive
        Err(_) => false, // timed out -> no evidence of life
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn detects_live_loopback_host() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        // Spawn a task that keeps the listener alive for the duration.
        let _addr = listener.local_addr().unwrap();
        // The default ping ports won't hit our ephemeral port, but loopback
        // refuses (rather than drops) connections to closed ports, so the host
        // still reads as alive.
        let up = tcp_ping(
            vec![IpAddr::from([127, 0, 0, 1])],
            Duration::from_millis(500),
            8,
        )
        .await;
        assert_eq!(up, vec![IpAddr::from([127, 0, 0, 1])]);
    }
}
