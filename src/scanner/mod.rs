//! The async TCP connect-scan core.
//!
//! This is where the speed comes from: thousands of concurrent `connect()`
//! attempts driven by tokio, bounded by an adaptive concurrency ceiling (see
//! [`batch`]) so we never exhaust file descriptors. Scanning is **read-only** —
//! we complete the TCP handshake to observe port state and immediately close
//! the socket. No bytes are ever sent to the target here.

pub mod batch;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use governor::DefaultDirectRateLimiter;
use indicatif::ProgressBar;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio::task::{JoinError, JoinSet};

/// The observed state of a scanned TCP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    /// The handshake completed — a service is listening.
    Open,
    /// The connection was actively refused (RST) — reachable but nothing listening.
    Closed,
    /// No response within the timeout (dropped/firewalled), or unreachable.
    Filtered,
}

/// The result of probing a single `(ip, port)`.
#[derive(Debug, Clone, Copy)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub state: PortState,
    /// Connect round-trip time in milliseconds (only meaningful for `Open`).
    pub rtt_ms: Option<u64>,
}

/// Runtime knobs for a scan pass.
pub struct ScanRuntime {
    /// Maximum simultaneous connection attempts.
    pub concurrency: usize,
    /// Per-connection timeout.
    pub timeout: Duration,
    /// Retries for ambiguous (timed-out) probes.
    pub retries: u32,
    /// Optional global rate limiter (probes/sec).
    pub limiter: Option<Arc<DefaultDirectRateLimiter>>,
    /// Optional progress bar, ticked once per completed probe.
    pub progress: Option<ProgressBar>,
}

/// Scan every `(ip, port)` pair and return one [`ProbeResult`] per pair.
///
/// Concurrency is bounded by `rt.concurrency` using a [`JoinSet`] as a sliding
/// window: once the window is full we wait for one probe to finish before
/// launching the next, keeping memory flat regardless of target count.
pub async fn run_scan(
    targets: Vec<IpAddr>,
    ports: Arc<Vec<u16>>,
    rt: ScanRuntime,
) -> Vec<ProbeResult> {
    let total = targets.len().saturating_mul(ports.len());
    let concurrency = rt.concurrency.max(1);
    let mut set: JoinSet<ProbeResult> = JoinSet::new();
    let mut results: Vec<ProbeResult> = Vec::with_capacity(total);

    for ip in targets {
        for &port in ports.iter() {
            while set.len() >= concurrency {
                if let Some(joined) = set.join_next().await {
                    collect(joined, &mut results, rt.progress.as_ref());
                } else {
                    break;
                }
            }
            // Apply the global rate cap before launching, if configured.
            if let Some(limiter) = &rt.limiter {
                limiter.until_ready().await;
            }
            let timeout = rt.timeout;
            let retries = rt.retries;
            set.spawn(async move { probe(ip, port, timeout, retries).await });
        }
    }

    while let Some(joined) = set.join_next().await {
        collect(joined, &mut results, rt.progress.as_ref());
    }

    if let Some(pb) = &rt.progress {
        pb.finish_and_clear();
    }
    results
}

fn collect(
    joined: Result<ProbeResult, JoinError>,
    out: &mut Vec<ProbeResult>,
    pb: Option<&ProgressBar>,
) {
    match joined {
        Ok(result) => {
            if let Some(pb) = pb {
                pb.inc(1);
            }
            out.push(result);
        }
        // probe() cannot panic on recoverable errors; a JoinError means the task
        // was cancelled or panicked. Log and drop that single probe.
        Err(e) => tracing::error!(error = %e, "probe task failed to join"),
    }
}

/// Probe a single port with a bounded-time TCP connect, retrying only on
/// ambiguous (timeout) outcomes. A refused connection is a definitive "closed"
/// and is never retried.
async fn probe(ip: IpAddr, port: u16, timeout: Duration, retries: u32) -> ProbeResult {
    let addr = SocketAddr::new(ip, port);
    let mut attempt: u32 = 0;
    loop {
        let started = Instant::now();
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let rtt = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                // Read-only: close immediately without sending anything.
                drop(stream);
                return ProbeResult {
                    ip,
                    port,
                    state: PortState::Open,
                    rtt_ms: Some(rtt),
                };
            }
            Ok(Err(e)) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    return ProbeResult {
                        ip,
                        port,
                        state: PortState::Closed,
                        rtt_ms: None,
                    };
                }
                // Unreachable/other transient errors: retry, then call it filtered.
                if attempt < retries {
                    attempt += 1;
                    continue;
                }
                return ProbeResult {
                    ip,
                    port,
                    state: PortState::Filtered,
                    rtt_ms: None,
                };
            }
            Err(_elapsed) => {
                if attempt < retries {
                    attempt += 1;
                    continue;
                }
                return ProbeResult {
                    ip,
                    port,
                    state: PortState::Filtered,
                    rtt_ms: None,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn detects_open_and_closed_ports() {
        // Bind an ephemeral listener; its port is Open.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = listener.local_addr().unwrap().port();

        // Bind and immediately drop another to obtain a very likely-closed port.
        let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = tmp.local_addr().unwrap().port();
        drop(tmp);

        let ports = Arc::new(vec![open_port, closed_port]);
        let rt = ScanRuntime {
            concurrency: 16,
            timeout: Duration::from_millis(500),
            retries: 0,
            limiter: None,
            progress: None,
        };
        let results = run_scan(vec![IpAddr::from([127, 0, 0, 1])], ports, rt).await;

        let open = results.iter().find(|r| r.port == open_port).unwrap();
        assert_eq!(open.state, PortState::Open);

        let closed = results.iter().find(|r| r.port == closed_port).unwrap();
        // Loopback refuses connections to unbound ports rather than dropping them.
        assert_eq!(closed.state, PortState::Closed);
    }
}
