//! The scan report: a serde data model that is the machine-readable **source of
//! truth**, plus renderers. JSON is emitted verbatim from these structs; the
//! human summary is derived from the same data. CSV and HTML renderers (Phase 4)
//! will derive from this identical model.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::scanner::{PortState, ProbeResult};

/// Top-level scan report.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub meta: ScanMeta,
    pub summary: Summary,
    pub hosts: Vec<HostReport>,
}

/// Scan-level metadata (targets, timing, tool version, profile).
#[derive(Debug, Serialize)]
pub struct ScanMeta {
    pub tool: String,
    pub version: String,
    pub profile: String,
    pub authorized_ack: bool,
    pub started_at_utc: String,
    pub started_at_epoch_ms: u64,
    pub duration_ms: u128,
    pub target_inputs: Vec<String>,
    pub scope: Vec<String>,
    pub hosts_in_scope: usize,
    pub hosts_refused_out_of_scope: usize,
    pub hosts_scanned: usize,
    pub ports_per_host: usize,
    pub total_probes: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u32,
    pub probes_per_second: f64,
}

/// Severity-style rollup counts. (Vulnerability severity rollups arrive with the
/// vuln engine in Phase 3; today this rolls up port states.)
#[derive(Debug, Serialize)]
pub struct Summary {
    pub hosts_up: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
}

/// Per-host findings. Only hosts with at least one open port are listed; the
/// closed/filtered totals live in [`Summary`].
#[derive(Debug, Serialize)]
pub struct HostReport {
    pub ip: IpAddr,
    pub open_ports: Vec<PortReport>,
}

/// A single open-port finding. Phase 2+ extends this with service, product,
/// version, CPE, TLS metadata, and vulnerability findings.
#[derive(Debug, Serialize)]
pub struct PortReport {
    pub port: u16,
    pub transport: String,
    pub state: String,
    pub rtt_ms: Option<u64>,
}

/// Inputs needed to assemble a report alongside the raw probe results.
pub struct ReportInputs {
    pub profile: String,
    pub authorized_ack: bool,
    pub started_at_epoch_ms: u64,
    pub duration_ms: u128,
    pub target_inputs: Vec<String>,
    pub scope: Vec<String>,
    pub hosts_in_scope: usize,
    pub hosts_refused_out_of_scope: usize,
    pub hosts_scanned: usize,
    pub ports_per_host: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u32,
}

impl ScanReport {
    /// Build a report from probe results and scan inputs.
    pub fn build(results: &[ProbeResult], inputs: ReportInputs) -> ScanReport {
        let mut open_by_host: BTreeMap<IpAddr, Vec<PortReport>> = BTreeMap::new();
        let (mut open, mut closed, mut filtered) = (0usize, 0usize, 0usize);

        for r in results {
            match r.state {
                PortState::Open => {
                    open += 1;
                    open_by_host.entry(r.ip).or_default().push(PortReport {
                        port: r.port,
                        transport: "tcp".into(),
                        state: "open".into(),
                        rtt_ms: r.rtt_ms,
                    });
                }
                PortState::Closed => closed += 1,
                PortState::Filtered => filtered += 1,
            }
        }

        let hosts: Vec<HostReport> = open_by_host
            .into_iter()
            .map(|(ip, mut ports)| {
                ports.sort_unstable_by_key(|p| p.port);
                HostReport {
                    ip,
                    open_ports: ports,
                }
            })
            .collect();

        let total_probes = results.len();
        let secs = inputs.duration_ms as f64 / 1000.0;
        let pps = if secs > 0.0 {
            total_probes as f64 / secs
        } else {
            total_probes as f64
        };

        ScanReport {
            meta: ScanMeta {
                tool: "ferroscan".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                profile: inputs.profile,
                authorized_ack: inputs.authorized_ack,
                started_at_utc: format_rfc3339_utc(inputs.started_at_epoch_ms),
                started_at_epoch_ms: inputs.started_at_epoch_ms,
                duration_ms: inputs.duration_ms,
                target_inputs: inputs.target_inputs,
                scope: inputs.scope,
                hosts_in_scope: inputs.hosts_in_scope,
                hosts_refused_out_of_scope: inputs.hosts_refused_out_of_scope,
                hosts_scanned: inputs.hosts_scanned,
                ports_per_host: inputs.ports_per_host,
                total_probes,
                concurrency: inputs.concurrency,
                timeout_ms: inputs.timeout_ms,
                retries: inputs.retries,
                probes_per_second: (pps * 100.0).round() / 100.0,
            },
            summary: Summary {
                hosts_up: hosts.len(),
                open_ports: open,
                closed_ports: closed,
                filtered_ports: filtered,
            },
            hosts,
        }
    }

    /// Serialize the report as pretty JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(Error::from)
    }

    /// Write the JSON report to a writer.
    pub fn write_json<W: Write>(&self, mut w: W) -> Result<()> {
        let json = self.to_json()?;
        w.write_all(json.as_bytes())?;
        w.write_all(b"\n")?;
        Ok(())
    }

    /// Write a human-readable summary to a writer.
    pub fn write_human<W: Write>(&self, mut w: W) -> Result<()> {
        let m = &self.meta;
        let s = &self.summary;
        writeln!(w, "ferroscan v{} — scan complete", m.version)?;
        writeln!(
            w,
            "profile: {} | concurrency: {} | timeout: {}ms | retries: {}",
            m.profile, m.concurrency, m.timeout_ms, m.retries
        )?;
        writeln!(
            w,
            "started: {} | duration: {:.2}s | throughput: {:.0} probes/s",
            m.started_at_utc,
            m.duration_ms as f64 / 1000.0,
            m.probes_per_second
        )?;
        if m.scope.is_empty() {
            writeln!(w, "scope: (none configured)")?;
        } else {
            writeln!(w, "scope: {}", m.scope.join(", "))?;
        }
        writeln!(
            w,
            "hosts: {} in scope, {} scanned, {} up ({} refused out-of-scope)",
            m.hosts_in_scope, m.hosts_scanned, s.hosts_up, m.hosts_refused_out_of_scope
        )?;
        writeln!(
            w,
            "probes: {} total | open: {} | closed: {} | filtered: {}",
            m.total_probes, s.open_ports, s.closed_ports, s.filtered_ports
        )?;
        writeln!(w)?;

        if self.hosts.is_empty() {
            writeln!(w, "No open ports found.")?;
            return Ok(());
        }

        writeln!(w, "{:<39}  {:<10}  {:<7}  RTT", "HOST", "PORT", "STATE")?;
        writeln!(w, "{}", "-".repeat(72))?;
        for host in &self.hosts {
            for p in &host.open_ports {
                let rtt = p
                    .rtt_ms
                    .map(|r| format!("{r}ms"))
                    .unwrap_or_else(|| "-".into());
                writeln!(
                    w,
                    "{:<39}  {:<10}  {:<7}  {}",
                    host.ip.to_string(),
                    format!("{}/{}", p.port, p.transport),
                    p.state,
                    rtt
                )?;
            }
        }
        Ok(())
    }
}

/// The current wall-clock time in Unix epoch milliseconds.
pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Format epoch-millis as an RFC 3339 UTC timestamp without pulling in a date
/// crate (Hinnant's `civil_from_days` algorithm).
fn format_rfc3339_utc(epoch_ms: u64) -> String {
    let secs = (epoch_ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_epoch() {
        // 2021-01-01T00:00:00Z == 1_609_459_200 s
        assert_eq!(
            format_rfc3339_utc(1_609_459_200_000),
            "2021-01-01T00:00:00Z"
        );
        // Unix epoch.
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // A time with a nonzero clock component: 2026-07-14T16:20:00Z
        assert_eq!(
            format_rfc3339_utc(1_784_046_000_000),
            "2026-07-14T16:20:00Z"
        );
    }

    #[test]
    fn build_rolls_up_states_and_groups_open_ports() {
        let results = vec![
            ProbeResult {
                ip: IpAddr::from([10, 0, 0, 1]),
                port: 443,
                state: PortState::Open,
                rtt_ms: Some(2),
            },
            ProbeResult {
                ip: IpAddr::from([10, 0, 0, 1]),
                port: 22,
                state: PortState::Open,
                rtt_ms: Some(1),
            },
            ProbeResult {
                ip: IpAddr::from([10, 0, 0, 1]),
                port: 25,
                state: PortState::Closed,
                rtt_ms: None,
            },
            ProbeResult {
                ip: IpAddr::from([10, 0, 0, 2]),
                port: 80,
                state: PortState::Filtered,
                rtt_ms: None,
            },
        ];
        let inputs = ReportInputs {
            profile: "normal".into(),
            authorized_ack: true,
            started_at_epoch_ms: 0,
            duration_ms: 1000,
            target_inputs: vec!["10.0.0.0/30".into()],
            scope: vec!["10.0.0.0/24".into()],
            hosts_in_scope: 2,
            hosts_refused_out_of_scope: 0,
            hosts_scanned: 2,
            ports_per_host: 2,
            concurrency: 16,
            timeout_ms: 1500,
            retries: 1,
        };
        let report = ScanReport::build(&results, inputs);

        assert_eq!(report.summary.open_ports, 2);
        assert_eq!(report.summary.closed_ports, 1);
        assert_eq!(report.summary.filtered_ports, 1);
        assert_eq!(report.summary.hosts_up, 1);
        assert_eq!(report.meta.total_probes, 4);
        assert_eq!(report.meta.probes_per_second, 4.0);

        // Open ports for host .1 are sorted ascending.
        let host = &report.hosts[0];
        assert_eq!(host.ip, IpAddr::from([10, 0, 0, 1]));
        assert_eq!(
            host.open_ports.iter().map(|p| p.port).collect::<Vec<_>>(),
            vec![22, 443]
        );

        // Report round-trips through JSON.
        assert!(report.to_json().unwrap().contains("\"probes_per_second\""));
    }
}
