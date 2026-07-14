//! Scan orchestration: expand targets → enforce scope → (optionally) discover →
//! plan concurrency → scan → assemble the report.
//!
//! This is the single place where all the pieces come together, and where the
//! operational-safety checks (scope enforcement, authorization reminders, rate
//! control) are wired in front of any network activity.

use std::io::IsTerminal;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use governor::{Quota, RateLimiter};
use indicatif::{ProgressBar, ProgressStyle};

use crate::config::target::resolve_and_expand;
use crate::config::ScanConfig;
use crate::discovery;
use crate::error::{Error, Result};
use crate::report::{now_epoch_ms, ReportInputs, ScanReport};
use crate::scanner::{batch, run_scan, ScanRuntime};

/// Number of file descriptors a single discovery host uses (one per ping port).
const DISCOVERY_FANOUT: usize = 5;

/// Run a full scan and return the assembled report.
pub async fn run(config: ScanConfig) -> Result<ScanReport> {
    // --- Operational-safety posture (warn now; a later phase hard-gates) ---
    if config.scope.is_empty() {
        tracing::warn!(
            "no --scope configured: every resolved target will be scanned. Configure an \
             authorized scope allowlist for safe operation."
        );
    }
    if !config.authorized {
        tracing::warn!(
            "authorization not acknowledged (--i-have-authorization); only scan systems you \
             are contractually authorized to assess."
        );
    }

    // --- 1. Expand targets to concrete IPs (DNS resolution + safety cap) ---
    let expanded = resolve_and_expand(&config.targets, config.max_targets).await?;
    if expanded.is_empty() {
        return Err(Error::NoTargets { stage: "expansion" });
    }

    // --- 2. Enforce authorized scope BEFORE any packet is sent ---
    let (in_scope, refused) = config.scope.partition(expanded);
    for ip in &refused {
        tracing::warn!(target = %ip, "refusing out-of-scope target");
    }
    let hosts_in_scope = in_scope.len();
    let hosts_refused = refused.len();
    if in_scope.is_empty() {
        return Err(Error::NoTargets {
            stage: "scope enforcement",
        });
    }

    // --- 3. Plan adaptive concurrency from the fd limit + profile ---
    let plan = batch::plan(config.requested_concurrency, config.ulimit, config.profile)?;
    tracing::info!(
        concurrency = plan.concurrency,
        fd_soft = plan.fd_soft,
        fd_hard = plan.fd_hard,
        fd_budget = plan.fd_budget,
        "concurrency plan"
    );

    // --- 4. Optional host discovery (TCP ping) ---
    let targets = if config.ping {
        let disc_conc = (plan.concurrency / DISCOVERY_FANOUT).max(1);
        let up = discovery::tcp_ping(in_scope.clone(), config.timeout, disc_conc).await;
        tracing::info!(up = up.len(), total = hosts_in_scope, "discovery complete");
        if up.is_empty() {
            return Err(Error::NoTargets { stage: "discovery" });
        }
        up
    } else {
        in_scope
    };
    let hosts_scanned = targets.len();

    // --- 5. Optional global rate limiter ---
    let limiter = config
        .max_rate
        .and_then(NonZeroU32::new)
        .map(|r| Arc::new(RateLimiter::direct(Quota::per_second(r))));
    if let Some(rate) = config.max_rate.filter(|r| *r > 0) {
        tracing::info!(rate_pps = rate, "global rate cap enabled");
    }

    // --- 6. Progress UX ---
    let ports = Arc::new(config.ports.clone());
    let total_probes = hosts_scanned.saturating_mul(ports.len());
    let progress = build_progress(config.progress, total_probes as u64);

    // --- 7. Run the scan ---
    let started_ms = now_epoch_ms();
    let clock = Instant::now();
    let rt = ScanRuntime {
        concurrency: plan.concurrency,
        timeout: config.timeout,
        retries: config.retries,
        limiter,
        progress,
    };
    let results = run_scan(targets, Arc::clone(&ports), rt).await;
    let duration_ms = clock.elapsed().as_millis();

    // --- 8. Assemble the report (JSON source of truth) ---
    let inputs = ReportInputs {
        profile: config.profile.as_str().to_string(),
        authorized_ack: config.authorized,
        started_at_epoch_ms: started_ms,
        duration_ms,
        target_inputs: config.target_inputs.clone(),
        scope: config.scope.raw().to_vec(),
        hosts_in_scope,
        hosts_refused_out_of_scope: hosts_refused,
        hosts_scanned,
        ports_per_host: ports.len(),
        concurrency: plan.concurrency,
        timeout_ms: config.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
        retries: config.retries,
    };
    Ok(ScanReport::build(&results, inputs))
}

fn build_progress(enabled: bool, total: u64) -> Option<ProgressBar> {
    if !enabled || !std::io::stderr().is_terminal() {
        return None;
    }
    let pb = ProgressBar::new(total);
    if let Ok(style) = ProgressStyle::with_template(
        "{spinner} [{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) {msg}",
    ) {
        pb.set_style(style);
    }
    pb.set_message("scanning");
    Some(pb)
}
