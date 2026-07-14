//! Adaptive concurrency planning.
//!
//! A TCP connect scan consumes one file descriptor per in-flight connection, so
//! the natural ceiling on concurrency is the process's `RLIMIT_NOFILE` soft
//! limit. This is the "RustScan trick": read the ulimit, optionally raise it,
//! and size the concurrent batch to fit inside it with headroom left for stdio,
//! DNS sockets, and the tracing/progress machinery.

use rlimit::Resource;

use crate::cli::Profile;
use crate::error::{Error, Result};

/// File descriptors reserved for everything that is *not* a scan connection.
const FD_HEADROOM: u64 = 64;

/// The concurrency decision plus the fd facts that produced it, for logging.
#[derive(Debug, Clone, Copy)]
pub struct BatchPlan {
    /// Effective maximum number of simultaneous connection attempts.
    pub concurrency: usize,
    /// The fd soft limit in effect after any raise attempt.
    pub fd_soft: u64,
    /// The fd hard limit.
    pub fd_hard: u64,
    /// The fd budget available to the scan (`fd_soft - headroom`).
    pub fd_budget: usize,
}

/// Compute the concurrency plan.
///
/// * `requested` — an explicit `--concurrency` value, if any.
/// * `ulimit_target` — an explicit `--ulimit` value to raise the soft limit to.
/// * `profile` — supplies a hard concurrency cap for gentle profiles.
///
/// The effective concurrency is the minimum of: the requested value (or the fd
/// budget if unset), the fd budget, and the profile cap.
pub fn plan(
    requested: Option<usize>,
    ulimit_target: Option<u64>,
    profile: Profile,
) -> Result<BatchPlan> {
    let (mut soft, hard) = Resource::NOFILE
        .get()
        .map_err(|e| Error::Rlimit(format!("reading RLIMIT_NOFILE: {e}")))?;

    // Optionally raise the soft limit toward the requested value (never above hard).
    if let Some(target) = ulimit_target {
        let new_soft = target.min(hard);
        if new_soft > soft {
            match Resource::NOFILE.set(new_soft, hard) {
                Ok(()) => {
                    tracing::info!(from = soft, to = new_soft, "raised fd soft limit");
                    soft = new_soft;
                }
                Err(e) => {
                    tracing::warn!(error = %e, target = new_soft, "could not raise fd soft limit; using current");
                }
            }
        }
    }

    let fd_budget = (soft.saturating_sub(FD_HEADROOM)).max(1) as usize;

    // Start from the requested value or the full budget, then clamp.
    let mut concurrency = requested.unwrap_or(fd_budget).min(fd_budget);
    if let Some(cap) = profile.concurrency_cap() {
        concurrency = concurrency.min(cap);
    }
    let concurrency = concurrency.max(1);

    if let Some(req) = requested {
        if req > fd_budget {
            tracing::warn!(
                requested = req,
                fd_budget,
                "requested concurrency exceeds the fd budget; clamping (raise --ulimit to go higher)"
            );
        }
    }

    Ok(BatchPlan {
        concurrency,
        fd_soft: soft,
        fd_hard: hard,
        fd_budget,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_positive_and_within_budget() {
        let plan = plan(None, None, Profile::Normal).unwrap();
        assert!(plan.concurrency >= 1);
        assert!(plan.concurrency <= plan.fd_budget);
    }

    #[test]
    fn explicit_request_is_clamped_to_budget() {
        let plan = plan(Some(usize::MAX), None, Profile::Normal).unwrap();
        assert_eq!(plan.concurrency, plan.fd_budget);
    }

    #[test]
    fn paranoid_profile_caps_hard() {
        let plan = plan(Some(10_000), None, Profile::Paranoid).unwrap();
        assert!(plan.concurrency <= 8);
    }
}
