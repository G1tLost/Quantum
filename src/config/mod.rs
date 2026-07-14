//! Configuration assembly: validate a parsed [`Cli`] into a runnable
//! [`ScanConfig`], applying profile defaults where the user did not override.

pub mod ports;
pub mod scope;
pub mod target;

use std::path::PathBuf;
use std::time::Duration;

use crate::cli::{Cli, Format, Profile};
use crate::error::{Error, Result};

use scope::Scope;
use target::{parse_target_token, TargetSpec};

/// A fully-validated, ready-to-run scan configuration.
#[derive(Debug)]
pub struct ScanConfig {
    /// Parsed (not yet expanded) target specifications.
    pub targets: Vec<TargetSpec>,
    /// The original target strings, for report metadata.
    pub target_inputs: Vec<String>,
    /// Sorted, de-duplicated ports to scan.
    pub ports: Vec<u16>,
    /// User-requested concurrency cap (may be further limited by the fd budget).
    pub requested_concurrency: Option<usize>,
    /// Per-connection timeout.
    pub timeout: Duration,
    /// Retries for ambiguous (timed-out) probes.
    pub retries: u32,
    /// Optional target for raising the fd soft limit.
    pub ulimit: Option<u64>,
    /// The selected timing/safety profile.
    pub profile: Profile,
    /// Optional global rate cap (probes/sec).
    pub max_rate: Option<u32>,
    /// The authorized scope allowlist.
    pub scope: Scope,
    /// Whether the operator acknowledged authorization.
    pub authorized: bool,
    /// Whether to run TCP-ping host discovery first.
    pub ping: bool,
    /// Report format.
    pub format: Format,
    /// Optional output file (stdout if `None`).
    pub output: Option<PathBuf>,
    /// Whether to render a progress bar.
    pub progress: bool,
    /// Safety cap on expanded host count.
    pub max_targets: usize,
}

impl ScanConfig {
    /// Assemble and validate configuration from parsed CLI arguments.
    ///
    /// This performs all synchronous validation (targets, ports) and resolves
    /// the scope (which may touch DNS for hostname scope entries).
    pub async fn from_cli(cli: Cli) -> Result<ScanConfig> {
        // --- Targets: positional args + optional target file ---
        let mut target_inputs: Vec<String> = cli.targets.clone();
        if let Some(path) = &cli.target_file {
            target_inputs.extend(read_list_file(path, "target")?);
        }
        if target_inputs.is_empty() {
            return Err(Error::NoTargets { stage: "input" });
        }
        let targets: Vec<TargetSpec> = target_inputs
            .iter()
            .map(|t| parse_target_token(t))
            .collect::<Result<_>>()?;

        // --- Ports: exactly one selection mode, defaulting to the top-ports list ---
        let ports = if let Some(spec) = &cli.ports {
            ports::parse_port_spec(spec)?
        } else if let Some(n) = cli.top_ports {
            ports::top_ports(n)?
        } else if cli.all_ports {
            ports::all_ports()
        } else {
            // Sensible default: the built-in top-ports list.
            ports::top_ports(ports::TOP_PORTS.len())?
        };
        if ports.is_empty() {
            return Err(Error::NoPorts);
        }

        // --- Scope: CLI entries + optional scope file ---
        let mut scope_entries = cli.scope.clone();
        if let Some(path) = &cli.scope_file {
            scope_entries.extend(read_list_file(path, "scope")?);
        }
        let scope = Scope::build(&scope_entries).await?;

        // --- Profile-derived defaults (explicit flags win) ---
        let profile = cli.profile;
        let timeout = Duration::from_millis(
            cli.timeout_ms
                .unwrap_or_else(|| profile.default_timeout_ms()),
        );
        let retries = cli.retries.unwrap_or_else(|| profile.default_retries());
        let max_rate = cli.max_rate.or_else(|| profile.default_max_rate());

        Ok(ScanConfig {
            targets,
            target_inputs,
            ports,
            requested_concurrency: cli.concurrency,
            timeout,
            retries,
            ulimit: cli.ulimit,
            profile,
            max_rate,
            scope,
            authorized: cli.authorized,
            ping: cli.ping,
            format: cli.format,
            output: cli.output,
            progress: !cli.no_progress,
            max_targets: cli.max_targets,
        })
    }
}

/// Read a newline-delimited list file, trimming whitespace and skipping blank
/// lines and `#` comments.
fn read_list_file(path: &PathBuf, kind: &'static str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path).map_err(|source| Error::FileRead {
        kind,
        path: path.display().to_string(),
        source,
    })?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}
