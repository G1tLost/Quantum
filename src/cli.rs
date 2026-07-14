//! Command-line interface (clap v4, derive API).
//!
//! This module only *describes* the CLI surface. Validation, defaulting, and
//! assembly into a runnable [`crate::config::ScanConfig`] happen in
//! [`crate::config`].

use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};

/// Fast, safety-first network scanner for **authorized** defensive assessments.
///
/// ferroscan performs read-only TCP connect scanning. It does not exploit,
/// brute-force, fuzz, or otherwise attempt to degrade a target.
#[derive(Debug, Parser)]
#[command(
    name = "ferroscan",
    version,
    about = "Fast, safety-first network scanner for authorized defensive assessments",
    long_about = None,
)]
pub struct Cli {
    /// Targets: IP, CIDR (a.b.c.d/24), range (a.b.c.d-e.f.g.h or a.b.c.d-N), or hostname.
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Read additional targets from a file (one per line; blank lines and `#` comments ignored).
    #[arg(short = 'f', long = "target-file", value_name = "FILE")]
    pub target_file: Option<PathBuf>,

    /// Ports to scan: comma list and/or ranges, e.g. `22,80,443,8000-8100`.
    #[arg(short = 'p', long = "ports", value_name = "SPEC")]
    pub ports: Option<String>,

    /// Scan the top N most common TCP ports.
    #[arg(long = "top-ports", value_name = "N", conflicts_with_all = ["ports", "all_ports"])]
    pub top_ports: Option<usize>,

    /// Scan all TCP ports (1-65535).
    #[arg(long = "all-ports", conflicts_with_all = ["ports", "top_ports"])]
    pub all_ports: bool,

    /// Maximum concurrent connection attempts. Defaults to a value derived from the
    /// file-descriptor limit (see --ulimit) and the selected --profile.
    #[arg(short = 'c', long = "concurrency", value_name = "N")]
    pub concurrency: Option<usize>,

    /// Per-connection timeout in milliseconds.
    #[arg(long = "timeout", value_name = "MS")]
    pub timeout_ms: Option<u64>,

    /// Retries for ambiguous (timed-out) probes. Refused ports are never retried.
    #[arg(long = "retries", value_name = "N")]
    pub retries: Option<u32>,

    /// Raise the file-descriptor soft limit toward this value before scanning
    /// (capped at the hard limit).
    #[arg(long = "ulimit", value_name = "N")]
    pub ulimit: Option<u64>,

    /// Timing/safety profile controlling concurrency, timeouts, and rate caps.
    #[arg(long = "profile", value_enum, default_value_t = Profile::Normal)]
    pub profile: Profile,

    /// Global cap on connection attempts per second. Overrides the profile default.
    #[arg(long = "max-rate", value_name = "PPS")]
    pub max_rate: Option<u32>,

    /// Authorized scope entry (CIDR/IP/hostname). Repeatable. Targets resolving
    /// outside every scope entry are refused and logged.
    #[arg(long = "scope", value_name = "CIDR")]
    pub scope: Vec<String>,

    /// Read authorized scope entries from a file (one per line; `#` comments ignored).
    #[arg(long = "scope-file", value_name = "FILE")]
    pub scope_file: Option<PathBuf>,

    /// Acknowledge that you are authorized to scan the target scope. Recorded in
    /// the report metadata. (A hard authorization gate + audit log arrives in a
    /// later phase; today this records intent and suppresses the reminder banner.)
    #[arg(long = "i-have-authorization")]
    pub authorized: bool,

    /// Enable TCP-ping host discovery: probe common ports first and skip hosts
    /// that show no response. Off by default (all in-scope hosts are scanned).
    #[arg(long = "ping")]
    pub ping: bool,

    /// Output format.
    #[arg(long = "format", value_enum, default_value_t = Format::Human)]
    pub format: Format,

    /// Write the report to a file instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Disable the progress bar (also auto-disabled when stderr is not a TTY).
    #[arg(long = "no-progress")]
    pub no_progress: bool,

    /// Safety cap on how many hosts a target expansion may produce.
    #[arg(long = "max-targets", value_name = "N", default_value_t = 65536)]
    pub max_targets: usize,

    /// Increase logging verbosity (-v = debug, -vv = trace).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,
}

/// Timing/safety profiles, loosely mirroring nmap timing templates.
///
/// Explicit flags (`--concurrency`, `--timeout`, `--retries`, `--max-rate`)
/// always override the profile's suggested value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// Extremely gentle: tiny concurrency, long timeouts, hard rate cap. For fragile devices.
    Paranoid,
    /// Gentle: modest concurrency, generous timeouts, moderate rate cap.
    Polite,
    /// Balanced default: fd-derived concurrency, no rate cap.
    Normal,
    /// Fast: maximum fd-derived concurrency, short timeouts, no retries.
    Aggressive,
}

impl Profile {
    /// Human-readable name used in reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Paranoid => "paranoid",
            Profile::Polite => "polite",
            Profile::Normal => "normal",
            Profile::Aggressive => "aggressive",
        }
    }

    /// Suggested per-connection timeout (ms) when the user does not set `--timeout`.
    pub fn default_timeout_ms(self) -> u64 {
        match self {
            Profile::Paranoid => 3000,
            Profile::Polite => 2000,
            Profile::Normal => 1500,
            Profile::Aggressive => 800,
        }
    }

    /// Suggested retry count when the user does not set `--retries`.
    pub fn default_retries(self) -> u32 {
        match self {
            Profile::Paranoid => 2,
            Profile::Polite => 1,
            Profile::Normal => 1,
            Profile::Aggressive => 0,
        }
    }

    /// A hard cap on concurrency for gentle profiles, regardless of fd budget.
    /// `None` means "use the fd-derived budget".
    pub fn concurrency_cap(self) -> Option<usize> {
        match self {
            Profile::Paranoid => Some(8),
            Profile::Polite => Some(128),
            Profile::Normal | Profile::Aggressive => None,
        }
    }

    /// Suggested global rate cap (probes/sec) when the user does not set `--max-rate`.
    pub fn default_max_rate(self) -> Option<u32> {
        match self {
            Profile::Paranoid => Some(10),
            Profile::Polite => Some(200),
            Profile::Normal | Profile::Aggressive => None,
        }
    }
}

/// Report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Human-readable summary table.
    Human,
    /// Structured JSON (the machine-readable source of truth).
    Json,
}
