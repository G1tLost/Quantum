//! Crate-wide error type.
//!
//! Library code returns [`Result`] (this crate's alias) and never panics on
//! recoverable conditions — no `unwrap()`/`expect()` on fallible values in
//! library paths. The binary boundary (`main`) upgrades these into
//! `anyhow::Result` for reporting.

use thiserror::Error;

/// Errors produced by ferroscan's library paths.
#[derive(Debug, Error)]
pub enum Error {
    /// A target token (IP/CIDR/range/hostname) could not be parsed.
    #[error("invalid target '{token}': {reason}")]
    TargetParse { token: String, reason: String },

    /// A port specification could not be parsed.
    #[error("invalid port specification '{spec}': {reason}")]
    PortParse { spec: String, reason: String },

    /// The requested target expansion exceeded the configured safety cap.
    #[error(
        "target expansion would produce {count} hosts, exceeding the --max-targets cap of {cap}; \
         narrow the scope or raise --max-targets"
    )]
    TooManyTargets { count: usize, cap: usize },

    /// A scope entry could not be parsed.
    #[error("invalid scope entry '{entry}': {reason}")]
    ScopeParse { entry: String, reason: String },

    /// DNS resolution failed for a hostname.
    #[error("could not resolve host '{host}': {reason}")]
    DnsResolution { host: String, reason: String },

    /// Reading or raising the file-descriptor limit failed.
    #[error("file-descriptor limit error: {0}")]
    Rlimit(String),

    /// No usable targets remained after parsing/scoping/discovery.
    #[error("no scannable targets remain after {stage}")]
    NoTargets { stage: &'static str },

    /// No ports were selected to scan.
    #[error("no ports selected; pass --ports, --top-ports, or --all-ports")]
    NoPorts,

    /// Failed to read a file (target list or scope file).
    #[error("could not read {kind} file '{path}': {source}")]
    FileRead {
        kind: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// A wrapped I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON (de)serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;
