//! ferroscan — a fast, safety-first network scanner for **authorized** defensive
//! assessments.
//!
//! The library is organized into focused modules that mirror the scan pipeline:
//!
//! - [`cli`] — command-line surface (clap derive).
//! - [`config`] — target/port/scope parsing and validated [`config::ScanConfig`].
//! - [`discovery`] — host liveness (TCP ping).
//! - [`scanner`] — the async connect-scan core and adaptive batching.
//! - [`report`] — the serde data model (source of truth) and renderers.
//! - [`runner`] — orchestration tying the pipeline together.
//! - [`error`] — the crate error type.
//!
//! # Safety boundary
//!
//! ferroscan is a **defensive assessment** tool. It performs read-only TCP
//! connect probing and metadata inspection only. It never exploits, delivers
//! payloads, brute-forces credentials, or emits traffic designed to degrade a
//! target. Anything that cannot be done safely and read-only does not belong in
//! this crate.

pub mod cli;
pub mod config;
pub mod discovery;
pub mod error;
pub mod report;
pub mod runner;
pub mod scanner;

pub use error::{Error, Result};
