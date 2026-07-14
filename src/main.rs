//! ferroscan binary entry point.
//!
//! Kept thin: parse the CLI, initialize tracing, assemble configuration, run the
//! scan via the library, and render the report. All fallible work returns
//! `Result`; `anyhow` provides context at this boundary.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use clap::Parser;

use ferroscan::cli::{Cli, Format};
use ferroscan::config::ScanConfig;
use ferroscan::report::ScanReport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    // Capture output settings before `cli` is consumed by config assembly.
    let format = cli.format;
    let output = cli.output.clone();

    let config = ScanConfig::from_cli(cli)
        .await
        .context("assembling scan configuration")?;
    let report = ferroscan::runner::run(config)
        .await
        .context("running scan")?;

    render(&report, format, output.as_deref()).context("writing report")?;
    Ok(())
}

/// Configure tracing to stderr so stdout stays clean for report output.
fn init_tracing(verbose: u8) {
    use tracing_subscriber::{fmt, EnvFilter};

    let default_level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    // `try_init` avoids panicking if a subscriber is somehow already installed.
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

fn render(report: &ScanReport, format: Format, output: Option<&Path>) -> anyhow::Result<()> {
    match output {
        Some(path) => {
            let file = std::fs::File::create(path)
                .with_context(|| format!("creating output file {}", path.display()))?;
            let mut writer = std::io::BufWriter::new(file);
            write_report(report, format, &mut writer)?;
            writer.flush()?;
        }
        None => {
            let stdout = std::io::stdout();
            let mut writer = stdout.lock();
            write_report(report, format, &mut writer)?;
        }
    }
    Ok(())
}

fn write_report<W: Write>(
    report: &ScanReport,
    format: Format,
    writer: &mut W,
) -> anyhow::Result<()> {
    match format {
        Format::Json => report.write_json(writer)?,
        Format::Human => report.write_human(writer)?,
    }
    Ok(())
}
