//! Integration tests exercising the public library API end-to-end against a
//! local mock TCP service. These require no network access and no privileges.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ferroscan::scanner::{run_scan, PortState, ScanRuntime};
use tokio::net::TcpListener;

/// Spin up a real listener and confirm the connect scanner reports it Open,
/// while an unbound loopback port reports Closed.
#[tokio::test]
async fn scans_local_mock_service() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let open_port = listener.local_addr().unwrap().port();

    // Keep accepting so the port stays open for the duration of the scan.
    let accept_task = tokio::spawn(async move {
        // Accept a few connections then return; the scanner opens exactly one.
        for _ in 0..8 {
            if tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Obtain a port that is very likely closed by binding then dropping it.
    let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = tmp.local_addr().unwrap().port();
    drop(tmp);

    let ports = Arc::new(vec![open_port, closed_port]);
    let rt = ScanRuntime {
        concurrency: 64,
        timeout: Duration::from_millis(500),
        retries: 1,
        limiter: None,
        progress: None,
    };

    let results = run_scan(vec![IpAddr::from([127, 0, 0, 1])], ports, rt).await;
    assert_eq!(results.len(), 2);

    let open = results.iter().find(|r| r.port == open_port).unwrap();
    assert_eq!(open.state, PortState::Open, "listener port should be open");

    let closed = results.iter().find(|r| r.port == closed_port).unwrap();
    assert_eq!(
        closed.state,
        PortState::Closed,
        "unbound loopback port should be refused (closed)"
    );

    accept_task.abort();
}

/// The full config → run pipeline against loopback, with scope enforcement and
/// a report assembled from real probe results.
#[tokio::test]
async fn end_to_end_run_against_loopback() {
    use ferroscan::cli::{Cli, Format, Profile};
    use ferroscan::config::ScanConfig;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let open_port = listener.local_addr().unwrap().port();
    let accept_task = tokio::spawn(async move {
        for _ in 0..8 {
            if tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let cli = Cli {
        targets: vec!["127.0.0.1".to_string()],
        target_file: None,
        ports: Some(open_port.to_string()),
        top_ports: None,
        all_ports: false,
        concurrency: Some(32),
        timeout_ms: Some(500),
        retries: Some(1),
        ulimit: None,
        profile: Profile::Normal,
        max_rate: None,
        scope: vec!["127.0.0.0/8".to_string()],
        scope_file: None,
        authorized: true,
        ping: false,
        format: Format::Json,
        output: None,
        no_progress: true,
        max_targets: 65536,
        verbose: 0,
    };

    let config = ScanConfig::from_cli(cli).await.unwrap();
    let report = ferroscan::runner::run(config).await.unwrap();

    assert_eq!(report.meta.hosts_scanned, 1);
    assert_eq!(report.summary.open_ports, 1);
    assert_eq!(report.summary.hosts_up, 1);
    assert_eq!(report.hosts[0].ip, IpAddr::from([127, 0, 0, 1]));
    assert_eq!(report.hosts[0].open_ports[0].port, open_port);
    assert!(report.meta.authorized_ack);

    // Report serializes to JSON cleanly.
    let json = report.to_json().unwrap();
    assert!(json.contains("\"tool\": \"ferroscan\""));

    accept_task.abort();
}

/// Scope enforcement must refuse a target outside the allowlist.
#[tokio::test]
async fn out_of_scope_target_is_refused() {
    use ferroscan::cli::{Cli, Format, Profile};
    use ferroscan::config::ScanConfig;
    use ferroscan::error::Error;

    let cli = Cli {
        targets: vec!["10.99.99.99".to_string()],
        target_file: None,
        ports: Some("80".to_string()),
        top_ports: None,
        all_ports: false,
        concurrency: Some(8),
        timeout_ms: Some(200),
        retries: Some(0),
        ulimit: None,
        profile: Profile::Normal,
        max_rate: None,
        scope: vec!["127.0.0.0/8".to_string()], // does not include 10.99.99.99
        scope_file: None,
        authorized: true,
        ping: false,
        format: Format::Json,
        output: None,
        no_progress: true,
        max_targets: 65536,
        verbose: 0,
    };

    let config = ScanConfig::from_cli(cli).await.unwrap();
    let err = ferroscan::runner::run(config).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::NoTargets {
                stage: "scope enforcement"
            }
        ),
        "expected scope enforcement to leave no scannable targets, got {err:?}"
    );
}
