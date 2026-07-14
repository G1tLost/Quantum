# ferroscan

A fast, **safety-first** network scanner for **authorized** defensive assessments,
written in Rust. ferroscan combines RustScan-class connect-scan speed with a
roadmap toward Nessus-style assessment: host discovery → fast port scan →
service/version fingerprinting → version-based vulnerability detection → scored,
structured reporting.

> **This is a defensive assessment tool.** It detects and reports; it does not
> exploit. ferroscan performs **read-only** TCP connect probing and metadata
> inspection only. It never delivers payloads, brute-forces credentials, fuzzes,
> or emits traffic designed to degrade a target. Anything that cannot be done
> safely and read-only does not belong in this tool.

## ⚠️ Authorized use only

ferroscan is intended to be run **only** against systems you own or are
explicitly authorized (in writing / under contract) to assess. Unauthorized
scanning may be illegal and is always unwelcome. You are responsible for
staying within your authorized scope.

To support safe operation, ferroscan provides:

- **Scope enforcement** — an allowlist (`--scope` / `--scope-file`); every
  resolved target is checked against it **before any packet is sent**, and
  out-of-scope targets are refused and logged.
- **Rate control** — `--max-rate` plus `--profile paranoid|polite` throttle
  hard for fragile targets.
- **Authorization acknowledgment** — `--i-have-authorization` records operator
  intent in the report metadata.
- **A hard `--max-targets` cap** so a fat CIDR can never silently expand into
  millions of hosts.

## Project status

This repository currently implements **Phase 1** of the build plan. The
architecture and CLI are laid out for the later phases, which are not yet
implemented.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Scan core: CLI, config, async connect-scan with adaptive batching, JSON/human output, scope enforcement, rate control, discovery | ✅ implemented |
| 2 | Fingerprinting: banner grab + probe/response → service, version, CPE; TLS cert metadata | ⏳ planned |
| 3 | Vuln engine: CPE→CVE via NVD (cached + offline), CVSS scoring, safe active checks | ⏳ planned |
| 4 | Reporting: CSV + HTML with severity rollups | ⏳ planned |
| 5 | Safety + polish: hard authorization gate, append-only audit log, SYN-scan feature flag, richer discovery (ICMP/ARP) | ⏳ planned |

## Building

Requires a stable Rust toolchain (2021 edition). Dependencies are fetched from
crates.io, so the build host needs network access to `index.crates.io` /
`static.crates.io`.

```sh
cargo build --release
# binary at ./target/release/ferroscan
```

Run the test suite (unit + integration tests; all local, no network required):

```sh
cargo test
```

Lints and formatting:

```sh
cargo fmt --all
cargo clippy --all-targets
```

## Usage

```
ferroscan [OPTIONS] [TARGET]...
```

Targets may be a single IP, a CIDR block, an IP range, or a hostname. Ports may
be a list/range, the top-N most common, or all 65535.

### Examples

Scan the top-100 ports on a single host (top-ports is the default):

```sh
ferroscan 192.168.1.10 --scope 192.168.1.0/24 --i-have-authorization
```

Scan a /24 for web ports, gently, writing JSON:

```sh
ferroscan 10.0.0.0/24 -p 80,443,8080,8443 \
  --scope 10.0.0.0/24 --profile polite \
  --format json -o scan.json --i-have-authorization
```

Scan an inclusive range with a custom concurrency ceiling and timeout:

```sh
ferroscan 10.0.0.10-10.0.0.50 --top-ports 1000 \
  --concurrency 2000 --timeout 800 \
  --scope 10.0.0.0/24 --i-have-authorization
```

Read targets and scope from files, enable TCP-ping discovery first:

```sh
ferroscan -f targets.txt --scope-file scope.txt --ping --i-have-authorization
```

Benchmark throughput against loopback (safe, all in-scope):

```sh
ferroscan 127.0.0.0/24 --top-ports 100 \
  --scope 127.0.0.0/8 --i-have-authorization --format json | grep probes_per_second
```

### Key options

| Option | Description |
|--------|-------------|
| `[TARGET]...` | IP / CIDR / range (`a.b.c.d-e.f.g.h` or `a.b.c.d-N`) / hostname |
| `-f, --target-file <FILE>` | Read targets from a file (one per line, `#` comments) |
| `-p, --ports <SPEC>` | Ports: `22,80,443,8000-8100` |
| `--top-ports <N>` | Scan the top N common TCP ports |
| `--all-ports` | Scan all 65535 ports |
| `-c, --concurrency <N>` | Max concurrent connections (default: derived from fd limit) |
| `--timeout <MS>` | Per-connection timeout |
| `--retries <N>` | Retries for ambiguous (timed-out) probes |
| `--ulimit <N>` | Raise the fd soft limit toward N before scanning |
| `--profile <P>` | `paranoid` \| `polite` \| `normal` \| `aggressive` |
| `--max-rate <PPS>` | Global cap on connection attempts per second |
| `--scope <CIDR>` | Authorized scope entry (repeatable) |
| `--scope-file <FILE>` | Read scope entries from a file |
| `--i-have-authorization` | Acknowledge authorization to scan the scope |
| `--ping` | TCP-ping host discovery before scanning |
| `--format <F>` | `human` (default) \| `json` |
| `-o, --output <FILE>` | Write the report to a file instead of stdout |
| `--max-targets <N>` | Safety cap on expanded host count (default 65536) |
| `-v, --verbose` | Increase logging (`-v` debug, `-vv` trace) |

## How the speed works

The port scan is an async TCP **connect** scan driven by tokio. Concurrency is
bounded adaptively: ferroscan reads the process's file-descriptor limit
(`RLIMIT_NOFILE`) and sizes its concurrent batch to fit inside it, leaving
headroom for stdio and DNS sockets (the "RustScan trick"). A `JoinSet` acts as a
sliding window — once it is full, one probe must finish before the next is
launched — so memory stays flat regardless of how many hosts and ports are in
play. Connect scanning requires no root and is fully portable; a raw-socket SYN
scan is planned as an optional, privilege-gated feature.

Port states reported:

- **open** — the TCP handshake completed (a service is listening).
- **closed** — the connection was actively refused (reachable, nothing listening).
- **filtered** — no response within the timeout (dropped/firewalled) or unreachable.

## Output

JSON is the machine-readable **source of truth**; the human summary is derived
from the same data model, and the planned CSV/HTML renderers will be too. Every
report includes scan metadata (targets, scope, timing, tool version, profile,
throughput), a state rollup, and per-host open-port findings sorted by port.

## Architecture

```
src/
  main.rs            binary entry: CLI → config → run → render
  lib.rs             library root
  error.rs           crate error type (thiserror)
  cli.rs             clap v4 derive surface
  runner.rs          orchestration
  config/
    mod.rs           ScanConfig assembly + profile defaults
    target.rs        IP/CIDR/range/hostname/file parsing + expansion (capped)
    ports.rs         port list/range/top-ports/all parsing
    scope.rs         authorized allowlist + enforcement
  discovery/mod.rs   TCP-ping host liveness
  scanner/
    mod.rs           async connect-scan core
    batch.rs         ulimit → adaptive concurrency sizing
  report.rs          serde data model (source of truth) + JSON/human renderers
tests/
  integration.rs     end-to-end scan against a local mock TCP listener
```

## License

Licensed under either of MIT or Apache-2.0 at your option.
