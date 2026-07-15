# Design — Phase 2 (fingerprinting) & Phase 3 (vuln engine)

Status: design, not yet implemented. These phases are where **Invariant 1
(detection only)** is most at risk, because for the first time the tool will
*send bytes* to a target and *parse attacker-controlled responses*. The
constraints in §0 are load-bearing, not aspirational.

Depends on Phase 1 (green) and slots in after the scan core produces open ports.

---

## 0. Non-negotiable constraints (Invariant 1)

Every probe added in these phases MUST be:

1. **Read-only / non-intrusive.** Connect, optionally send a *minimal, benign,
   protocol-standard* request (e.g. an HTTP `GET /`, a TLS ClientHello), read the
   response, close. No auth attempts, no state-changing requests, no oversized or
   malformed input intended to trip a parser.
2. **Bounded.** Every probe has a byte cap on what it reads (e.g. 4–8 KiB of
   banner) and a time cap (reuse the scan `timeout`/profile). A target that
   streams forever must not hang or OOM us.
3. **Rate-governed.** Fingerprint/vuln probes flow through the **same** global +
   per-host limiters as the scan (see `docs/design/safety-machinery.md` §2). A
   host does not get a second, ungoverned wave of traffic.
4. **Untrusted-input safe.** Banners, certs, headers, and CVE JSON are hostile
   input: no `unwrap` on parsed fields, byte caps enforced, regexes anchored and
   non-catastrophic. The rotation-#3 discipline (no panics on fallible paths)
   extends to all parsing here.

If a check cannot be expressed within these limits, it does not belong in
ferroscan (this is the exploit/brute-force/fuzz line — Non-Goals).

---

## Phase 2 — Fingerprinting

### Where it plugs in
After `run_scan` returns `ProbeResult`s (`src/scanner/mod.rs`), a new
`fingerprint` stage takes the **Open** ports only and enriches each with a
service identity. Output extends the per-port finding the report already carries
(`src/report.rs`).

### Module layout (`src/fingerprint/`)
- `mod.rs` — orchestration: for each open `(ip, port)`, run the applicable
  probes under the shared limiters, collect the best match.
- `probe.rs` — the probe/response engine, modeled loosely on
  `nmap-service-probes`: a probe = {trigger ports, optional payload to send,
  response regex, extracted product/version/CPE template}. Ship a small curated
  set (HTTP, TLS, SSH, SMTP, FTP, Redis, etc.), embedded at compile time.
- `banner.rs` — generic banner grab: connect, read up to N bytes with a timeout,
  no send (many services greet first — SSH, SMTP, FTP).
- `tls.rs` — TLS inspection via `rustls`: perform a handshake to read the
  certificate chain (subject/SAN/issuer/validity), negotiated version, and cipher.
  **Read-only: no MITM, no downgrade probing that could disrupt.** Record weak
  versions (SSLv3/TLS1.0/1.1) and expired/self-signed certs as findings.

### Data model
```rust
pub struct ServiceId {
    pub service: Option<String>,   // "http", "ssh"
    pub product: Option<String>,   // "nginx", "OpenSSH"
    pub version: Option<String>,   // "1.25.3", "8.9p1"
    pub cpe: Option<String>,       // "cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"
    pub tls: Option<TlsInfo>,
    pub evidence: String,          // the banner/line matched, for auditability
}
```
CPE synthesis is best-effort: map (product, version) → CPE 2.3 string via a small
vendor/product table; leave `cpe: None` when unsure rather than guessing wrong
(a wrong CPE produces wrong CVEs downstream).

### New crates (from the original approved stack — still confirm at add time)
- `rustls` (+ `tokio-rustls`) — TLS handshake/cert reading.
- `regex` — probe response matching (anchored patterns).
- `hickory-resolver` — optional, only if we move off `tokio::net::lookup_host`
  (`src/config/target.rs:266-285`) for richer DNS; not required for Phase 2.

### Tests
- Parse fixed banner fixtures → expected `ServiceId` (pure, table-driven).
- Local mock server emits a known banner → correct product/version.
- TLS: spin a rustls test server with a known cert → assert extracted SAN/validity.
- Byte-cap test: a mock that streams endlessly is cut off at N bytes, no hang.

---

## Phase 3 — Vuln engine

### Where it plugs in
Consumes `ServiceId` (esp. `cpe`) per open port and attaches known CVEs +
severity. Feeds the report's severity rollups (`src/report.rs`).

### Module layout (`src/vuln/`)
- `cpe.rs` — CPE parsing/normalization + (product,version) → CPE synthesis.
- `nvd.rs` — NVD lookups: query by CPE, with an **on-disk cache** keyed by CPE
  (respect NVD rate limits; cache TTL). `reqwest` client, bounded timeouts.
- `feed.rs` — **offline mode**: load a pre-downloaded NVD JSON feed so the engine
  runs air-gapped (common in client environments). Offline is the safer default
  for sensitive engagements.
- `cvss.rs` — parse CVSS v3.1 base score + vector; map score → severity band.
- `checks/` — the small set of **safe active checks** (all read-only):
  - exposed/default admin endpoints — detect by unauthenticated `GET` returning a
    known login/console page; **never** attempt credentials.
  - weak TLS versions/ciphers — from Phase 2 `TlsInfo`.
  - missing security headers — `HSTS`, `X-Content-Type-Options`, etc. via a
    single `GET`.

### Data model
```rust
pub struct Finding {
    pub cve_id: String,               // "CVE-2023-44487"
    pub cvss_v31_base: Option<f32>,   // 0.0–10.0
    pub cvss_vector: Option<String>,
    pub severity: Severity,           // Critical/High/Medium/Low/None
    pub references: Vec<String>,
    pub source: FindingSource,        // NvdOnline | OfflineFeed | ActiveCheck
}
```

### Safety notes specific to Phase 3
- **Offline-first for sensitive engagements**: `--offline` uses only the local
  feed; no outbound traffic to NVD.
- Cache poisoning: treat NVD/feed JSON as untrusted (bounded parse, no `unwrap`).
- The active checks are the closest thing to "active" in the whole tool — each
  one gets an explicit safety review against Invariant 1 before merge, and each is
  a single benign request under the shared limiters.

### New crates (from the original approved stack)
- `reqwest` (rustls TLS backend, no native-tls) — NVD API + HTTP checks.
- `serde_json` — already present — feed/cache parsing.

### Tests
- CPE parse/synthesis round-trips (pure).
- CVSS vector → score band mapping (pure, table-driven).
- NVD client against a local mock returning canned JSON → correct `Finding`s;
  cache hit avoids a second request.
- Offline feed load → same `Finding`s without network.
- Each active check against a mock exhibiting/lacking the condition.

---

## Sequencing

Phase 2 before Phase 3 (the vuln engine needs `ServiceId`/CPE). Within each,
follow the loop: smallest coherent change, CI green, one commit, `PROGRESS.md`
entry. Every Phase 2/3 change also triggers a **safety-invariant pass** (rotation
#2) re-verifying Invariant 1, because these are the phases that add outbound
bytes.
