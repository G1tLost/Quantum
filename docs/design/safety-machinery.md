# Design — Safety machinery (Invariant 2 closure)

Status: design, not yet implemented. Closes findings **F-2, F-3, F-4** from
`docs/threat-model.md`. Three mechanisms named by HARD INVARIANT 2 that do not
yet exist: the **authorization gate**, **per-host rate limiting**, and the
**append-only audit log**.

Guiding rules for this whole doc:

- Every mechanism **fails safe**: the absence or failure of a guard means *no
  scan*, never *scan anyway*.
- Each is a **separate loop iteration** (one axis per pass — `CLAUDE.md`).
  Suggested order at the end (§5).
- **No new crates required.** `governor` already ships keyed limiters and pulls
  `dashmap`; the audit log needs only `std::fs` + `serde_json`. If that turns
  out wrong during implementation, stop and ask before adding a dependency.
- Nothing here weakens Invariants 1/3/4. All three changes make the tool
  *safer/more conservative*, which Invariant 3 explicitly permits.

---

## 0. Revised `runner::run` pipeline

The mechanisms compose into the orchestrator. Target end state
(`src/runner.rs`), guards first, **before any network activity**:

```
0. Open the audit log            → abort if unopenable            (F-4, fail-safe)
1. Authorization gate            → abort if unauthorized/no-scope  (F-3, fail-safe)
   └─ write `authorized` audit record (operator, scope, scope-hash, method, ts)
2. Expand targets (DNS + cap)    → existing (see F-1 note in threat model)
3. Scope partition               → existing; write refusals to audit
4. Plan concurrency              → existing
5. Discovery (optional)          → existing
6. Scan                          → existing + global AND per-host limiters   (F-2)
7. Write `completed` audit record (counts, duration, tool version)
8. Assemble report               → existing
```

Current pipeline for comparison: `src/runner.rs:27-129` (steps 2–8 exist; the
warns at `:29-40` become the real gate in step 1).

---

## 1. Hard authorization gate (F-3)

### Goal
No packet leaves the tool unless the operator has affirmatively authorized the
**specific scope** being scanned, and that consent is recorded.

### Behavior
- A scan is **authorized** iff *both* hold:
  1. **Scope is non-empty.** An empty scope currently means "allow all" with a
     warning (`src/config/scope.rs:80-83`, `src/runner.rs:29-34`). Under the
     gate, empty scope is **refused** — you cannot authorize "everything"
     (Invariant 4). `Scope::is_empty()` already exists (`scope.rs:69-71`).
  2. **Consent is present**, via either:
     - `--i-have-authorization` (interactive attestation, existing flag
       `src/cli.rs:78-82`), **or**
     - `--scope-file <path>` carrying a signed authorization header (operator,
       engagement id, issued/expiry dates, and a `scope_sha256` that must match
       the resolved scope). Signature verification is a v2 nicety; v1 accepts a
       well-formed signed file and records its metadata.
- **First-run-against-new-scope semantics** (from the original spec): compute a
  stable `scope_hash` = SHA-256 over the sorted, normalized scope entries
  (`Scope::raw()` at `scope.rs:73-76`, sorted + lowercased). Keep a local ack
  ledger (the audit log doubles as this). If `scope_hash` has not been
  acknowledged before, require `--i-have-authorization` *this run* and record it.
  Re-runs against an already-acknowledged scope still log, but need not re-prompt.
- Expiry: if a signed scope file has an `expiry` in the past → refuse.

### Enforcement point
New function `authorize(&config) -> Result<Authorization>` called at
`runner::run` **step 1**, before `resolve_and_expand`. Returns an
`Authorization` value (operator, method, scope_hash, timestamp) that is then
handed to the audit log. On failure returns an error and the scan never starts.

### Config / CLI
- Keep `--i-have-authorization` (`authorized: bool`).
- Add `--operator <NAME>` (or read `FERROSCAN_OPERATOR` / OS user) for the record.
- Add `--engagement <ID>` (free-form, for the audit trail).
- `--scope-file` already exists (`src/cli.rs:74-76`); extend its parser to
  recognize an optional leading authorization header block.

### Errors (new variants in `src/error.rs`)
```rust
/// Scan refused: authorization was not established.
#[error("refusing to scan: {reason}. Pass --i-have-authorization (or a signed \
         --scope-file) and a non-empty --scope")]
Unauthorized { reason: String },
```
(There is precedent and room in the enum; `error.rs` currently has no
authorization variant after the earlier cleanup.)

### Failure-safe & invariants
- Default with no flags → **refuse** (today it scans with a warning). This is a
  deliberate, documented tightening and is *more* conservative (Invariant 3 ✓).
- Ties directly to Invariant 2 ("authorization gate … enforced on every code
  path") and reinforces Invariant 4 (no allow-all).

### Tests
- No scope → `Unauthorized`.
- Non-empty scope, no ack, unseen scope-hash → `Unauthorized`.
- Non-empty scope + `--i-have-authorization` → `Ok`, and an audit record is
  written with the correct scope_hash.
- Signed scope file with past expiry → `Unauthorized`.

---

## 2. Per-host rate limiting (F-2)

### Goal
Bound the load any **single** host receives, independent of the global rate and
concurrency, so a fragile device is never bursted.

### Two independent controls
1. **Per-host connections/sec** — a *keyed* rate limiter keyed by `IpAddr`.
   `governor` provides this directly (`RateLimiter::keyed` /
   `DefaultKeyedRateLimiter<IpAddr>`), no new dependency. Before launching a
   probe for `(ip, port)`, `await keyed.until_key_ready(&ip)`.
2. **Per-host in-flight concurrency** — an `Arc<DashMap<IpAddr, Arc<Semaphore>>>`
   (or a small fixed map, since host count is known post-scope). Acquire a
   permit for `ip` before the connect; release on completion. Caps simultaneous
   sockets to one host.

The existing **global** limiter (`src/runner.rs:85-89`,
`src/scanner/mod.rs:82-84`) stays as the aggregate ceiling; per-host layers
underneath it.

### Complementary: interleave scan order
Host-major iteration (`src/scanner/mod.rs:72-89`) is the reason bursts
concentrate. Switching to **round-robin over hosts** (port-major, or a
zip/interleave of per-host port streams) spreads launches across hosts and cuts
burstiness even before the limiter engages. Recommended alongside the hard
limiter, not instead of it. Note: this reorders results, which is fine —
`ScanReport::build` groups by host regardless.

### Config / CLI
- `--max-rate-per-host <PPS>` → `max_rate_per_host: Option<u32>`.
- `--max-per-host-inflight <N>` → `max_inflight_per_host: Option<usize>`.
- Profile defaults (extend `src/cli.rs` `Profile`), gentler than global:

  | Profile | per-host pps | per-host in-flight |
  |---------|-------------:|-------------------:|
  | Paranoid | 2 | 1 |
  | Polite | 20 | 4 |
  | Normal | (none) | 16 |
  | Aggressive | (none) | (none) |

  Only defaults change; explicit flags still win (matches existing pattern at
  `src/config/mod.rs:95-102`). Every value here only *reduces* load → Invariant 3 ✓.

### Enforcement point
`ScanRuntime` (`src/scanner/mod.rs:44-55`) gains `per_host_limiter:
Option<Arc<DefaultKeyedRateLimiter<IpAddr>>>` and `per_host_inflight:
Option<usize>`. In `run_scan`, acquire per-host permit + `until_key_ready(&ip)`
in addition to the existing global `until_ready` (`:82-84`).

### Tests
- With per-host in-flight = N against a mock host, assert observed simultaneous
  connections never exceed N (counter in the mock's accept loop).
- With per-host pps = R, assert the time to complete K probes to one host is
  ≥ (K-1)/R seconds (timing bound).
- Global cap still respected across multiple hosts.

---

## 3. Append-only audit log (F-4)

### Goal
A durable, append-only record answering "what was scanned, when, by whom, under
what authorization, with what profile" — written for **every** scan.

### Format & location
- **JSON Lines** (`.jsonl`): one self-contained JSON object per event, appended,
  never rewritten.
- Default path `~/.ferroscan/audit.jsonl`; override with `--audit-log <path>`;
  `--no-audit` is **not** offered (the log is mandatory — Invariant 2).
- Open with `OpenOptions::new().create(true).append(true)`; `write_all` a line +
  `flush`/`sync_all` per record so a crash mid-scan still leaves the `started`
  record on disk.

### Events (minimum viable)
1. `authorized` — written at pipeline step 1, **before** expansion: tool version,
   timestamp, operator, engagement, scope entries, scope_hash, auth method.
2. `out_of_scope_refused` — for refused targets (today only `tracing::warn` at
   `src/runner.rs:50-52`): the refused addresses (or an aggregate count + sample).
3. `completed` — at the end: hosts in/out of scope, hosts scanned, ports/host,
   open/closed/filtered counts, duration, exit status.

The `authorized` record doubles as the **first-run ack ledger** for §1: to check
whether a scope_hash was previously acknowledged, scan existing `authorized`
records for a matching hash.

### Tamper-evidence (v2, note only)
Each record may carry `prev_hash` = SHA-256 of the previous line, forming a hash
chain so deletions/edits are detectable. v1 ships plain append-only JSONL; the
schema reserves a `prev_hash` field so v2 is non-breaking.

### Module / errors
- New `src/audit.rs`: `struct AuditLog { file }`, `AuditLog::open(path)`,
  `log.record(&Event)`. Events are `#[derive(Serialize)]`.
- New error variant:
  ```rust
  #[error("audit log error at '{path}': {source}")]
  Audit { path: String, #[source] source: std::io::Error },
  ```
- **Fail-safe:** `AuditLog::open` failure at step 0 aborts the scan. No audit →
  no scan.

### Tests
- Open temp path, run a scan, assert an `authorized` then a `completed` record
  exist and parse as JSON.
- Second scan **appends** (line count grows; first record intact) — proves
  append-only, not truncate.
- Unwritable path (e.g. a directory, or perms) → scan aborts with `Error::Audit`.
- Refused target produces an `out_of_scope_refused` record.

---

## 4. Interaction with existing HARD INVARIANTS

| Change | 1 (detect-only) | 2 (safety machinery) | 3 (conservative defaults) | 4 (scope) |
|--------|:---:|:---:|:---:|:---:|
| Auth gate | — | **strengthens** | more conservative default | forbids allow-all → strengthens |
| Per-host limits | — | **strengthens** | gentler defaults only | — |
| Audit log | — | **strengthens** | — | records refusals |

None weaken any invariant. The safety-invariant review pass after each should
confirm all four still hold and that the new guard is enforced on every path.

---

## 5. Suggested iteration sequence

One axis per loop pass; each ends green in CI before the next begins.

1. **Audit log first.** It is a precondition the other two want to write into,
   and it is self-contained (new module, no behavior change to scanning). Lowest
   risk, unblocks recording.
2. **Authorization gate.** Depends on the audit log (for the ack ledger + consent
   record). Changes default behavior → do it deliberately, with docs + tests.
3. **Per-host rate limiting.** Independent of the other two; the most code (keyed
   limiter + optional scan-order interleave) and the most test surface, so last.

Each pass: state focus → report → smallest change → CI green → commit →
`PROGRESS.md` entry.
