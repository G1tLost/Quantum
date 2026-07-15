# ferroscan — Threat Model & Safety Audit

Status: living document. Grounded in the code as of the current branch. Every
claim below cites `file:line` so it can be re-verified against the source, not
taken on faith. This is an **audit-only** artifact — it makes no code changes.

Read alongside `CLAUDE.md` (the HARD INVARIANTS) and
`docs/design/safety-machinery.md` (the plan to close the gaps found here).

---

## 1. What we are protecting

ferroscan is run by an MSSP/SOC engineer against **client** environments under
contract. The tool is trusted with the ability to send traffic to third-party
infrastructure. The assets at risk are therefore **not** ferroscan's own data —
they are:

| Asset | Harm if the tool misbehaves |
|-------|-----------------------------|
| The client's *out-of-scope* hosts | Scanning them is unauthorized access — a real incident, potentially a legal one |
| The client's *fragile* in-scope hosts | A burst of connections can degrade or knock over brittle devices (SCADA, printers, legacy appliances) |
| The engagement's auditability | If we can't prove *what* was scanned, *when*, and *under what authorization*, the assessment is disputable |
| The operator's authority | Running outside the contracted window/scope exceeds authorization even if technically in-range |

These map directly onto the four HARD INVARIANTS. This document treats each
invariant as a **security property** and asks: what could violate it, and does
the current code hold?

---

## 2. Trust boundaries & actors

- **Operator (trusted, but fallible).** Supplies targets, scope, profile, and
  authorization. The most likely source of an incident is an *honest mistake* —
  a fat CIDR, a typo'd scope, a forgotten `--profile polite` against fragile
  gear. The tool's job is to make the safe path the default and the dangerous
  path loud and explicit.
- **Targets (untrusted input source).** Banners, TLS certs, and (future) HTTP
  responses are attacker-controllable data. Anything parsed from a target must
  be treated as hostile input. *(Relevant once Phase 2 fingerprinting lands.)*
- **DNS (semi-trusted).** Hostname → IP resolution can return an address the
  operator did not intend (misconfiguration or, adversarially, DNS rebinding).
- **NVD / feeds (semi-trusted, future).** CVE data pulled over the network in
  Phase 3; must be cached and integrity-checked.

---

## 3. Invariant-by-invariant analysis

### Invariant 1 — Detection only. ✅ HOLDS

The scan core completes the TCP handshake purely to observe port state, then
drops the socket **without writing any bytes**: `drop(stream)` with the comment
"Read-only: close immediately without sending anything" (`src/scanner/mod.rs:128-131`).
Discovery is the same connect-and-observe pattern (`src/discovery/mod.rs:76-82`).
There is no payload, brute-force, or fuzz path anywhere in the tree.

**Residual risk:** Phase 2 (banner grab) and Phase 3 (safe active checks) will
add code that *does* send bytes. That is the moment this invariant is most at
risk. The Phase 2/3 design (`docs/design/phases-2-3-fingerprinting-vuln.md`)
constrains every probe to be read-only and bounded; the safety-invariant review
pass must re-verify this invariant on every Phase 2/3 change.

### Invariant 4 — No scope creep past the allowlist. ✅ HOLDS (with notes)

Scope is enforced **after** target expansion and **before** any probe:
`config.scope.partition(expanded)` at `src/runner.rs:48-49`, feeding only
`in_scope` into discovery (`:74`) and the scan (`:81`). `Scope::allows` checks
IP membership against CIDR/IP entries (`src/config/scope.rs:80-94`). Discovery
and the scan never see a refused address.

**Notes / residual risks:**

1. **DNS is queried for out-of-scope hostnames.** A `Host(...)` target is
   resolved (`src/config/target.rs:239-243, 266-285`) *before* the scope check.
   The resolver query itself is not a probe of the target, so this is not a
   scope violation — but the *resolved* address is correctly scope-filtered
   afterward, which also neutralizes naive **DNS-rebinding** (a hostname pointing
   at an out-of-scope IP is refused at `partition`). This is the right ordering;
   keep it.
2. **`--max-targets` is applied to raw expansion, before scope filtering**
   (`src/runner.rs:42-49`; estimate/cap in `src/config/target.rs:191-217`). A
   large-but-mostly-out-of-scope target (e.g. `10.0.0.0/8` with scope
   `10.0.0.0/24`) trips `TooManyTargets` instead of scoping down to the 254
   in-scope hosts. This **fails safe** (it errors, never over-scans) but is a UX
   wart. Candidate correctness iteration: intersect with scope during expansion,
   or cap the in-scope subset. Tracked as finding **F-1**.

### Invariant 2 — Safety machinery functional on every path. ⚠️ PARTIAL — the main gap

The invariant names four mechanisms. Two exist and hold; three are absent
(counting per-host rate limiting as distinct from global). None are *regressions*
— they were never built (Phase 5) — but the current posture does **not** meet
Invariant 2, and a safety-invariant review pass cannot honestly mark it "intact"
until they exist.

| Mechanism | State | Evidence |
|-----------|-------|----------|
| Scope allowlist enforcement | ✅ present, enforced pre-probe | `src/runner.rs:48-59`, `src/config/scope.rs:80-94` |
| Global rate limiting | ✅ present (optional; profile defaults) | `src/runner.rs:85-92`, `src/scanner/mod.rs:82-84`, `src/cli.rs:168-174` |
| **Authorization gate** | ❌ soft only | `--i-have-authorization` sets a bool (`src/cli.rs:78-82`); runner only **warns** if absent and scans anyway (`src/runner.rs:35-40`) |
| **Per-host rate limiting** | ❌ absent | only a single *global* limiter exists; see burst risk below |
| **Append-only audit log** | ❌ absent | no audit module; `tracing` to stderr (`src/main.rs:38-55`) is ephemeral, not a durable record |

**Burst risk (per-host).** `run_scan` iterates **host-major** — all ports of
host A are launched before host B (`src/scanner/mod.rs:72-89`). With the default
`Normal` profile (no rate cap, fd-derived concurrency ≈ `fd_soft − 64`), a single
host can receive up to `concurrency` simultaneous SYNs before the window fills.
For a fragile device that is exactly the failure mode the per-host limiter is
meant to prevent. Tracked as finding **F-2**.

**Auth bypass.** Today any invocation scans; the flag only silences a banner.
There is no first-run-against-new-scope attestation and no record of consent.
Tracked as finding **F-3**.

**No durable audit.** If asked "prove what you scanned on 2026-07-14 and under
what authorization," the tool cannot answer from its own artifacts. Tracked as
finding **F-4**.

→ Closure plan for F-2/F-3/F-4: `docs/design/safety-machinery.md`.

### Invariant 3 — Conservative defaults stay conservative. ⚠️ DECISION NEEDED

The default profile `Normal` uses the full fd-derived concurrency with **no rate
cap** and **no per-host cap** (`src/cli.rs:159-174`, `src/scanner/batch.rs:63-70`).
An operator who forgets to pass `--profile polite/paranoid` gets a fast, uncapped
scan. This is not a regression (it is the established baseline, and the invariant
forbids making defaults *more* aggressive, which we must not) — but for a tool
that hits fragile client gear, whether the *default* should carry a gentle
per-host cap is a genuine product decision. Tracked as finding **F-5** (a
decision, not a bug). Any change here must only make defaults *gentler*.

---

## 4. Error-handling / robustness audit (rotation #3) — ✅ CLEAN

Swept the whole tree for panic-prone calls on fallible paths
(`.unwrap()`, `.expect(`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`).

**Result: every hit is inside a `#[cfg(test)]` module.** There are **zero**
panic-prone calls on library runtime paths. Representative:

- Library code returns `Result` throughout, with a typed error enum
  (`src/error.rs`) and `anyhow` context only at the binary boundary
  (`src/main.rs:26-33`).
- `main.rs` uses the safe combinator `unwrap_or_else` for the tracing filter and
  `try_init` to avoid double-install panics (`src/main.rs:46-54`).
- Numeric conversions that could truncate are guarded
  (`.min(u128::from(u64::MAX)) as u64`, e.g. `src/scanner/mod.rs:129`,
  `src/report.rs:246`).
- Range/CIDR math avoids overflow via `saturating_add`/`checked_shl`
  (`src/config/target.rs:42, 62-67, 196`).

No change required for this focus area at this time. (Test-only `unwrap()`s are
idiomatic and acceptable.)

---

## 5. Findings register

| ID | Sev | Invariant | Summary | Disposition |
|----|-----|-----------|---------|-------------|
| F-1 | minor | 4 | `--max-targets` capped before scope filtering; fails safe but rejects large-but-in-scope inputs | correctness iteration (design optional) |
| F-2 | major | 2/3 | No per-host rate/concurrency limit; host-major order can burst a single host | `safety-machinery.md` §2 |
| F-3 | major | 2 | Authorization is a soft warning, not a gate; no attestation record | `safety-machinery.md` §1 |
| F-4 | major | 2 | No append-only audit log | `safety-machinery.md` §3 |
| F-5 | decision | 3 | Default `Normal` profile is uncapped; decide if default should be gentler | product decision |

None of these are compile/test failures — CI is green. They are gaps between the
current (Phase-1-complete) code and the Phase-5 safety posture the invariants
describe.

---

## 6. Reaffirmed non-goals

Restating, because the threat model must not tempt scope creep the wrong way:
**no** exploitation, **no** payload delivery, **no** credential guessing/spraying,
**no** service-crashing fuzz. If a proposed check cannot be done read-only and
non-intrusively, it does not belong in ferroscan (Invariant 1).
