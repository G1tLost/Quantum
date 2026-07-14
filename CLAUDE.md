# CLAUDE.md — ferroscan review & upgrade loop

This file is read at the start of every session and every routine iteration. It
defines what "review and upgrade" means for this project and the invariants that
must never be violated in the process. Read it fully before making any change.

## Project

`ferroscan` is a defensive network vulnerability scanner (Rust, tokio async). It
does host discovery → fast async port scan → service/version fingerprinting →
version-based CVE matching → scored reporting. It is an assessment / detection
tool, run against client environments under contract with authorization.

## HARD INVARIANTS — never violate, never "optimize away"

These are load-bearing. If an improvement would touch any of them, reject the
improvement and log why. Do not weaken, disable, refactor-away, or "simplify"
them even if they look unused, redundant, or slow.

1. **Detection only.** Never add exploitation, payload delivery, credential
   brute-forcing, fuzzing that can crash a service, or anything that
   degrades/DoSes a target. If a proposed change moves the tool toward
   weaponization, stop and reject it.
2. **Safety machinery is untouchable.** The scope allowlist enforcement, the
   authorization gate, per-host + global rate limiting, and the append-only
   audit log must remain functional and enforced on every code path. A
   "cleanup" pass that removes an apparently unused guard is a regression, not
   an improvement.
3. **Conservative defaults stay conservative.** Do not raise default scan
   aggressiveness, concurrency, or timeout defaults. Speed work happens behind
   explicit flags, never in the default profile.
4. **No scope creep past the allowlist.** Any code that could touch a host
   outside the configured scope is a critical bug — fix it, never introduce it.

If you learn a new invariant the hard way during a run, append it to this list
so it propagates to every future iteration.

## Iteration protocol (the loop body)

Do exactly one focus area per iteration. Rotate through them in order; do not
touch multiple axes in a single pass (it makes review and rollback impossible).

Focus rotation:

1. Correctness / logic bugs
2. Safety-invariant audit (verify all four HARD INVARIANTS still hold — this
   pass makes no feature changes, only confirms or repairs guards)
3. Error handling (no `unwrap()`/`expect()` on fallible paths in library code;
   meaningful error types)
4. Performance (only behind flags; must not regress the safe defaults)
5. Test coverage (add tests for the focus area's findings)
6. Documentation (README, doc comments, `--help` text accuracy)

Each pass:

1. State the focus area and what you're auditing before changing anything.
2. Report findings first. Then make the smallest coherent change that addresses
   one.
3. Verify (change is kept ONLY if every check passes):
   * `cargo build --all-targets`
   * `cargo clippy --all-targets -- -D warnings`
   * `cargo fmt --check`
   * `cargo test`
4. If the focus was performance, run the benchmark and keep the change only if
   throughput does not regress against the recorded baseline.
5. Commit this single change on its own with a clear message, or open a PR. Git
   is the undo button — never batch unrelated changes into one commit.
6. Append a one-line entry to `PROGRESS.md`: what changed, why, and the
   verification result.
7. If you made a mistake or hit a recurring gap, write the lesson into this file
   so it doesn't recur.

## Definition of "done" (the checker — deterministic)

The loop stops when ALL of these hold across a full rotation of focus areas:

* `cargo clippy --all-targets -- -D warnings` produces no warnings
* `cargo fmt --check` is clean
* `cargo test` fully passes
* All four HARD INVARIANTS verified intact by the safety-invariant pass
* The reviewer reports no material improvement found for a complete rotation

"Refactored for elegance" with no measurable change to correctness, safety,
performance, or coverage is not an improvement — do not count it, and do not
churn on it.

## Review discipline

* Do not grade your own homework. Review changes with fresh context (a reviewer
  subagent or a separate review pass), not the same reasoning that produced
  them.
* Deterministic gates over judgment wherever possible: the compiler, clippy, and
  the test suite are the authority on "did this work," not self-assessment.
* Start read-only. The first pass on any new run is audit-only — report
  findings, make no edits — so you (and I) can see what it intends before it
  touches code.

## Guardrails for unattended runs

* Respect the turn/iteration cap set at launch. Do not attempt to raise it from
  inside a run.
* These loops compound token cost with every iteration — prefer the smallest
  model that can do the focus area's work, and reserve the strongest model for
  judgment calls.
* Every iteration must leave the repo in a green, committed state. Never leave a
  broken build as the last action of a pass.

## Operating notes (learned — append as you go)

* **Verification gates require crates.io egress.** Three of the four deterministic
  gates (`cargo build`, `cargo clippy`, `cargo test`) need to fetch dependencies
  from `index.crates.io`. In an environment whose network policy does not
  allowlist that host, those gates cannot run locally and the edit→verify→commit
  loop MUST NOT proceed on judgment alone (it would violate "deterministic gates
  over judgment"). Only `cargo fmt --check` runs without network. To fix locally:
  add `index.crates.io` (and `static.crates.io` for downloads) to the
  environment's network egress allowlist.
* **CI is the gate when local egress is blocked.** `.github/workflows/ci.yml`
  runs all four gates on GitHub's runners (which reach crates.io), so the
  deterministic authority is preserved even when this sandbox can't compile. The
  honest loop under this constraint: make the smallest change → `cargo fmt
  --check` locally → push → **read the CI result as the gate** → keep the change
  only if CI is green, otherwise fix and re-push. Do not mark an iteration
  "done" until its CI run passes. (Requires GitHub Actions enabled on the repo.)
