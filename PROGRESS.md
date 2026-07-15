# PROGRESS.md — ferroscan review & upgrade loop log

One line per kept change: what changed, why, and the verification result.
Newest at the bottom.

---

- **2026-07-14 — loop setup.** Added `CLAUDE.md` (operating manual) and this
  log. No code change. Verify: `cargo fmt --check` clean. **Blocker recorded:**
  this environment's network policy does not allowlist `index.crates.io`, so
  `cargo build` / `clippy` / `test` cannot run here (only `cargo fmt --check`
  does). The edit→verify→commit loop cannot be honored until crates.io egress is
  enabled — see "Operating notes" in `CLAUDE.md`.
- **2026-07-14 — CI gating.** Added `.github/workflows/ci.yml` running the four
  gates (fmt, clippy -D warnings, build, test) on GitHub runners, which reach
  crates.io. This restores the deterministic authority the local sandbox can't
  provide: from now on a change is "kept" only once its CI run is green. Verify:
  YAML validated; `cargo fmt --check` clean.
- **2026-07-14 — first CI run caught a real defect.** CI #1 failed on
  `clippy::write_literal` at `src/report.rs:219` (a `"RTT"` literal fed to a `{}`
  placeholder) — a lint no static reviewer flagged. Inlined the literal per
  clippy's suggestion (no output change). Verify: **CI #2 green** — fmt, clippy
  (-D warnings), build --all-targets, and test all pass. Phase 1 is now
  compile- and test-verified, not just statically reviewed.
- **2026-07-14 — audit + design docs (no code change).** Rotations #1/#3 audit
  + documentation. Added `docs/threat-model.md` (invariant-by-invariant analysis
  with file:line evidence; error-handling audit = CLEAN, all panic-prone calls
  are test-only; findings F-1..F-5), `docs/design/safety-machinery.md`
  (implementation-ready plans for the 3 missing Invariant-2 mechanisms: auth
  gate, per-host rate limiting, append-only audit log), and
  `docs/design/phases-2-3-fingerprinting-vuln.md`. Verify: `cargo fmt --check`
  clean; docs-only, so CI stays green.
