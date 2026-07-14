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
