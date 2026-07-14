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
