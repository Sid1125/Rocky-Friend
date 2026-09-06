# ROCKY Build Tracker

Last updated: 2026-09-06

## Overall status

**Estimated full-project completion: 87%**

This is an engineering estimate against the full personal-project vision, not a measure of code volume. The goal is to build as much useful capability as practical while retaining the project constitution's safety boundaries.

## Current activity

**Phase 0 — Safe core foundation: 100% complete**

- [x] Read and adopt project constitution, architecture, security, and development contracts.
- [x] Verify Rust workspace compiles and tests on the installed stable toolchain.
- [x] Install `rustfmt` and `clippy` toolchain components.
- [x] Define dependency direction between workspace crates.
- [x] Add pure domain primitives for autonomy, capabilities, and task-state transitions.
- [x] Add deny-by-default scoped policy evaluation with traversal and scope-boundary checks.
- [x] Add a typed, non-executing tool broker with deadlines and cancellation requirements.
- [x] Add bounded logical-worker admission rules.
- [x] Add resource-pressure admission rules.
- [x] Add append-only in-memory audit records.
- [x] Compose policy, resource, tool-contract, and audit guards in the runtime crate.
- [x] Run and pass formatting, strict lint, and the complete unit-test suite after the implementation batch.
- [x] Fix `unused_mut` clippy denial and rustfmt drift left in the permit/executor batch.
- [x] Harden the canonicalized filesystem-read executor (post-open handle check, byte limit, wrong-permit and symlink-escape rejection) with adversarial tests.
- [x] Make SQLite task writes transactional and align duplicate-task errors with the in-memory boundary.
- [x] Reject revision-counter overflow instead of wrapping.
- [x] Persist approvals with bounded expiry and revocation in memory and SQLite (schema v2 with v1 migration).
- [x] Move `ApprovalRecord` into the pure domain crate so policy, storage, and runtime share one type without new dependencies.
- [x] Consume persisted approvals in the runtime gate: stable FNV-1a action hash binds task/tool/scope, stale approvals stay `ApprovalRequired`, mismatched approvals are `Denied` as replay, valid approvals still pass resource admission.
- [x] Propagate cooperative cancellation (`CancellationToken`) through evaluation, permit issuance, and the filesystem executor with audit coverage.
- [x] Add a structured, allowlisted process executor: no shell ever (direct argv), exact scope-to-program binding, per-call deadline with kill, bounded piped output drained on helper threads (no pipe deadlock), cancellation kill, nonzero-exit mapping, NUL/overflow inputs rejected without panicking, plus shell-metacharacter adversarial tests.
- [x] Add a cross-crate adversarial suite (`rocky-runtime/tests/adversarial.rs`): traversal denial end to end, kind-confused model requests, unregistered shell tools, hostile file content as inert data, SQLite revocation blocking reissue, persisted approvals authorizing only their exact action, approvals never bypassing backpressure. Document the filesystem check-then-act boundary honestly.
- [x] Add typed, versioned, observational event contracts for the UI boundary.
- [x] Add a typed, versioned UI→runtime command protocol (`SubmitGoal`, `ApproveAction`, `DenyAction`, `CancelTask`, `QueryTask`) with bounded goals and action-hash binding. Shape validation only; authorization stays in the Rust core.
- [x] Add a task lifecycle session in the runtime crate: every transition persists a storage revision and emits a UI event through one choke point, terminal steps emit their terminal event only, rejected steps leave neither a revision nor an event.
- [x] Add a task-bound, append-only finding blackboard in the agents crate: validated findings (integer-percent confidence, bounded artifact lists), per-task isolation, fixed capacity, duplicate rejection. Findings are data, never authority.
- [x] Add an explicit worker lifecycle (`Created→Queued→Running→Waiting`, terminal `Completed|Failed|Cancelled|TimedOut`) built on scheduler-admitted specs so budgets validate once; queue step unskippable, terminals final.
- [x] Add a frozen goal contract in the domain crate (private fields, bounded constraints) and make it the session's only goal source, so the persisted goal cannot drift from the frozen one.
- [x] Add an exact-match prompt guard at the model edge for caller-declared secrets (bounded list, longest-first redaction, fixed marker, secrets never printed by `Debug`). No heuristic detection by design: undeclared secrets stay the caller's responsibility.
- [x] Add a fixed context budget at the model edge: prompts that would eat the completion reserve are rejected, all arithmetic checked, zero reserves rejected fail-closed.
- [x] Add content-addressed evidence capture: stable cross-compiler digest helper shared by approvals and evidence, per-task sequenced evidence records with digests in memory and SQLite (schema v3, incremental migration), per-entry and per-task bounds.
- [x] Wire approval UI decisions to the store: `ApproveAction` commands persist hash-bound, capability-bound, future-expiry approvals (double-approve fails loudly, no silent overwrite); `DenyAction` revokes or quietly reports nothing-to-deny; wrong-variant commands rejected.
- [x] Close the permit→executor→evidence chain: permit-bound capture records executor output under the permit's task/tool with re-verifiable digests, proven by a gate-to-store integration test.
- [x] Drive tasks from UI commands: `SubmitGoal` starts contract-bound sessions, `CancelTask` cancels only the matching loaded session, sessions rehydrate from the store and continue; struct-literal command bypasses still refused.
- [x] Add standing area-trust approvals for day-to-day autonomy: scope-bound grants with canonical hashes (re-trust collides instead of stacking), gate converts `ApprovalRequired` without ever overriding `Denied`, inapplicable trust waits instead of denying, backpressure still applies, schema v4 migration proven against a real old-schema file.
- [x] Surface green/orange/red autonomy tiers from execution decisions for the future approval UI.
- [x] Decompose goals into scheduler-admitted subtasks (capacity/depth/budget enforced up front) and aggregate boards by strongest-earliest finding.
- [x] Cap inference concurrency with a non-blocking RAII gate (saturation reported, never deadlocked; proven across threads).
- [x] Persist worker findings in memory and SQLite (schema v5, relational artifact rows, per-task caps).
- [x] Add a CI workflow running fmt, clippy, and the full test suite (dependency review/SBOM/scanning still pending).
- [x] Tool registry hygiene: the broker's registration path (duplicate/unknown/kind-mismatch rejection with tests) already satisfies the registry requirement; no new code needed.
- [x] Bind tool arguments end to end: broker bounds (count/length/NUL), arguments travel in the request and permit, the process executor runs byte-for-byte the brokered argv, and approval hashes cover arguments (`--dry-run` vs `--force` are different actions).
- [x] Answer `QueryTask` with read-only snapshots and surface pending approvals from the audit log for the approval UI.
- [x] Combine scheduler admission with worker lifecycle entry (`spawn`) and bridge finding boards into the store idempotently (`persist_board`).
- [x] Add specialist mini-ROCKY roles: validated narrow roles (tools+budget+description), a deterministic registry selecting least-privilege covers by needed capability, and `spawn_specialist` wiring role tools into admitted workers. (Which model runs a role arrives with the K2 plan's config tiers.)
- [x] Unify cancellation on one domain `CancelFlag` shared by workers, gate, and executors (runtime keeps an alias, zero churn); worker lifecycle-cancel trips the shared flag; cross-crate test proves a revoked worker's tools stop at the gate.
- [x] Enforce worker role allowlists in the step loop: proposals outside the worker's kinds die pre-gate with no audit or evidence.
- [x] Emit UI event payloads from step runs: every attempt yields `tool.requested`, permits add approval/completion, holds name the exact action hash; denials emit the attempt only.
- [x] Review Tauri readiness (`docs/plans/TAURI_READINESS.md`): all five commands have single core handlers, eight event kinds have producers; agent-activity and resource-status events remain blocked on the orchestrator and sampler respectively.
- [x] Compose mini-ROCKY orchestration without new authority: specialist spawning with `agent.spawned` events (refusals emit nothing), board publishing with per-finding events and quiet re-syncs, ordered event forwarding; `persist_board` returns fresh IDs, boards expose their task.
- [x] Enforce worker step budgets (`record_step`/`is_exhausted`, exhaustion errors instead of silent overruns).
- [x] Read audit trails back from SQLite in sequence order (the audit-visibility backend).
- [x] Carry goal constraints from `SubmitGoal` commands into frozen contracts, validated against the same bounds at both layers.
- [x] Sample real OS CPU/RAM via a single-shot `SystemSampler` (sysinfo 0.36 pinned to the project's toolchain; weighed justification in the manifest; no threads, no polling loops).
- [x] Review the full direct-dependency surface (`docs/plans/DEPENDENCY_REVIEW.md`): two direct deps with recorded justifications; vulnerability scanning wired into CI; SBOM/license-automation still open.
- [x] Store secrets behind a trait boundary: in-memory store for tests plus an OS-credential `KeyringSecretStore` (values never printed, blank keys/values rejected). The OS backend failed round-trip on this dev machine (documented in-test), so it stays `#[ignore]`d and undepended-on until re-verified.
- [x] Persist frozen goal contracts in memory and SQLite (schema v6, relational constraint rows, transactional saves, duplicate re-freezes rejected); sessions save, hold, and rehydrate the contract, refusing pre-contract rows loudly.
- [x] List every task in ID order from both stores (the task-visibility backend).
- [x] Assemble deterministic prompts with stable section framing, excerpt bounds, and fail-instead-of-truncate sizing.
- [x] Spawn workers only for live parent tasks (ghost and finished tasks refused pre-emission).
- [x] Revoke approvals and stop their workers in one order (validation first, halt even with nothing to revoke).
- [x] Bind tool arguments end to end across the whole chain (broker bounds, permit binding, executor equality, approval-hash coverage).
- [x] Add a tool-aware model contract (`RequestedTool`) and a loopback-only Ollama localhost provider with deterministic tool-call mapping (K2 plan Phase 1 done early; model choice still pending evaluation).
- [x] Bind step runs to workers: role allowlists, cancellation flags, and step budgets enforced in the loop; exhaustion ends runs quietly.
- [x] Detect resource mode transitions purely (`mode_change` reports only changes), so future samplers and the `resource.mode_changed` event stay flap-free by construction.
- [x] Give workers parent-task binding and caller-clock deadline expiry (saturating, panic-free); `spawn` carries the parent task.
- [x] Persist every audit outcome to SQLite through a tested gate-to-store chain (covers the previously untested `Cancelled` mapping).
- [x] Run the bounded agent step loop: scripted-model proposals → invocation-table scopes → gate permits → executor dispatch → evidence capture, with flood aborts, cancellation reporting, quiet termination, and per-proposal denial tolerance.
- [x] Scaffold the Tauri 2 desktop shell (`apps/desktop`): seven thin command adapters (submit/list/query/cancel/approve/deny/inspect-contract) over the core boundary with behavior tested without the framework, in-memory state, strict CSP static workspace UI (task list, submit, cancel, detail + constraints). Verified: `cargo build`, 5 adapter tests, `node --check`. Deferred with reasons: `tauri dev` windowing/bundling run, PNG bundle icons (placeholder ICO generated for the Windows resource step), React migration.
- [x] Add strict configuration loading for the existing secure defaults.
- [x] Add a persistence boundary with transactional task-state updates and revision tracking.
- [x] Add a SQLite task-store adapter behind the persistence boundary.
- [x] Add SQLite schema versioning and append-only audit-event persistence.
- [x] Add a provider-agnostic model contract with explicit cloud opt-in routing.
- [x] Add cross-crate runtime tests for approval-required and queued outcomes.
- [x] Make the scaffolded desktop shell actually reach the core: `app.withGlobalTauri` was unset, so the static UI rendered and every `invoke` threw on the first line. Fixed with config plus a bridge check that reports itself, and the window `label` pinned to match the declared capability. (2026-09-06)
- [x] Replace the placeholder icon with a generated bundle set (32/128/256 PNG plus a four-entry ICO) from a checked-in `icons/generate.mjs`, and list the `.ico` in `bundle.icon` so WiX can find it. `cargo tauri build` now produces MSI and NSIS installers. (2026-09-06)
- [x] Fix the `KeyringSecretStore` backend: `keyring` 3.x had no store feature requested, so it silently resolved to its mock keystore and discarded every secret. Per-target `windows-native` / `apple-native` features, plus a CI-safe test that fails if the mock ever becomes the default again. Linux stays on the mock and is documented as untrusted. (2026-09-06)
- [x] Enforce licence, ban, and source policy in CI (`cargo deny` + `deny.toml`) and publish an SPDX SBOM artifact (`cargo sbom`), then correct the three dependency-review claims the desktop shell had invalidated. (2026-09-06)
- [x] Grow the adversarial suite from 9 tests to 24, two of them proved to bite against deliberately weakened guards. (2026-09-06)

## Verification status

| Check | Status | Evidence |
|---|---|---|
| Rust toolchain | Passing | `rustc 1.98.1`, `cargo 1.98.1` (was 1.94.1; re-verified on a second Windows machine 2026-09-06) |
| Formatting | Passing | `cargo fmt --all --check` |
| Linting | Passing | `cargo clippy --workspace --all-targets -- -D warnings` |
| Tests | Passing | `cargo test --workspace`: 247 passed, 1 ignored (the OS-credential round trip, which mutates real vault state) |
| Ignored OS test | Passing on Windows | `cargo test -p rocky-models -- --ignored`: 1 passed after the keyring backend feature fix |
| Licences / bans / sources | Passing | `cargo deny check licenses bans sources`: all ok, zero warnings |
| SBOM | Passing | `cargo sbom`: SPDX-2.3, 453 packages, 1336 relationships |
| Desktop environment | Passing | `cargo tauri info`: WebView2 152.0.4191.62, MSVC Build Tools 2022, all checks ✔ |
| Desktop bundling | Passing (Windows) | `cargo tauri build`: MSI + NSIS installers produced, icon extracts from the built exe. macOS needs an `icon.icns` that does not exist yet. |
| Post-change verification | Passing | All checks rerun after the 2026-09-06 batch; `node --check` clean on the UI script |

## Next tasks

1. [x] Issue non-forgeable runtime permits and introduce executor traits that consume them. (Permits done; single `FilesystemReadExecutor` struct consumes them. A shared executor trait waits for the second executor type per YAGNI.)
2. [x] Add a canonicalized, scoped filesystem-read executor.
3. [x] Add Tauri command adapters (seven thin adapters built and tested; the windowing run and PNG bundle icons landed 2026-09-06, which is also when the adapters were first reachable from the UI at all).
4. [x] Add a resource sampling adapter. (Done: single-shot sysinfo sampler feeding the pure classifier; polling cadence stays the caller's decision.)
5. [x] Consume persisted approvals in the runtime gate (verify hash, expiry, revocation before converting `ApprovalRequired` into a permit) and enforce expiration/revocation end to end.

## Planned capability areas

- [ ] Tauri 2 desktop host and React UI. (Shell + static workspace UI done and now actually functional — see the 2026-09-06 `withGlobalTauri` fix. PNG bundle icons done. React migration remains.)
- [x] SQLite persistence and migrations. (Done: `SqliteTaskStore` behind the `TaskStore` boundary, schema v2 with v1 migration, transactional transitions, append-only audit events.)
- [ ] Platform-specific, canonicalized filesystem executor.
- [x] Structured, allowlisted process executor.
- [ ] Approval UI and revocation propagation.
- [x] Model-provider abstraction and local/cloud opt-in configuration. (Done: provider contract with explicit cloud routing gate plus strict config defaults.)
- [ ] Resource sampler and cancellation propagation. (Sampler done: single-shot sysinfo readings feed the existing classifier; cancellation was already propagated.)
- [x] Prompt-injection and end-to-end adversarial test suites.
- [x] CI, dependency review, SBOM, and vulnerability scanning. (Done 2026-09-06: `fmt`/`clippy`/`test`, `rustsec/audit-check`, `cargo deny check licenses bans sources`, and an SPDX `cargo sbom` artifact are all CI jobs.)

This is an open-ended build list rather than an MVP cut line; entries move into the active queue as their prerequisites are completed.

## Plans & reviews (implementation later unless noted)

- `docs/plans/K2_HORIZON_EVALUATION.md` — local-model evaluation plan (benchmarks distrusted, hardware-gated phases; Phase 1 provider already built).
- `docs/plans/TAURI_READINESS.md` — desktop boundary review (adapters green-lit, two gaps owned).
- `docs/plans/LIVING_INTERFACE.md` — ambient companion product spec + architecture review.
- `docs/plans/VOICE_INTEGRATION.md` — Wispr Flow optional voice plan + review.
- `docs/plans/WEB_INTELLIGENCE.md` — Scrapling sidecar plan + review (not yet sequenced).
- `docs/plans/EXPANSION_VISION.md` — 17-capability vision + existence mapping + build order.
- `docs/plans/DEPENDENCY_REVIEW.md` — direct-dependency audit + CI scanning notes.

## Tasks for Saksham

- [ ] **K2 hardware inventory + viability smoke test (your machine).**
  Follow Phase 0 and Phase 0.5 of
  `docs/plans/K2_HORIZON_EVALUATION.md`: record GPU/VRAM/RAM, which K2
  sizes fit with OS headroom, whether Ollama installs cleanly, then cold
  / warm load latency, sustained tokens/sec, peak RAM+VRAM, thermals,
  and host responsiveness under normal dev load (browser + IDE open).
  No code changes. Done = dated results appended to the plan appendix
  plus a fit/viable-or-not verdict against the pre-registered gates.
- [x] **`tauri dev` windowing verification + bundle icons.** Done
  2026-09-06. `cargo tauri info` reports a clean environment (WebView2
  152.0.4191.62, MSVC Build Tools 2022, rustc 1.98.1). Three defects
  found and fixed, all config/asset only:
  1. **The workspace UI was inert.** `frontend/app.js` read
     `window.__TAURI__.core`, but `app.withGlobalTauri` was unset and
     Tauri 2 defaults it to `false`
     (`tauri-utils-2.9.3/src/config.rs:3073`), and the file is a classic
     `<script>` with no bundler, so there was no module import to fall
     back on. The window opened and rendered static HTML while every
     flow threw on line one. Fixed by setting `withGlobalTauri` and by
     making a missing bridge report itself in `#form-error` instead of
     dying silently.
  2. **`bundle.icon` referenced three PNGs that did not exist**; only a
     16x16 placeholder ICO did. Replaced with a generated set (32, 128,
     256 plus a four-entry ICO) from `icons/generate.mjs`, checked in as
     source so the artifacts are re-derivable and cost no new
     dependency.
  3. **Bundling still failed after that**, verbatim:
     `Error failed to bundle project: `Couldn't find a .ico icon``. The
     WiX bundler looks for a `.ico` in the configured icon list, not on
     disk, and `icons/icon.ico` was never listed. Added.
  Verified end to end afterwards: `cargo tauri build` produced
  `rocky-desktop_0.1.0_x64_en-US.msi` and
  `rocky-desktop_0.1.0_x64-setup.exe`, and the icon extracts from the
  built exe. Also pinned the window `label` to `main` so it matches the
  existing `capabilities/default.json` explicitly rather than by
  default. Backend side of every UI flow now covered by two new adapter
  tests, including the double-cancel a terminal row's Cancel button
  makes reachable. Still open: no `icon.icns`, so macOS bundling will
  fail the same way item 3 did — deliberately not guessed at from a
  Windows machine. React migration still deferred.
- [x] **Secret OS-backend re-verification.** Done 2026-09-06. Reproduced
  the failure exactly on a second, independent Windows 11 machine, then
  found the 2026-09-05 "vault/session quirk" diagnosis was wrong. Root
  cause: `keyring` 3.x compiles in no credential store unless a store
  feature is requested, and with none requested it resolves
  `pub use mock as default`; the mock builder returns a fresh empty
  credential per `Entry::new`, and `KeyringSecretStore::entry` builds one
  per operation, so the write landed in a dropped value. Confirmed by
  `cargo tree -p keyring` resolving only `log` + `zeroize`. Fixed with
  per-target features (`windows-native`, `apple-native`); the ignored
  round-trip test now passes on this machine. Verdict: the backend is
  dependable on Windows and macOS; the round-trip test stays `#[ignore]`d
  because it mutates real OS credential state and CI has no vault.
  Regression cover is `keyring_backend_is_not_the_mock_store`, which runs
  in CI, touches no credential, and was proved to bite (removing the
  feature makes it fail with its own diagnostic). **Linux is still on the
  mock store** and must not be trusted; recorded as an open item in
  `docs/plans/DEPENDENCY_REVIEW.md`.
- [x] **SBOM + license automation.** Done 2026-09-06. `cargo sbom` emits
  SPDX 2.3 (verified locally: 453 packages, 1336 relationships,
  `pkg:cargo` purls) and `cargo deny` enforces licence, ban, and source
  policy from `deny.toml`; both are wired into
  `.github/workflows/ci.yml` as the `sbom` and `supply-chain` jobs.
  Advisories deliberately stay with the existing `audit` job so each
  control has one enforcement point. The review also corrected three
  claims the desktop shell had invalidated: the workspace has eight
  direct dependencies, not two; Tauri brings `tokio`, `hyper`,
  `reqwest`, and `rustls` into the graph, so "no async runtimes, no HTTP
  clients" is now only true of ROCKY's own crates; and the licence set is
  not MIT/Apache-only — `MPL-2.0` needed an explicit decision and
  `LGPL-2.1-or-later` is deliberately excluded from the allowlist. Every
  workspace crate now sets `publish = false`, which is what makes the
  licence gate report third-party obligations only. Both open items in
  `docs/plans/DEPENDENCY_REVIEW.md` are closed; two new ones are named.
- [x] **Adversarial fixture expansion.** Done 2026-09-06.
  `crates/rocky-runtime/tests/adversarial.rs` grew from 9 tests to 24,
  each stating the invariant it pins: tool-id shadowing (plus the
  stronger point that a definition's scope is never authority),
  kind-confused *approvals*, expiry closing on the clock alone with no
  store write, revoked SQLite area trust, `DenyAction` not retracting
  area trust, the two approval paths refusing each other's records,
  approvals queueing under capacity pressure without being consumed,
  A4 and over-ceiling autonomy refused with no approval able to rescue
  them, argument floods erroring before any audit entry, post-permit
  argv substitution stopped before any spawn, a held permit dying with
  its worker, `.` and backslash traversal, the deliberately-permitted
  separator cases, and battery/idle backpressure. Two were proved to
  bite by weakening the guard they cover; those quote the outcome the
  weakened code produced.
- [ ] **K2 evaluation runs (gated on inventory).** Only after the
  inventory verdict: run the Phase 3 benchmark battery and record the
  dated results table + adopt/reject decision. Do not start early.

## Guardrails

- No component may execute OS actions without passing through the tool broker and policy layer.
- No capability is granted by model output or untrusted content.
- New workers require finite budgets, deadlines, and depth checks.
- All progress claims require command output or tests as evidence.


ALL THE WORK DONE BY ANY AGENT WILL BE REVIEWED BY CODEX THOUROUGHLY AT ITS HIGHEST EFFORT SETTING, WHICH WILL RESULT IN CONSEQUENCES IF ANY BUGS ARE FOUND.