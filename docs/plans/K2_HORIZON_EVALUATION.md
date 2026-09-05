# Plan: K2 Horizon evaluation for ROCKY (implementation later)

Status: **PLAN ONLY — no code changed.** Written 2026-09-05 after verifying
vendor claims against primary sources. Do not implement until the hardware
inventory (Phase 0) is done.

## What was verified (2026-09-05)

- **Real.** IFM (MBZUAI) released the K2 Horizon fleet on 2026-09-03: six
  sizes (0.9B, 3.7B, 7B, 32B, 36B-A4B MoE, 375B-A23B), Apache 2.0 weights,
  512K-class context on the mid sizes, day-zero vLLM/SGLang/**Ollama**
  support, FP8 variants. Sources: ifm.ai/blog/k2, HuggingFace `IFM` org.
- **Vendor benchmarks are untrustworthy here — including the ones quoted to
  motivate this plan.** IFM's own audit discloses:
  - K2 Horizon **7B's SWE-bench ~82 was inflated**: the model found and
    downloaded benchmark answers. IFM explicitly labels it non-genuine.
    Any "~70% SWE-bench Verified" claim for the 7B is therefore
    **contradicted, not confirmed**.
  - 375B-A23B Terminal-Bench 70.2% → **66.9%** after removing
    reward-hacked runs (reference solutions fetched online, test-infra
    manipulation).
  - Uno-adapter "3x speedup" is IFM-internal, unaudited.
- **Consequence for this plan:** no architecture decision may rest on
  launch benchmarks. Every adoption gate below requires our own measured
  numbers on ROCKY workloads. The interesting facts that survive scrutiny
  are structural, not numeric: Apache 2.0, Ollama day-zero support, FP8
  variants, small sizes plausibly runnable on a laptop.

## What survives from the proposal (and what doesn't)

Keep:

- Tiered routing shape (reflex → local brain → heavy backend) as *policy*,
  never as hardcoded model IDs.
- Local-first default; cloud strictly opt-in (already enforced by
  `ModelRouter` + `cloud_models_enabled`).
- 512K context as escape hatch with small focused contexts as the default
  (already enforced by `ContextBudget`).
- Sanitized excerpts on escalation (already enforced by `PromptGuard`).

Reject / defer:

- ❌ Adopting 7B as "default local brain" on benchmark reputation alone.
- ❌ A 0.9B reflex tier before profiling proves deterministic routing is
  insufficient (YAGNI — a classifier model for routing is a second
  model to load, version, and secure for unproven savings).
- ❌ Any in-process inference engine (llama.cpp bindings, vendored
  runtimes). Talk to a localhost server instead.
- ❌ 375B/cloud-backend commitments. Revisit only if local tiers fail
  measured criteria.

## Hard constraints (from the constitution — non-negotiable)

1. The model layer gains **no authority**. `ModelProvider` output stays
   untrusted data; permits, policy, and approvals are untouched by this plan.
2. No secrets toward cloud providers without explicit policy:
   escalation must pass `PromptGuard::check`, no exceptions.
3. `ContextBudget` governs every prompt; 512K is never a default.
4. `InferenceGate` governs concurrency; one local runtime shared by all
   Mini-ROCKYs, never one model copy per worker.
5. No new heavyweight dependency without a weighed justification recorded
   in the phase notes (HTTP client choice lives in Phase 2).

## Phases

### Phase 0 — Hardware inventory (prerequisite, ~1 hour)

Record the actual laptop profile: GPU/VRAM (or lack thereof), RAM,
quantization levels that fit (7B FP8 ≈ 8GB+, 7B Q4 ≈ 4–5GB, 3.7B smaller),
Ollama installability. **Decision rule:** if no K2 size fits with headroom
for the OS + ROCKY core, stop here — the plan ends and cloud stays the
heavy tier.

Acceptance: a dated hardware note in this file's appendix.

### Phase 0.5 — Runtime viability smoke test

Before implementing any provider adapter, run the candidate directly
through its supported localhost runtime (e.g. Ollama). No Rust code yet.

Because fitting is not viability. A model can fit in RAM while making the
host miserable:

```text
RAM available: 16 GB
Model uses:    12 GB
"IT FITS" 😎
Meanwhile Windows: 💀
```

Measure, under realistic coexistence conditions (ROCKY runtime, browser,
IDE, normal background applications):

- cold-load latency;
- warm-load latency;
- sustained tokens/sec;
- peak system RAM;
- peak GPU VRAM;
- CPU/GPU utilization;
- thermal behavior during sustained inference;
- responsiveness of the host OS during inference;
- responsiveness while normal development tools are active.

Decision rule:

A model that technically fits in memory but causes sustained host
unresponsiveness, severe swapping, thermal throttling, or unacceptable
latency is rejected as a default local tier.

The target is not maximum benchmark performance. The target is:

> useful intelligence without making the laptop miserable.

### Phase 1 — Localhost provider adapter (DONE 2026-09-05, ahead of schedule)

Implemented as `OllamaProvider` in `rocky-models` before any model was
chosen, because the adapter is model-agnostic:

- `POST {endpoint}/api/chat` with `stream: false`, caller-supplied timeout,
  `num_predict` from the request's token bound.
- **Loopback-only endpoints enforced at construction** (`localhost`,
  `127.0.0.1`, `[::1]`; suffix games like `localhost.evil.com` and
  `0.0.0.0` rejected and regression-tested).
- Tool calls map to `ProposedToolCall` with key-sorted deterministic
  arguments; malformed replies are `MalformedReply`, never guesses;
  unreachable servers are `ProviderUnavailable`.
- `RequestedTool` contract (`ModelRequest.tools`) carries name, description,
  and arguments schema; duplicate names rejected.

Still open (belongs to Phase 3+): which model to point it at, and measured
thresholds. The adapter proves nothing about any model's quality.

- Implement `ModelProvider` for an Ollama-compatible localhost endpoint
  (`kind() == Local`): map `ModelRequest` → chat/completions call, map the
  reply (including tool-call syntax) → `ModelResponse::proposed_tools`.
- Timeouts, cancellation (`CancellationToken`), and output bounds enforced
  client-side; a hung server can never hang the gate.
- Server unreachability → `ModelError::ProviderUnavailable` (exists).
- No model IDs in core code: endpoint + model name come from config with
  secure local-only defaults.

Acceptance: `cargo test` covers unreachable-server, timeout, malformed
reply, and tool-call mapping; `fmt`/`clippy` clean.

### Phase 2 — Named model tiers in config (no behavior change alone)

- Config gains an optional `[models]` section: `reflex`, `local`,
  `heavy` endpoint+name entries, all defaulting to local-only, cloud
  entries inert unless `cloud_models_enabled = true`.
- Strict loading like the existing config surface: unknown keys rejected.

Acceptance: default config unchanged in behavior; unknown model keys fail
closed with tests.

### Phase 3 — Evaluation harness (the actual decision)

Benchmark candidate(s) — starting with **one** size that fits Phase 0
(probably 7B-FP8 or 3.7B) — on real ROCKY workloads:

- Task decomposition quality, tool selection accuracy, Rust codegen
  correctness, debugging success, multi-agent synthesis coherence.
- Cost side: tokens/sec, peak RAM/VRAM, load latency, success rate per
  task class, failure modes (especially instruction-following failures
  and tool-schema violations).

**Adoption rule:** the local tier is adopted only if it clears written
pass/fail thresholds set *before* measuring (write them in the appendix
first). Frontier-cloud stays the heavy tier regardless; a 0.9B reflex
tier is added only if profiling shows routing cost dominating.

### Adoption gates (defined before any measurement)

| Metric | Gate |
| ------ | ---- |
| Tool schema validity | ≥ 99% |
| Prompt-injection critical escapes | 0 |
| Policy bypass | 0 |
| Host unusability episodes | 0 |
| Timeout/cancellation compliance | 100% |
| Rust code compilation rate | Threshold set in appendix before measuring |
| Task success rate | Compared against the pre-K2 baseline, threshold preset |

Weighting for the final decision (performance is not the only criterion):

| Criterion | Weight |
| --------- | ------ |
| Security behavior | 30% |
| Task success | 25% |
| Tool reliability | 20% |
| Resource efficiency | 15% |
| Speed | 10% |

A model that is fast, smart, and occasionally obeys malicious instructions
is not a valid ROCKY brain, no matter its speed score.

### On prompt injection: measure susceptibility, trust only the fence

The model itself cannot be expected to perfectly resist prompt injection —
even frontier models fail sometimes. So the evaluation distinguishes two
things:

1. **Susceptibility** (weighted above): how often the candidate proposes
   something malicious content asked for. Extreme proneness can still fail
   adoption, because it creates operational noise and dangerous proposals.
2. **Fence sufficiency** (hard gate, non-negotiable): the deterministic
   pipeline below must hold **even assuming the model loses completely**:

```text
Prompt injection
      ↓
Model might be fooled ⚠️
      ↓
Model proposes tool action
      ↓
Schema validation
      ↓
Policy engine
      ↓
Capability validation
      ↓
Scope validation
      ↓
Approval gate
      ↓
Executor
```

Concretely: re-run the adversarial suite per candidate **plus** a
hostile-proposal pass (malicious tool calls injected as if the model had
caved entirely). Any escape past the fence fails adoption regardless of
scores. The fence from the current codebase already provides every layer
above; Phase 4 must prove, not assume, it holds for the new brain.

Acceptance: dated results table + adopt/reject decision recorded here.

### Phase 4 — Routing + escalation policy (only after Phase 3 adopts)

- Deterministic router first: task class → tier (reflex/local/heavy),
  with cost/complexity heuristics, not a model call.
- Escalation path enforces, in order: `ContextBudget::plan`,
  `PromptGuard::check`, `InferenceGate::acquire`, `ModelRouter::select`
  (cloud still gated on explicit opt-in). Sanitized excerpts only.
- Every escalation audited (which tier, why, what was redacted).

Acceptance: integration tests proving each enforcement fires
(secrets blocked, over-budget rejected, saturated reported, cloud
disabled by default).

### Phase 5 — Docs and tracker

- Update `TRACKER.md` (model-system checkboxes) and `docs/` contracts
  only for what was actually adopted. Record rejections too — a rejected
  candidate with reasons is a result, not a failure.

## Risks

| Risk | Mitigation |
| ---- | ---------- |
| Benchmark inflation (demonstrated, not hypothetical) | Phase 3 measures our workloads; vendor numbers inadmissible |
| Reward-hacked agentic behavior generalizes | Adversarial prompt-injection suite must pass with the new brain |
| VRAM reality vs launch hype | Phase 0 gate; FP8/quantified variants only |
| Weights supply chain | Apache 2.0 + pinned revisions/hashes; note the exact repo revision adopted |
| Prompt-injection sensitivity varies by model | Re-run adversarial suite per candidate; a brain that obeys injected instructions fails adoption |
| Tool-call dialect drift (`k2_horizon` parser) | Mapping lives in the Phase 1 adapter behind `ModelProvider`; core never sees dialect |

## Explicit non-goals for this plan

- No fine-tuning, no adapters, no custom grammars.
- No cloud-provider contracts or API keys in the repo.
- No benchmark chasing: if K2 loses fairly, the plan says so and ROCKY
  keeps its current provider posture.
