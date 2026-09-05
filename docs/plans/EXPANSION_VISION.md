# Plan: ROCKY expansion vision (17 capabilities) — implementation later

Status: **PLAN ONLY — no code changed.** Received as a ranked wishlist;
reviewed 2026-09-05 against the tree. The single most important finding:
**large parts of Tiers 2–3 already exist** — the proposal undercounts the
current system. §B maps every item to its true status.

## A. The wishlist (as received, condensed)

**Tier 1 — Make him alive:** animated Rocky, voice input/output, ambient
desktop presence. (Covered by `LIVING_INTERFACE.md` + `VOICE_INTEGRATION.md`.)

**Tier 2 — Make him useful:** real model (K2 eval), workspace awareness,
file tools, process tools, web intelligence. (Largely built; see §B.)

**Tier 3 — Make him powerful:** mini-Rocky specialists, sandboxing,
screen understanding, computer interaction, deep research.

**Tier 4 — Make him YOUR Rocky:** long-term memory, skills, personal
knowledge graph, proactive behavior, contextual animations.

Ranked items: 1 screen awareness, 2 computer use, 3 persistent memory
(working/episodic/semantic/procedural), 4 skill system (recipes, not
self-modification), 5 dry-run/simulation mode, 6 DAG mission planner,
7 proactive Rocky (with `ProactivityPolicy`), 8 multimodal input,
9 specialist personalities, 10 personal knowledge graph, 11 plugin/skill
ecosystem (declared capabilities, never `computer.everything`), 12
contextual presence, 13 deep-research engine, 14 sandboxes, 15 background
tasks (scoped, expiring, budgeted, visible), 16 self-evaluation
(Completed/Verified/Partial/Failed/Unknown), 17 behavioral/emotional
expression from real events. Top-5 picks: screen, memory, sandbox,
deep research, skills.

## B. Existence mapping (verified, not assumed)

| # | Item | Status in tree (2026-09-05) |
| - | ---- | --------------------------- |
| 2-adjacent | File tools | ✅ DONE (scoped read executor + broker + permits) |
| 2-adjacent | Process tools | ✅ DONE (allowlisted executor, no shell) |
| 9 | Specialist mini-Rockys | ✅ DONE (`SpecialistRole`, least-privilege registry, `spawn_specialist`; `SpecialistProfile` ≡ `SpecialistRole` + budget + success criteria — only success-criteria text is missing) |
| 13-adjacent | Research fan-out | ✅ DONE (decompose + workers + boards + evidence) |
| 16-adjacent | Evidence-based completion | ✅ PARTIAL (evidence capture + terminal states exist; `Verified`/`PartiallyCompleted` states do not) |
| 17 | Behavioral expression | ✅ BACKEND READY (every listed trigger maps to an existing event; expression itself is frontend-owned per living-interface review) |
| 12 | Contextual presence | ✅ BACKEND READY (`ResourceMode` + `mode_change` feed it directly) |
| 11 | Plugin ecosystem | ✅ PATTERN EXISTS (broker registration + invocation tables + declared capabilities; no plugin loader — correctly so, premature) |
| 3-partial | Episodic memory substrate | ✅ EXISTS UNLABELED (audit trail + findings + evidence ARE episodic memory; what's missing is semantic facts + retrieval) |
| 5 | Dry-run mode | ❌ MISSING (but cheapest high-value item — see §D) |
| 3 | Semantic/procedural memory + retrieval | ❌ MISSING (design below) |
| 4 | Skills | ❌ MISSING (design below) |
| 6 | DAG planner | ❌ MISSING (decompose is single-level; dependencies/retries absent) |
| 7 | Proactivity | ❌ MISSING (needs policy + triggers; nothing structural blocks it) |
| 1, 8 | Screen/vision/multimodal | ❌ MISSING (OS APIs + vision-capable model required) |
| 2 | Computer interaction | ❌ MISSING — **and in tension with the constitution, see §C** |
| 10 | Knowledge graph | ❌ MISSING (correctly so — needs scale justification first) |
| 14 | Sandboxes | ❌ MISSING (smaller than it looks — see §D) |
| 15 | Background tasks | ❌ MISSING (needs OS wake integration; pattern already specified) |

## C. Constitutional flags (must be decided, not drifted into)

1. **Computer Use vs non-goals.** The constitution lists "general
   unrestricted desktop autonomy" as an explicit non-goal. Scoped
   `computer.observe/click/type` with window constraints, approvals, and
   a kill switch is arguably *not* that — but arguably it is. This needs
   an explicit constitutional decision + threat-model update BEFORE any
   click/type executor exists. The wishlister's own design (bounded
   coordinates, app identity, approvals, kill switch) is the right shape
   *if* the decision goes yes. Until then: observe-only discussion, zero
   interaction code.
2. **Screen awareness vs privacy.** Screen pixels are the most sensitive
   data class in the project (passwords, banking, messages). The
   proposed `ScreenCapability` scopes are correct; additionally: captures
   must be evidence-store entries (bounded, hashed, expiring — never an
   open-ended screenshot folder), secrets in pixels get the same
   redaction thinking as text, and full-desktop capture should require
   A3-style explicit confirmation every session, not a standing grant.
3. **Skills vs self-modification.** Enforce the stated line in code
   review, not just docs: skills may bundle decompositions + scopes +
   standing grants, never code, prompts-as-policy, or permission edits.
4. **Proactive vs Clippy-with-root.** `ProactivityPolicy` must gate on
   (signal strength × expected value × reversibility) with a global
   quiet-hours/off switch; proactive actions use the SAME permit path
   (no fast lane), and proactive suggestions are capped per day by
   default. Annoyance is a reliability bug.
5. **Sandbox scope honesty.** A "sandbox" here means scoped temp-dir
   workspaces + existing executors + kill switches — not containers,
   not VMs. Say so explicitly or the word will inflate the design.

## D. Recommended build order (my take, differing in two places)

The proposal's top-5 is directionally right; I would reorder by
(cost × security-fit), cheapest transformative first:

1. **Dry-run mode** (proposal #5, my #1 pick). The permits already
   exist *before* execution: preview = collect the permits a run WOULD
   consume, render them human-readably, execute only on approval. This
   is a small orchestrator addition with 11/10 security value. Build
   first.
2. **Semantic memory + SQLite FTS5 retrieval** (proposal #3 core).
   Facts KV table + full-text search over findings/evidence using the
   ALREADY-BUNDLED SQLite FTS5 — zero new dependencies, no vector DB,
   recency+keyword ranking. Episodic substrate exists; this completes
   "remember" without new infrastructure.
3. **Skills as versioned recipes** (proposal #4): named decomposition
   templates + scope + standing-grant references, inspectable/revocable/
   testable. Builds on decompose + roles + decisions; forbids
   self-modification structurally.
4. **Self-evaluation states** (proposal #16 core): `Verified` /
   `PartiallyCompleted` task states + a verify-step convention
   (evidence re-check). Tiny domain change, large reliability payoff.
5. **Sandbox workspaces** (proposal #14): temp-dir roots + scoped
   executors + existing kill paths. Small once stated honestly.
6. **Then** planner DAG, proactive policy, background tasks, knowledge
   graph (in that dependency order — each needs the previous).
7. **Last, gated on constitutional decisions:** screen awareness, then
   computer interaction. Highest value AND highest risk; the fence must
   be proven on everything else first.

## E. Explicit non-goals carried forward

- No unrestricted desktop autonomy without a constitutional amendment.
- No open-ended screenshot stores; captures are bounded evidence.
- No vector database until FTS5 demonstrably fails.
- No MCP-protocol adoption (per web-intelligence review).
- No new model capabilities assumed: every brain-dependent item
  re-runs the K2 adoption gates.
