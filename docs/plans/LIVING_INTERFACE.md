# ROCKY — Living Interface & Ambient Desktop Presence Plan

## Status

**PRODUCT/UI ARCHITECTURE PLAN**

This plan defines ROCKY's intended user experience as a living, animated, voice-first desktop companion.

ROCKY is **not** a chatbot interface with a mascot attached.

The character, animation system, voice system, and agent runtime are parts of one integrated product.

---

# 1. PRODUCT VISION

The primary interaction should feel like this:

> You are working on your laptop.

ROCKY is present in the corner of your screen.

You say:

> **"Rocky, figure out why my Android build is failing."**

ROCKY reacts.

He looks toward you.

He acknowledges the request.

He begins thinking.

He may split into multiple visual Mini-Rocky representations.

He investigates.

His behavior visibly changes depending on what he is doing.

When he finds something, he talks to you.

You can ask follow-up questions naturally.

You should not need to open a chat window to begin working.

The fundamental experience is:

```text
YOU SPEAK
    ↓
ROCKY HEARS
    ↓
ROCKY REACTS
    ↓
ROCKY UNDERSTANDS
    ↓
ROCKY WORKS
    ↓
YOU WATCH WHAT HE IS DOING
    ↓
ROCKY TALKS BACK
```

The interface is a **living visualization of the agent runtime**.

---

# 2. CORE PRODUCT PRINCIPLE

## ROCKY IS A CHARACTER, NOT A CHAT WINDOW

The UI must never be designed around the assumption that the primary interaction is:

```text
User message
↓
Assistant message
↓
User message
↓
Assistant message
```

Instead:

```text
Ambient presence
        ↓
Voice interaction
        ↓
Visible behavior
        ↓
Agent activity
        ↓
Natural spoken feedback
```

Text remains available for:

* accessibility;
* reviewing work;
* long technical information;
* searching history;
* debugging;
* explicit task inspection.

But text is **secondary**.

Voice and character behavior are primary.

---

# 3. ROCKY HAS TWO PRESENCE MODES

ROCKY should exist in two distinct forms.

---

## MODE A — AMBIENT DESKTOP ROCKY

This is ROCKY's default form.

When the main window is closed or minimized, ROCKY remains visible in a
configurable screen location (default: bottom-right corner).

This is not a minimized application icon. It is an actual transparent,
borderless, animated, always-available desktop presence. The character
continues to animate. The agent continues to work when authorized. The
user can interact with ROCKY directly.

---

## MODE B — EXPANDED WORKSPACE

When the user clicks ROCKY, asks for details, or explicitly opens the
workspace, a visual command center appears showing what ROCKY is doing,
what he has discovered, Mini-Rockys, approvals, resource usage, task
state, evidence, and important results.

This is **not a chat page**.

---

# 4. THE AMBIENT DESKTOP PET WINDOW

The minimized ROCKY must continue to exist independently from the
expanded workspace. Both windows communicate through the same typed
application state.

The ambient window should support: transparent background, frameless
rendering, always-on-top option, click interaction, drag repositioning,
configurable size, opacity, monitor selection, and animation in both idle
and working states.

---

# 5. ROCKY'S BEHAVIOR SYSTEM

ROCKY should never randomly play animations. The character animation must
represent actual runtime state. The runtime publishes semantic state, for
example: `Idle`, `Listening`, `Thinking`, `Working`, `Investigating`,
`WaitingForTool`, `WaitingForApproval`, `Speaking`, `Happy`, `Confused`,
`Error`, `Sleeping`, `Celebrating`. The animation system maps those states
to behavior.

---

# 6. ROCKY'S ANIMATION STATE MACHINE

```text
                         ┌──────────┐
                         │   IDLE   │
                         └────┬─────┘
                              │
                  Voice activation
                              │
                              ▼
                       ┌────────────┐
                       │ LISTENING  │
                       └─────┬──────┘
                             │
                             ▼
                       ┌────────────┐
                       │ THINKING   │
                       └─────┬──────┘
                             │
                ┌────────────┼────────────┐
                ▼            ▼            ▼
           WORKING       SPEAKING      CONFUSED
                │            │            │
                └────────────┼────────────┘
                             ▼
                           IDLE
```

The character state must be driven by real events (inference start →
thinking animation, active workers → working animation, approval required
→ pause and look at user, speech synthesis → talking animation).

---

# 7. ANIMATION LIBRARY

Reusable animation primitives for: idle (breathing, swaying, blinking),
listening (attentive posture), thinking (pacing, head tilt), working
(focused movement), happy/success (hopping, celebration), confused (head
tilt, pause), waiting (looks toward user), sleeping (optional low-activity
rest mode).

---

# 8. 2D ANIMATION TECHNOLOGY

Preferred initial architecture: character assets → 2D rig/animation
system → animation state machine → renderer → Tauri window. Must support
skeletal animation, layering, blending, transitions, expressions,
procedural movement, and lip-sync states. The animation layer stays
independent from agent logic. The Rust runtime emits semantic events
(`ThinkingStarted`, `ApprovalRequested`, `TaskSucceeded`, `WorkerSpawned`,
…); the UI decides how those look. The Rust runtime must never contain
`play_happy_dance()`.

---

# 9. VOICE-FIRST INTERACTION

Primary input is voice: microphone → wake word → voice activity detection
→ speech-to-text → goal interpretation → ROCKY runtime.

---

# 10. WAKE WORD SYSTEM

`"Rocky"` is the primary wake phrase. The always-listening system must be
lightweight, local, explicitly enabled, and independently disableable.
A low-cost wake-word detector gates the microphone pipeline — the main
agent model must **not** continuously process microphone audio (no 24/7
LLM inference 💀).

---

# 11. VOICE OUTPUT

ROCKY responds through speech planning → text-to-speech → audio playback
→ lip-sync animation, visibly reacting while speaking. MVP lip-sync may
use phoneme/viseme approximation or audio amplitude.

---

# 12. ROCKY SHOULD NOT NARRATE EVERYTHING

Critical: a voice agent narrating every micro-step becomes unbearable.
ROCKY needs a communication policy — silent work by default (animation
communicates activity), speech for clarification, approvals, important
discoveries, completion, and errors. Live narration only on request
("Tell me what you're doing").

---

# 13. MINI-ROCKYS AS VISUAL CHARACTERS

Spawned workers become visible Mini-Rockys (logs / build / config).

**CRITICAL RULE:** visual Mini-Rockys must not imply additional model
instances. They represent logical workers, not loaded LLMs. The UI
subscribes to actual worker lifecycle events (`WorkerSpawned`,
`WorkerWorking`, `WorkerWaiting`, `WorkerCompleted`, `WorkerCancelled`).
The visualization mirrors reality.

---

# 14. MINI-ROCKY BEHAVIOR

Workers may carry specialist identity (investigator, tester, dependency,
builder animations). Specialization stays cosmetic — permissions still
come from the deterministic capability system. A cute animation must
never imply authority.

---

# 15. VISUAL WORK REPRESENTATION

Four disclosure layers: character (what is he doing) → human-readable
activity → technical detail → full audit. Normal users get the character;
developer Siddharth gets SHOW ME EVERYTHING 🔥.

---

# 16. APPROVALS MUST INTERRUPT VISUALLY

When approval is required, the character visibly stops (🪨✋) and a
compact approval card appears (Allow / Deny / inspect). Approval may come
by click, voice, or inspection — but spoken approval maps into the
existing deterministic approval system. **Voice is input, not
authorization bypass.**

---

# 17. AMBIENT INTERACTION

Click (attention), double-click (workspace), drag (reposition),
right-click (pause/mute/settings/workspace/quit), voice (primary).

---

# 18. CLICK-THROUGH MODE

Idle ROCKY must not block the desktop beneath him: configurable normal
vs click-through pointer modes, with proximity-based interactivity as an
option.

---

# 19. FULL APPLICATION ARCHITECTURE

```text
                     ┌───────────────┐
                     │     USER      │
                     └───────┬───────┘
                             │
                  ┌──────────┼──────────┐
                  │                     │
                  ▼                     ▼
             🎤 VOICE              🖱 VISUAL
                  │                     │
                  └──────────┬──────────┘
                             ▼
                     INTERACTION LAYER
                             │
                             ▼
                       ROCKY RUNTIME
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
      AGENT CORE         MINI-ROCKYs         TOOLS
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │
                             ▼
                       EVENT STREAM
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
        🎭 Animation      🖥 Workspace    🔊 Speech
          Engine             UI              Engine
```

Core principle: **the runtime produces facts; the presentation layer
produces personality.**

---

# 20. EVENT-DRIVEN CHARACTER SYSTEM

Dedicated UI event vocabulary (`HeardWakeWord`, `ListeningStarted`,
`ThinkingStarted/Finished`, `TaskStarted/Completed/Failed`,
`WorkerSpawned/Completed`, `ApprovalRequested/Resolved`,
`SpeechStarted/Finished`, …) consumed by the character engine. Agent
runtime ≠ animation logic, always.

---

# 21. RESOURCE GOVERNANCE FOR THE UI

The UI obeys the laptop-friendly philosophy: HIGH / BALANCED / LOW POWER
/ CRITICAL visual quality levels driven by a published
`VisualPerformanceMode`. The resource governor publishes; the UI adapts.

---

# 22. IDLE RESOURCE TARGET

When idle: no LLM inference, no active agent loop, no unnecessary
network, no constant heavy rendering. Reduce activity on screen lock,
battery, gaming, pressure, or occlusion.

---

# 23. IMPLEMENTATION ROADMAP

- **UI-0** Character foundation: asset format, transparent ambient
  window, renderer, idle animation, drag, workspace open/close.
- **UI-1** Animation state system wired to mock runtime events.
- **UI-2** Real runtime events (task/worker lifecycle, inference,
  approvals, cancellation).
- **UI-3** Voice input (wake word → VAD → STT → goal submission).
- **UI-4** Voice output (TTS → audio → talking animation).
- **UI-5** Mini-Rocky visualization (spawn/active/complete/cancel).
- **UI-6** Ambient approvals (visual + spoken + click + voice + deny).
- **UI-7** Expanded workspace (tasks, minis, evidence, findings,
  approvals, resources — never chatbot-first).

---

# 24. THE FINAL EXPERIENCE

*"Rocky, why is this app crashing?" → wakes, looks, "I'll take a look"
→ splits into Mini-Rockys → works in the corner while you code →
celebrates → "Your Android dependency versions are conflicting" →
"Fix it." → pauses, "This will modify three project files. Want me to
proceed?" → "Go ahead." → modifies through the capability and approval
system → tests run → "Done. The build is passing again."* 🪨🎉

---

# FINAL PRODUCT PRINCIPLE

ROCKY should feel like **a small intelligent creature living on your
computer** — not an AI website in a desktop window. The intelligence is
the backend. The character is the experience. Neither is an afterthought.

---

# 25. ARCHITECTURE REVIEW (added 2026-09-05, verified against the tree)

This plan is compatible with the codebase with **no structural changes
required**. Findings, backend-readiness per roadmap phase, and required
additions:

## 25.1 What already exists for this plan

- **Event stream + versioned protocol** (`rocky-ipc`): task, worker,
  tool, approval, and resource events with correlation IDs. Today's
  producers cover task lifecycle, tool lifecycle (via `StepRun::events`),
  and approval holds. Missing producers are exactly Gap 1 (agent
  spawn/finding events — orchestrator now emits both) and Gap 2
  (resource mode — `mode_change` helper ready, sampler exists).
- **Approval determinism** (§16): `decisions` module already binds
  approve/deny commands to stored grants; voice approval would arrive as
  a `DenyAction`/`ApproveAction` command — input, not bypass. No change.
- **Mini-Rocky honesty** (§13–14): worker lifecycle, specialist roles,
  and least-privilege selection exist; findings are documented data, not
  authority. Cosmetic specialization is already the only kind possible.
- **Resource governance hookup** (§21–22): `ResourceMode` +
  `mode_change` map directly onto `VisualPerformanceMode`
  (Normal→HIGH/BALANCED, Constrained→LOW POWER, Critical→minimal).
  Idle targets (§22) match the existing governor (no inference while
  idle is already structural).
- **Disclosure layers** (§15): task snapshots, evidence records, audit
  trail, and findings stores already provide layers 2–4 verbatim.

## 25.2 What the plan still requires from the backend (small, enumerated)

1. **Presence event vocabulary** (§5, §20): `Listening*`, `Thinking*`,
   `Speech*`, `HeardWakeWord`, `ApprovalResolved` have no Rust
   counterpart today — correctly so, because they describe UI/microphone
   state the core never observes. Resolution: define them in the
   frontend event vocabulary (or a `rocky-ipc` presence extension),
   produced by the interaction layer, never by the core. `Waiting`,
   `Happy`, `Confused`, `Sleeping`, `Celebrating` are likewise
   presentation-mapped states, not core states — allowed by the
   architecture, provided the mapping table is explicit and reviewed.
2. **Communication policy** (§12): needs a small runtime struct when
   voice output exists (verbosity level + speak-on rules); not needed
   before UI-4. Do not build it early.
3. **Wake-word engine** (§10): prefer deterministic tiny-model/VAD
   options first; the K2 plan's reflex-tier rule applies (no 0.9B
   integration until profiling justifies it over a dedicated wake-word
   detector, which is kilobytes, not gigabytes).
4. **STT/TTS selection** (UI-3/UI-4): local-first options evaluated
   against the same adoption-gate discipline as K2 (thresholds first,
   privacy as a weighted criterion, microphone data never leaves the
   machine without explicit policy — extend `PromptGuard` thinking to
   audio transcripts).

## 25.3 Backend readiness per roadmap phase (as of 2026-09-05)

| Phase | Backend status |
| ----- | -------------- |
| UI-0 | No backend needed (window/renderer/assets only) |
| UI-1 | Ready (mock against the real `EventPayload` shapes) |
| UI-2 | Ready (all producers exist) |
| UI-3 | Blocked on STT/wake-word selection + `SubmitGoal` wiring (handler exists) |
| UI-4 | Blocked on TTS selection + communication policy (§25.2.2) |
| UI-5 | Ready (spawn/finding/completion events exist) |
| UI-6 | Backend ready (`decisions` + standing grants); needs product thought on standing-trust UX |
| UI-7 | Ready (snapshots, listings, evidence, audit, findings stores all exist) |

## 25.4 Non-negotiable mappings (for whoever builds the frontend)

- Every approval path in TypeScript must terminate in an
  `ApproveAction`/`DenyAction` command. Authorization logic in the
  frontend is a defect, not a shortcut (already the review rule).
- No animation may imply authority the capability system did not grant
  (§14 is already structurally enforced: roles carry tools, the step
  loop enforces them pre-gate).
- The 24/7-inference ban (§10, §22) is already structural (event-driven
  idle, no polling loops, bounded everything). The frontend must not
  reintroduce it via render loops or microphone streaming to an LLM.
