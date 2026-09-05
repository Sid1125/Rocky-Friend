# Tauri readiness review (2026-09-05)

Question: is the Rust authorization boundary complete enough that Tauri
command adapters would be thin validation shells rather than new authority?

Verdict: **yes for task, approval, and tool flows; two gaps remain for
agent-activity and resource-status panels** (listed below, both with owners).

## Command coverage: complete

Every `CommandPayload` variant has exactly one core handler, and every
handler was verified by tests, not by reading:

| Command | Handler | Authority minted? |
| ------- | ------- | ----------------- |
| `SubmitGoal` | `driver::submit_goal` | No (row + event only) |
| `CancelTask` | `driver::cancel_task` | No (own-task check first) |
| `QueryTask` | `driver::query_task` | No (read-only, proven) |
| `ApproveAction` | `decisions::approve_command_decision`, `approve_standing_decision` | No (record still faces gate checks) |
| `DenyAction` | `decisions::deny_command_decision` | No (revoke or quiet no) |

A Tauri adapter for any of these validates shape (already done by
`IpcCommand::new`), calls the handler, and forwards returned events.
There is nothing left to authorize in the adapter layer, which is exactly
the point: a compromised WebView sending well-formed commands gains no
authority the core did not already grant through policy.

## Event coverage: tool path complete, two gaps

| Event | Producer | Status |
| ----- | -------- | ------ |
| `task.created` | `session::start` | ✅ |
| `task.state_changed` | `session` transitions | ✅ |
| `task.completed` | `session::complete` | ✅ |
| `task.failed` | `session::fail` | ✅ |
| `tool.requested` / `tool.approved` / `tool.completed` | `StepRun::events` | ✅ (payloads; orchestrator emits via stream) |
| `approval.required` | `StepRun::events` (exact action hash) | ✅ |
| `agent.spawned` / `agent.finding` | nobody yet | ❌ Gap 1 |
| `resource.mode_changed` | nobody yet | ❌ Gap 2 |

**Gap 1 — agent activity events.** Worker spawn sites (`spawn`,
`spawn_specialist`) and board persistence (`persist_board`) do not emit.
They need an `EventStream` at the call site, which only an orchestrator
owning the stream can provide. Required before the agent-activity panel;
blocked on the orchestrator slice, not on Tauri.

**Gap 2 — resource status events.** No sampler exists (stdlib provides no
OS metrics; adding a dependency is deferred by explicit decision), so
nothing can observe mode changes. Required before the resource-status
panel; blocked on the sampler decision, not on Tauri.

## Decision

- **Green-light:** Tauri adapters for the five commands plus event
  forwarding for the eight covered events. Estimated shape: argument
  validation → core handler call → return events; no policy logic in
  TypeScript, ever.
- **Explicitly out of scope for the first adapter cut:** agent-activity
  and resource-status panels (gaps 1–2 above), approval UI beyond
  approve/deny forwarding (standing-trust UX needs product thought).
- **Invariant the adapters must preserve:** the frontend remains
  presentation-only. Any authorization logic found in TypeScript during
  review is a defect, not a shortcut.
