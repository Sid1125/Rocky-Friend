# Plan: Voice integration (Wispr Flow optional) — implementation later

Status: **PLAN ONLY — no code changed.** Verified 2026-09-05 against
`api-docs.wisprflow.ai` (WebSocket + REST exist, client-side JWT auth
pattern confirmed, 16kHz int16 PCM streaming protocol confirmed).
Claim NOT verified: exclusive-access/organization-approval availability —
confirm terms when scheduling Phase 2.

## Proposal (as received)

Wispr Flow (`wisprflow.ai`) as an **optional** cloud voice provider for
ROCKY's "talk and shit happens" experience: natural speech → cleaned
command transcript → goal interpretation → secure runtime → spoken result.

- WebSocket streaming (not record-upload-wait); partials drive the
  LISTENING animation, endpoint detection drives THINKING.
- Tiered: local wake word + local VAD always; local STT default and
  required; Wispr Flow optional cloud tier, explicitly enabled, never
  a dependency.
- API key architecture: org key stays in the Rust backend / OS secure
  storage, client JWTs minted per session; nothing secret in the
  frontend, bundle, repo, or casual IPC.
- Voice phases: provider contract → local voice → Wispr provider →
  voice-state animation → conversation UX.
- Wake word NEVER goes to the cloud (no 24/7 microphone streaming).
- Spoken approval maps into the deterministic approval system; voice is
  input, not authorization bypass.

## Review (verified against the tree)

1. **Provider shape matches house style** (`ModelProvider` precedent):
   `VoiceProvider` / `VoiceSession` / `TranscriptEvent` / `VoiceError`.
   But do NOT start a `rocky-voice/` crate: voice input arrives like any
   other UI input, so the contract starts as types alongside the IPC
   boundary (`rocky-ipc`), graduating to a crate only when a second
   provider implementation lands. Protocols before providers.
2. **Sync WebSocket, not async.** The provider trait is synchronous by
   design (same reason `ureq` beat `reqwest`). If/when streaming lands,
   the narrow dependency is `tungstenite` (blocking WebSocket), never an
   async runtime smuggled in for one feature.
3. **Secret storage already exists.** `KeyringSecretStore` + the
   approve/deny decision pattern is exactly where the Wispr credential
   and the `cloud_voice_enabled` flag belong. Config follows the strict
   `[voice] provider = "local"` / `cloud_voice_enabled = false` default
   pattern; unknown keys rejected like every other section.
4. **Transcript cleanup is an intent transform — treat it as one.**
   Wispr normalizing "why the damn build is broken again" into "why the
   build is failing" is wonderful UX and a real risk surface: the FINAL
   transcript is what becomes the goal text, and it must stay visible
   (task snapshots already show it verbatim) with consequential actions
   still confirming. Never act on partials; partials animate only.
5. **Wake-word economics favor determinism.** A wake-word detector is
   kilobytes; the K2 reflex-tier rule applies unchanged — no 0.9B-class
   model for wake-word without profiling justification.
6. **Listening/speaking states are frontend-owned** (per the living
   interface review): the core never observes microphone state. The
   transcript stream feeds presence events; the core sees only the final
   `SubmitGoal`.
7. Availability risk stands: if access terms block us, nothing is lost —
   Tier 1 local is the requirement, Wispr the option. Re-check terms at
   scheduling time; do not design around assumed access.

## Non-goals for the voice work

- No cloud-by-default, no mic streaming to any LLM, no approval logic in
  TypeScript, no 24/7 inference reintroduced through the frontend.
