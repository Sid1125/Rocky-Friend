# Plan: Web intelligence (Scrapling sidecar) — implementation later

Status: **PLAN ONLY — no code changed.** Verified 2026-09-05: Scrapling
is real (D4Vinci, Python, adaptive selectors + MCP server + prompt-
injection stripping all documented in its own docs). Stealth/Cloudflare-
bypass claims are vendor claims — treat like launch benchmarks (see the
K2 lesson), not facts. Verdict below stands regardless: **not yet**.

## Proposal (as received)

Scrapling as ROCKY's elite web-research capability behind a web
capability ladder (no-network → Rust HTTP → structured web → Scrapling
fetch → dynamic browser → crawl fleet), always starting at the lowest
sufficient level, with Mini-ROCKYs fanning research across sites.

## Review (verified against the tree)

### Agreement (load-bearing parts)

1. **Sidecar, never embedded.** Python + Chromium inside the Rust core
   would torch the lightweight/security-critical properties. Strict
   localhost boundary; crashes, leaks, and hangs stay on the far side.
2. **Typed tools only** (`web.fetch`, `web.extract`, `web.search_site`,
   `web.research`, `web.browser`), each with URL/domain scope, timeout,
   byte/page/concurrency limits, cancellation, and evidence capture.
   Never a raw `execute_anything`.
3. **SSRF protection is mandatory and enumerated**: localhost,
   loopback, link-local (169.254.169.54-style metadata endpoints),
   private ranges, `file://`, non-http(s) schemes — validated before
   the sidecar ever sees a URL, or the LLM gains an internal-network
   reconnaissance tool. Note the gap this exposes: `NetworkConnect`
   exists as a capability kind but has **no executor and no URL-scope
   format yet**; both are prerequisites, owned by this plan, not assumed.
4. **One browser runtime shared by all web workers**, mirroring the
   one-model-runtime rule. `BrowserPool(max 1)` with hard timeout and
   kill-on-cancel.
5. **Sanitization as a layer, never proof.** Sidecar stripping plus our
   pipeline (normalize → injection scan → context budget → untrusted
   data → LLM → policy → permit → approval → executor). Our adversarial
   suite pattern extends with web-injection fixtures when this lands.

### Corrections and additions

6. **No new process management needed.** The existing
   `AllowlistedProcessExecutor` (allowlist + argv-only + deadline +
   kill + cancellation) *is* the sidecar supervisor: spawn
   `python service.py`, supervise, kill on timeout/cancel. One open
   question for scheduling time, not now: stdio vs loopback framing
   for the sidecar protocol.
7. **No MCP protocol.** The sidecar speaks OUR minimal versioned typed
   JSON, not MCP. MCP servers are themselves an attack surface (tool
   descriptions arriving over the network are untrusted input), and our
   broker already does typed tools. Adopt the capability, never the
   protocol.
8. **No new Rust crate prematurely.** Contracts first (request/response
   types beside existing protocol types), sidecar second, crate only if
   a second web backend ever exists. Same rule as voice.
9. **Level 1 needs no new dependency.** `ureq` is already in the tree
   (models crate) — the bounded Rust fetch tool reuses it.
10. **Adaptive-selector state must be visible.** Scrapling persists
    element fingerprints in its own SQLite; ROCKY must record
    extraction targets (selector + identifier + domain) as findings
    with evidence refs, so adaptation state is inspectable instead of
    hidden inside the sidecar. A relocated selector that silently
    changes meaning is a correctness bug with security-adjacent
    consequences — re-validate narrowed content like any other
    untrusted input.
11. **Evidence path already exists.** Web excerpts enter through the
    evidence store (bytes in, digest out) and surface via findings.
    Nothing new to build there.
12. **ToS note (one line, not legal advice):** anti-bot bypass features
    exist for sites the user explicitly tasks; document that bypassing
    access controls is the user's call on their own behalf.

### Sequencing (unchanged from proposal, sharpened)

Desktop Rocky + voice + real agent + existing secure tools working
end-to-end FIRST. Web intelligence second, starting at ladder levels
0–2 (pure Rust, no sidecar), sidecar only when a vertical slice needs
dynamic content, browser/crawl levels only when research-fleet work
demands them. Each level independently gated, each with kill switches
and a complete off state.

### Prerequisites checklist (for scheduling day)

- [ ] `NetworkConnect` URL-scope format + SSRF validator (policy layer)
- [ ] Bounded Rust fetch tool on `ureq` (levels 0–2, no sidecar)
- [ ] Sidecar protocol spec (typed JSON, versioned, ours)
- [ ] Supervisor wiring via `AllowlistedProcessExecutor`
- [ ] Sanitization pipeline + web-injection fixtures in adversarial suite
- [ ] Extraction-target findings convention (selectors as evidence)
- [ ] Kill switches + resource fence per level
