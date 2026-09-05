# ROCKY

**ROCKY is a local-first, resource-aware, permission-gated agentic computing companion.**

> Design goal: a capable technical collaborator, not an unrestricted autonomous butler.

ROCKY can reason about tasks, use explicitly permitted tools, and dynamically create short-lived specialist subagents for parallel work. The system is designed to remain lightweight on a normal laptop.

## Core principles

1. **Local-first**
2. **Least privilege**
3. **Capability-based execution**
4. **Resource-aware concurrency**
5. **Ephemeral subagents**
6. **One model runtime, many logical agents**
7. **Explicit trust boundaries**
8. **Evidence before completion**
9. **Human authority for consequential actions**
10. **Graceful degradation**

## Recommended stack

- Core/runtime: **Rust**
- Desktop shell: **Tauri 2**
- UI: **TypeScript + React + Vite**
- Async runtime: **Tokio**
- Storage: **SQLite**
- IPC: typed local IPC/event protocol
- Local inference: provider abstraction; optional llama.cpp-compatible runtime
- Cloud inference: optional, explicitly configured providers

See `docs/INDEX.md` for the implementation contract.
