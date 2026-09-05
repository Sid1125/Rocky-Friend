# Architecture

## High-level design

```text
                 ┌─────────────────────┐
                 │       Desktop UI    │
                 │ Tauri + React/TS    │
                 └──────────┬──────────┘
                            │ typed IPC/events
                 ┌──────────▼──────────┐
                 │    Desktop Boundary │
                 │ capabilities only   │
                 └──────────┬──────────┘
                            │
       ┌────────────────────▼────────────────────┐
       │              ROCKY CORE                 │
       │                                        │
       │ Goal Manager → Planner → Scheduler     │
       │                    │                   │
       │              Agent Runtime             │
       │                    │                   │
       │       Policy / Resource Governor       │
       └───────────────┬───────────────┬────────┘
                       │               │
                ┌──────▼─────┐   ┌────▼─────────┐
                │ Tool Broker │   │ Model Router │
                └──────┬─────┘   └────┬─────────┘
                       │               │
             ┌─────────▼──────┐   ┌───▼────────────┐
             │ OS / sandboxed │   │ Local / cloud   │
             │ executors      │   │ model providers │
             └────────────────┘   └────────────────┘
```

## Process model

### MVP
Use one primary Rust process for the runtime and Tauri integration. Avoid microservices, external brokers, Kubernetes, Redis, or separate databases.

### Later
A privileged or crash-isolated execution sidecar may be introduced only when justified by isolation requirements.

## Why Rust

Rust is the default implementation language for:
- orchestration
- policy enforcement
- process management
- resource monitoring
- filesystem boundaries
- IPC
- tool execution

The goal is low baseline memory, predictable concurrency, and strong ownership boundaries.

## UI boundary

The frontend is presentation and user interaction. It does not receive arbitrary filesystem or shell authority.

All UI requests are converted into typed commands and validated by the Rust boundary.

## Data flow

1. User submits goal.
2. Goal contract freezes scope and constraints.
3. Planner produces candidate steps.
4. Scheduler checks resource budget.
5. Policy engine evaluates requested capabilities.
6. Tool broker validates schema and scope.
7. Executor performs action.
8. Evidence is collected.
9. Runtime updates task state.
10. User receives streaming events.

## Dependency direction

`ui -> application commands -> runtime -> domain/policy -> adapters`

Lower layers must never import UI code.
