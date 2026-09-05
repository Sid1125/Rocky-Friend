# Resource Governor

## Objective

ROCKY must adapt to the laptop instead of assuming dedicated hardware.

## Inputs

- CPU utilization
- available RAM
- process RSS
- GPU utilization/memory where available
- battery state
- thermal signals where available
- foreground application pressure
- model-provider queue depth

## Modes

### Idle
No inference. No active worker loop. Event-driven only.

### Normal
Default bounded concurrency.

### Constrained
Reduce worker count, context sizes, polling frequency, and background work.

### Critical
Stop spawning work, cancel low-priority tasks, release caches where safe.

## Initial acceptance targets

These are engineering targets, not guarantees across every machine:

- idle CPU: effectively near zero except event wakeups
- no continuous inference while idle
- bounded memory growth
- worker count dynamically capped
- cancellation must propagate quickly
- resource sampling must be inexpensive

## Scheduling rule

Estimate:

`priority × expected_value / estimated_cost`

and admit work only if global budgets permit.

## Backpressure

When overloaded:
1. do not spawn more workers;
2. queue low-priority work;
3. reduce parallelism;
4. reduce context;
5. route to cheaper/smaller provider if quality policy permits;
6. ask user before expensive escalation.

Never solve overload by recursively spawning more agents.
