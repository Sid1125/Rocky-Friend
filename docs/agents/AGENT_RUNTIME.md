# Agent Runtime and Mini-ROCKYs

## Core concept

A Mini-ROCKY is a **logical, ephemeral worker**, not a second persistent assistant process.

```text
Mini-ROCKY =
  goal
+ narrow context
+ role prompt
+ limited capability set
+ token/step budget
+ deadline
+ evidence requirements
```

## Spawn policy

Subagents may be spawned only when:
- work can be meaningfully parallelized;
- dependencies are understood;
- resource governor permits it;
- expected benefit exceeds coordination cost.

## Hard limits

Initial defaults:
- max active subagents: 3
- max nesting depth: 1
- max steps per worker: configurable, finite
- mandatory deadline
- mandatory cancellation token
- no worker may spawn another worker without scheduler approval

## Worker lifecycle

`Created -> Queued -> Running -> Waiting -> Completed | Failed | Cancelled | TimedOut`

Workers are destroyed after results are normalized and relevant findings are promoted.

## Context discipline

Never copy the entire conversation by default.

Each worker receives:
- task-specific goal
- relevant artifacts
- explicit constraints
- allowed tools
- bounded memory excerpts

## Shared state

Workers write structured findings to a task blackboard. The blackboard is not unrestricted shared mutable memory.

Finding schema:
- hypothesis
- evidence
- confidence
- affected artifacts
- recommended next action

## Model sharing

Logical concurrency must not imply multiple local model copies.

The model provider owns inference concurrency. The scheduler must account for:
- provider queue depth
- GPU/CPU pressure
- context size
- expected latency

If local inference serializes efficiently, multiple workers may remain logically concurrent while inference is queued.
