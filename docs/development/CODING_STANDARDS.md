# Coding Standards

## Rust

- `cargo fmt`
- `cargo clippy -- -D warnings` where practical
- no `unwrap()` in recoverable runtime paths
- errors must preserve actionable context
- async functions must not block the Tokio runtime
- blocking OS work goes to appropriate blocking boundaries

## Architecture

Before adding a dependency, ask:
1. Can the standard library do this?
2. Does an existing crate already own this concern?
3. What is the memory/startup/security cost?

## Security-sensitive code

Requires:
- explicit tests
- negative tests
- audit logging where consequential
- documented invariants

## LLM code

Do not encode authorization decisions purely in prompts.

Prompts may guide reasoning. Code enforces policy.
