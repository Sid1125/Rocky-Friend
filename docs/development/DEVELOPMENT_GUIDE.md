# Development Guide

## Recommended prerequisites

- current stable Rust toolchain
- Node.js LTS
- Tauri 2 prerequisites for the target OS
- SQLite tooling optional

## Commands

The exact commands may evolve, but the repository should expose:

```text
cargo fmt
cargo clippy
cargo test
npm run lint
npm run test
npm run build
```

## Development workflow

1. Read relevant architecture/security docs.
2. Define the invariant being changed.
3. Implement smallest viable change.
4. Add tests.
5. Run formatting/lint/tests.
6. Update docs if contracts changed.

## Golden rule

A convenience shortcut must not bypass:
- policy;
- permissions;
- approval;
- audit;
- resource governance.
