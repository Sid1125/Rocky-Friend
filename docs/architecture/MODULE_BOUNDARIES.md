# Module Boundaries

## Proposed Rust workspace

```text
crates/
  rocky-domain/       # pure domain types and state machines
  rocky-policy/       # permissions and risk evaluation
  rocky-runtime/      # agent loop and orchestration
  rocky-agents/       # logical subagent jobs
  rocky-tools/        # tool contracts and broker
  rocky-executors/    # filesystem/process/network adapters
  rocky-models/       # provider abstraction and routing
  rocky-memory/       # SQLite persistence and retrieval
  rocky-resources/    # system metrics and governor
  rocky-audit/        # append-only action records
  rocky-ipc/          # typed protocol
apps/
  desktop/            # Tauri host + frontend
```

## Forbidden dependencies

- Domain must not depend on Tauri.
- Policy must not depend on an LLM provider.
- Tool definitions must not execute OS actions.
- UI must not contain authorization logic.
- Agents must not bypass the tool broker.
- Model providers must not mutate permissions.

## Preferred pattern

Traits/interfaces at boundaries; concrete OS and model adapters at the edge.
