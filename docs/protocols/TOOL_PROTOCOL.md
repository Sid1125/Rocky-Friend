# Tool Protocol

## Rule

Tools are typed contracts. They are not arbitrary functions exposed directly to the model.

## Tool definition

Every tool declares:
- identifier
- input schema
- output schema
- required capabilities
- risk level
- timeout
- cancellation support
- evidence strategy

## Example

```json
{
  "id": "filesystem.read",
  "input": {"path": "relative or scoped path"},
  "required_capability": "filesystem.read",
  "risk": "A0"
}
```

## Execution contract

The model requests a tool.

The runtime:
1. validates JSON/schema;
2. resolves policy;
3. canonicalizes scope;
4. obtains approval if needed;
5. executes;
6. sanitizes result;
7. stores evidence;
8. returns typed output.

## Tool design requirements

- deterministic where possible
- idempotent where practical
- bounded output
- explicit timeout
- cancellation-aware
- no hidden privilege escalation
