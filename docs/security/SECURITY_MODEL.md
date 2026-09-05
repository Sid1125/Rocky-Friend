# Security Model

## Security philosophy

The LLM is an untrusted decision-support component.

It may suggest actions. It does not possess ambient machine authority.

## Enforcement pipeline

```text
Model intent
   ↓
Schema validation
   ↓
Goal/scope validation
   ↓
Permission evaluation
   ↓
Risk classification
   ↓
Resource admission
   ↓
User approval if required
   ↓
Executor sandbox
   ↓
Action
   ↓
Evidence + audit
```

## Trust boundaries

1. User
2. Desktop WebView/UI
3. Core runtime
4. Model provider
5. Tool broker
6. OS executor
7. Untrusted external content

Data crossing a boundary must be validated and minimally scoped.

## Secure defaults

- deny-by-default permissions
- localhost-only internal communication
- no arbitrary shell by default
- no admin elevation
- no secrets in prompts/logs
- explicit cloud provider opt-in
- audit consequential actions
- confirmation for high-impact actions

## Important principle

Tauri capabilities constrain exposed frontend interfaces, but Rust core code is still trusted application code. Therefore core policy enforcement is mandatory and cannot rely solely on UI capability configuration.
