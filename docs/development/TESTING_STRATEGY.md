# Testing Strategy

## Required layers

### Unit
Domain logic, policies, state machines.

### Integration
Tool broker + policy + executor.

### Adversarial
Prompt injection, path traversal, malformed tool calls, scope confusion.

### Resource
Cancellation, queue saturation, worker limits, memory growth.

### End-to-end
User goal → planning → approval → execution → evidence.

## Must-have security tests

- denied path cannot be read via traversal
- revoked permission stops future action
- untrusted content cannot grant authority
- arbitrary shell is unavailable without explicit permission
- worker cannot exceed spawn depth
- timeout cancels work
