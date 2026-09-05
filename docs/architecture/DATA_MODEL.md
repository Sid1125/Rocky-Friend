# Data Model

SQLite is the default embedded store.

## Canonical entities

### Task
- id
- user_goal
- goal_contract
- state
- created_at
- updated_at

### AgentRun
- id
- task_id
- parent_id
- role
- budget
- state

### Finding
- id
- task_id
- source_agent
- hypothesis
- evidence_ref
- confidence

### Approval
- id
- action_hash
- capability
- decision
- expires_at

### AuditEvent
- id
- timestamp
- task_id
- actor
- action
- policy_decision
- evidence_ref

## Storage rules

- SQLite is authoritative for runtime metadata.
- Large artifacts should be stored outside the DB with references.
- Sensitive values require dedicated secure storage, not plain SQLite.
- Writes must be transactional.
