# Event Protocol

The runtime emits typed events to the UI.

## Event categories

- `task.created`
- `task.state_changed`
- `agent.spawned`
- `agent.finding`
- `tool.requested`
- `tool.approved`
- `tool.completed`
- `approval.required`
- `resource.mode_changed`
- `task.completed`
- `task.failed`

## Requirements

- monotonically ordered per task
- correlation ID on every event
- payload schemas versioned
- UI must tolerate unknown event fields
- event streams are observational, not authorization channels
