//! Versioned, observational events emitted by the runtime to a UI boundary.
//!
//! Event consumers must not treat these records as authorization commands.

use rocky_domain::{MAX_CONSTRAINTS, TaskState};
use std::collections::HashMap;
use std::fmt;

pub const EVENT_SCHEMA_VERSION: u16 = 1;

/// A typed event payload. New variants are additive protocol changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventPayload {
    TaskCreated { task_id: String },
    TaskStateChanged { from: TaskState, to: TaskState },
    AgentSpawned { agent_id: String },
    AgentFinding { finding_id: String },
    ToolRequested { tool_id: String },
    ToolApproved { tool_id: String },
    ToolCompleted { tool_id: String },
    ApprovalRequired { action_id: String },
    ResourceModeChanged { mode: String },
    TaskCompleted,
    TaskFailed { reason: String },
}

/// An immutable, ordered event associated with exactly one task and correlation ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeEvent {
    pub schema_version: u16,
    pub sequence: u64,
    pub correlation_id: String,
    pub payload: EventPayload,
}

impl RuntimeEvent {
    pub fn new(
        sequence: u64,
        correlation_id: impl Into<String>,
        payload: EventPayload,
    ) -> Result<Self, EventError> {
        if sequence == 0 {
            return Err(EventError::ZeroSequence);
        }
        let correlation_id = correlation_id.into();
        if correlation_id.trim().is_empty() {
            return Err(EventError::EmptyCorrelationId);
        }
        Ok(Self {
            schema_version: EVENT_SCHEMA_VERSION,
            sequence,
            correlation_id,
            payload,
        })
    }
}

/// Assigns monotonically increasing event sequences independently for each task.
#[derive(Default)]
pub struct EventStream {
    next_sequence_by_correlation: HashMap<String, u64>,
}

impl EventStream {
    /// Produces a validated, observational event. It has no authorization side effects.
    pub fn emit(
        &mut self,
        correlation_id: impl Into<String>,
        payload: EventPayload,
    ) -> Result<RuntimeEvent, EventError> {
        let correlation_id = correlation_id.into();
        if correlation_id.trim().is_empty() {
            return Err(EventError::EmptyCorrelationId);
        }
        let next_sequence = self
            .next_sequence_by_correlation
            .entry(correlation_id.clone())
            .and_modify(|sequence| *sequence += 1)
            .or_insert(1);
        RuntimeEvent::new(*next_sequence, correlation_id, payload)
    }
}

pub const COMMAND_SCHEMA_VERSION: u16 = 1;

/// Maximum user-goal length in characters. The UI boundary must not deliver
/// unbounded allocations to the core no matter what the frontend sends.
pub const MAX_GOAL_CHARS: usize = 8_192;

/// A typed command from the UI into the runtime. New variants are additive
/// protocol changes.
///
/// Shape validation here is not authorization: a compromised UI sending
/// well-formed commands gains nothing by itself, because the Rust core still
/// runs every request through policy, approvals, and resource admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandPayload {
    SubmitGoal {
        goal: String,
        constraints: Vec<String>,
    },
    ApproveAction {
        action_hash: String,
    },
    DenyAction {
        action_hash: String,
    },
    CancelTask,
    QueryTask,
}

/// A validated command bound to exactly one task via its correlation ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpcCommand {
    pub schema_version: u16,
    pub command_id: String,
    pub correlation_id: String,
    pub payload: CommandPayload,
}

impl IpcCommand {
    pub fn new(
        command_id: impl Into<String>,
        correlation_id: impl Into<String>,
        payload: CommandPayload,
    ) -> Result<Self, CommandError> {
        let command_id = command_id.into();
        if command_id.trim().is_empty() {
            return Err(CommandError::EmptyCommandId);
        }
        let correlation_id = correlation_id.into();
        if correlation_id.trim().is_empty() {
            return Err(CommandError::EmptyCorrelationId);
        }
        payload.validate()?;
        Ok(Self {
            schema_version: COMMAND_SCHEMA_VERSION,
            command_id,
            correlation_id,
            payload,
        })
    }
}

impl CommandPayload {
    fn validate(&self) -> Result<(), CommandError> {
        match self {
            Self::SubmitGoal { goal, constraints } => {
                if goal.trim().is_empty() {
                    return Err(CommandError::EmptyGoal);
                }
                if goal.chars().count() > MAX_GOAL_CHARS {
                    return Err(CommandError::GoalTooLong);
                }
                // Same bounds as the frozen contract so a command the UI
                // accepts can never fail contract construction downstream.
                if constraints.len() > MAX_CONSTRAINTS {
                    return Err(CommandError::TooManyConstraints);
                }
                if constraints.iter().any(|item| item.trim().is_empty()) {
                    return Err(CommandError::EmptyConstraint);
                }
                Ok(())
            }
            Self::ApproveAction { action_hash } | Self::DenyAction { action_hash } => {
                if action_hash.trim().is_empty() {
                    return Err(CommandError::EmptyActionHash);
                }
                Ok(())
            }
            Self::CancelTask | Self::QueryTask => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    EmptyCommandId,
    EmptyCorrelationId,
    EmptyGoal,
    GoalTooLong,
    EmptyConstraint,
    TooManyConstraints,
    EmptyActionHash,
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid ipc command: {self:?}")
    }
}

impl std::error::Error for CommandError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventError {
    ZeroSequence,
    EmptyCorrelationId,
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid runtime event: {self:?}")
    }
}

impl std::error::Error for EventError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_require_a_monotonic_sequence_and_correlation_id() {
        assert_eq!(
            RuntimeEvent::new(0, "task-1", EventPayload::TaskCompleted),
            Err(EventError::ZeroSequence)
        );
        assert_eq!(
            RuntimeEvent::new(1, "", EventPayload::TaskCompleted),
            Err(EventError::EmptyCorrelationId)
        );
    }

    #[test]
    fn events_are_versioned() {
        let event =
            RuntimeEvent::new(1, "task-1", EventPayload::TaskCompleted).expect("valid event");
        assert_eq!(event.schema_version, EVENT_SCHEMA_VERSION);
    }

    #[test]
    fn event_sequence_is_monotonic_per_task() {
        let mut stream = EventStream::default();
        let first = stream
            .emit(
                "task-1",
                EventPayload::TaskCreated {
                    task_id: "task-1".into(),
                },
            )
            .expect("valid event");
        let second = stream
            .emit("task-1", EventPayload::TaskCompleted)
            .expect("valid event");
        let other_task = stream
            .emit("task-2", EventPayload::TaskCompleted)
            .expect("valid event");

        assert_eq!(
            (first.sequence, second.sequence, other_task.sequence),
            (1, 2, 1)
        );
    }

    fn submit_goal_command() -> IpcCommand {
        IpcCommand::new(
            "cmd-1",
            "task-1",
            CommandPayload::SubmitGoal {
                goal: "Summarize this document".into(),
                constraints: vec!["read-only".into()],
            },
        )
        .expect("valid command")
    }

    #[test]
    fn commands_are_versioned_and_bound_to_a_task() {
        let command = submit_goal_command();
        assert_eq!(command.schema_version, COMMAND_SCHEMA_VERSION);
        assert_eq!(command.command_id, "cmd-1");
        assert_eq!(command.correlation_id, "task-1");
    }

    #[test]
    fn commands_reject_blank_ids() {
        let payload = CommandPayload::CancelTask;
        assert_eq!(
            IpcCommand::new("", "task-1", payload.clone()),
            Err(CommandError::EmptyCommandId)
        );
        assert_eq!(
            IpcCommand::new("cmd-1", "  ", payload),
            Err(CommandError::EmptyCorrelationId)
        );
    }

    #[test]
    fn goals_must_be_nonempty_and_bounded() {
        assert_eq!(
            IpcCommand::new(
                "cmd-1",
                "task-1",
                CommandPayload::SubmitGoal {
                    goal: "  ".into(),
                    constraints: Vec::new(),
                }
            ),
            Err(CommandError::EmptyGoal)
        );
        assert_eq!(
            IpcCommand::new(
                "cmd-1",
                "task-1",
                CommandPayload::SubmitGoal {
                    goal: "x".repeat(MAX_GOAL_CHARS + 1),
                    constraints: Vec::new(),
                }
            ),
            Err(CommandError::GoalTooLong)
        );
    }

    #[test]
    fn submit_constraints_match_contract_bounds() {
        assert_eq!(
            IpcCommand::new(
                "cmd-1",
                "task-1",
                CommandPayload::SubmitGoal {
                    goal: "goal".into(),
                    constraints: vec!["  ".into()],
                }
            ),
            Err(CommandError::EmptyConstraint)
        );
        assert_eq!(
            IpcCommand::new(
                "cmd-1",
                "task-1",
                CommandPayload::SubmitGoal {
                    goal: "goal".into(),
                    constraints: vec!["c".to_string(); MAX_CONSTRAINTS + 1],
                }
            ),
            Err(CommandError::TooManyConstraints)
        );
    }

    #[test]
    fn approval_decisions_bind_to_an_action_hash() {
        assert_eq!(
            IpcCommand::new(
                "cmd-1",
                "task-1",
                CommandPayload::ApproveAction {
                    action_hash: "   ".into(),
                }
            ),
            Err(CommandError::EmptyActionHash)
        );
        let command = IpcCommand::new(
            "cmd-1",
            "task-1",
            CommandPayload::ApproveAction {
                action_hash: "abc123".into(),
            },
        )
        .expect("valid command");
        assert_eq!(
            command.payload,
            CommandPayload::ApproveAction {
                action_hash: "abc123".into(),
            }
        );
    }
}
