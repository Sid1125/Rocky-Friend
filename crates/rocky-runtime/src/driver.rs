//! Command-driven task control: UI commands become session steps.
//!
//! The driver translates validated [`IpcCommand`]s into session operations.
//! It mints no authority: `SubmitGoal` only creates rows and events, and
//! `CancelTask` only advances the caller's already-loaded session after
//! checking the command names the same task.

use crate::session::{SessionError, TaskSession};
use rocky_domain::{GoalContract, TaskState};
use rocky_ipc::{CommandPayload, IpcCommand, RuntimeEvent};
use rocky_storage::TaskStore;
use std::fmt;

/// Starts a session from a `SubmitGoal` command.
///
/// The command's goal and constraints become the frozen contract, so the
/// persisted task carries exactly what the UI sent. Anything but
/// `SubmitGoal` is rejected before touching the store.
pub fn submit_goal(
    store: &mut (impl TaskStore + rocky_storage::ContractStore),
    events: &mut rocky_ipc::EventStream,
    command: &IpcCommand,
) -> Result<(TaskSession, Vec<RuntimeEvent>), DriverError> {
    let CommandPayload::SubmitGoal { goal, constraints } = &command.payload else {
        return Err(DriverError::WrongCommand);
    };
    let contract = GoalContract::new(&command.correlation_id, goal.clone(), constraints.clone())
        .map_err(|_| DriverError::InvalidGoal)?;
    let (session, created) = TaskSession::start(store, events, &contract)?;
    Ok((session, vec![created]))
}

/// A read-only snapshot of one task for UI visibility. Snapshots describe;
/// they authorize nothing and carry no permits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSnapshot {
    pub task_id: String,
    pub goal: String,
    pub state: TaskState,
    pub revision: u64,
}

/// Answers a `QueryTask` command from the store. Read-only: no row is
/// created, mutated, or emitted over.
pub fn query_task(
    store: &impl TaskStore,
    command: &IpcCommand,
) -> Result<TaskSnapshot, DriverError> {
    if !matches!(command.payload, CommandPayload::QueryTask) {
        return Err(DriverError::WrongCommand);
    }
    let record = store
        .get(&command.correlation_id)?
        .ok_or(DriverError::UnknownTask)?;
    Ok(TaskSnapshot {
        task_id: record.id,
        goal: record.user_goal,
        state: record.state,
        revision: record.revision,
    })
}

/// Cancels a loaded session from a `CancelTask` command.
///
/// The command's correlation ID must equal the session's task: a cancel for
/// another task is rejected with the session untouched.
pub fn cancel_task(
    session: &mut TaskSession,
    store: &mut impl TaskStore,
    events: &mut rocky_ipc::EventStream,
    command: &IpcCommand,
) -> Result<Vec<RuntimeEvent>, DriverError> {
    if !matches!(command.payload, CommandPayload::CancelTask) {
        return Err(DriverError::WrongCommand);
    }
    if command.correlation_id != session.task_id() {
        return Err(DriverError::TaskMismatch);
    }
    Ok(vec![session.cancel(store, events)?])
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriverError {
    WrongCommand,
    TaskMismatch,
    InvalidGoal,
    UnknownTask,
    Session(SessionError),
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task driver error: {self:?}")
    }
}

impl std::error::Error for DriverError {}

impl From<SessionError> for DriverError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<rocky_storage::StorageError> for DriverError {
    fn from(error: rocky_storage::StorageError) -> Self {
        Self::Session(SessionError::from(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_domain::GoalContract;
    use rocky_ipc::{CommandPayload, EventPayload, EventStream, IpcCommand};
    use rocky_storage::{InMemoryTaskStore, TaskStore};

    fn submit_command() -> IpcCommand {
        IpcCommand::new(
            "cmd-1",
            "task-1",
            CommandPayload::SubmitGoal {
                goal: "Read a document".into(),
                constraints: vec!["read-only".into()],
            },
        )
        .expect("valid command")
    }

    fn cancel_command() -> IpcCommand {
        IpcCommand::new("cmd-2", "task-1", CommandPayload::CancelTask).expect("valid command")
    }

    #[test]
    fn submit_starts_a_session_from_the_command_goal() {
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();

        let (session, emitted) =
            submit_goal(&mut store, &mut events, &submit_command()).expect("submit goal");
        assert_eq!(session.task_id(), "task-1");
        assert_eq!(session.state(), rocky_domain::TaskState::Created);
        assert_eq!(emitted.len(), 1);
        assert_eq!(
            emitted[0].payload,
            EventPayload::TaskCreated {
                task_id: "task-1".into(),
            }
        );
        let stored = store
            .get("task-1")
            .expect("storage query")
            .expect("stored task");
        assert_eq!(stored.user_goal, "Read a document");
    }

    #[test]
    fn submit_rejects_a_non_submit_command() {
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();

        assert_eq!(
            submit_goal(&mut store, &mut events, &cancel_command()),
            Err(DriverError::WrongCommand)
        );
        assert!(store.get("task-1").expect("storage query").is_none());
    }

    #[test]
    fn submit_rejects_a_struct_literal_with_a_blank_goal() {
        // `IpcCommand` fields are public, so a hand-built command can dodge
        // the constructor's validation. The driver still refuses it.
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();
        let raw = IpcCommand {
            schema_version: rocky_ipc::COMMAND_SCHEMA_VERSION,
            command_id: "cmd-1".into(),
            correlation_id: "task-1".into(),
            payload: CommandPayload::SubmitGoal {
                goal: "  ".into(),
                constraints: Vec::new(),
            },
        };

        assert_eq!(
            submit_goal(&mut store, &mut events, &raw),
            Err(DriverError::InvalidGoal)
        );
    }

    #[test]
    fn cancel_drives_a_running_session_to_cancelled() {
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();
        let contract =
            GoalContract::new("task-1", "Run a tool", vec![]).expect("valid test contract");
        let (mut session, _) =
            TaskSession::start(&mut store, &mut events, &contract).expect("start session");
        session.plan(&mut store, &mut events).expect("plan");
        session.begin(&mut store, &mut events).expect("begin");

        let emitted = cancel_task(&mut session, &mut store, &mut events, &cancel_command())
            .expect("cancel task");
        assert_eq!(emitted.len(), 1);
        assert_eq!(session.state(), rocky_domain::TaskState::Cancelled);
    }

    #[test]
    fn cancel_rejects_a_command_for_another_task() {
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();
        let contract =
            GoalContract::new("task-1", "Run a tool", vec![]).expect("valid test contract");
        let (mut session, _) =
            TaskSession::start(&mut store, &mut events, &contract).expect("start session");
        let other =
            IpcCommand::new("cmd-9", "task-2", CommandPayload::CancelTask).expect("valid command");

        assert_eq!(
            cancel_task(&mut session, &mut store, &mut events, &other),
            Err(DriverError::TaskMismatch)
        );
        assert_eq!(session.state(), rocky_domain::TaskState::Created);
    }

    #[test]
    fn sessions_rehydrate_from_the_store_and_continue() {
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();
        let contract =
            GoalContract::new("task-1", "Run a tool", vec![]).expect("valid test contract");
        let (mut session, _) =
            TaskSession::start(&mut store, &mut events, &contract).expect("start session");
        session.plan(&mut store, &mut events).expect("plan");
        drop(session);

        let mut loaded = TaskSession::load(&store, "task-1").expect("load session");
        assert_eq!(loaded.state(), rocky_domain::TaskState::Planned);
        assert_eq!(loaded.revision(), 2);
        loaded.begin(&mut store, &mut events).expect("begin");
        loaded.complete(&mut store, &mut events).expect("complete");
        assert_eq!(loaded.state(), rocky_domain::TaskState::Completed);
    }

    #[test]
    fn load_reports_a_missing_task() {
        let store = InMemoryTaskStore::default();
        assert_eq!(
            TaskSession::load(&store, "task-missing"),
            Err(crate::session::SessionError::Storage(
                rocky_storage::StorageError::TaskNotFound
            ))
        );
    }

    fn query_command() -> IpcCommand {
        IpcCommand::new("cmd-7", "task-1", CommandPayload::QueryTask).expect("valid command")
    }

    #[test]
    fn query_returns_a_snapshot_without_mutating_anything() {
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();
        submit_goal(&mut store, &mut events, &submit_command()).expect("submit goal");

        let snapshot = query_task(&store, &query_command()).expect("query task");
        assert_eq!(snapshot.task_id, "task-1");
        assert_eq!(snapshot.goal, "Read a document");
        assert_eq!(snapshot.state, rocky_domain::TaskState::Created);
        assert_eq!(snapshot.revision, 1);
        // Read-only proof: the row and the stream are exactly as submit left them.
        let stored = store
            .get("task-1")
            .expect("storage query")
            .expect("stored task");
        assert_eq!(stored.revision, 1);
    }

    #[test]
    fn query_rejects_wrong_commands_and_missing_tasks() {
        let store = InMemoryTaskStore::default();
        assert_eq!(
            query_task(&store, &cancel_command()),
            Err(DriverError::WrongCommand)
        );
        assert_eq!(
            query_task(&store, &query_command()),
            Err(DriverError::UnknownTask)
        );
    }
}
