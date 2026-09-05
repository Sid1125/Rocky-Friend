//! Mini-ROCKY orchestration: spawning workers and publishing their work.
//!
//! The orchestrator owns no policy and mints no authority. It admits
//! workers through the scheduler, persists their findings through the
//! store, and forwards observational UI events through the stream —
//! composition of existing guards, not a new one.

use rocky_agents::{AgentScheduler, SpecialistRole, Worker, spawn_specialist};
use rocky_domain::TaskState;
use rocky_ipc::{EventError, EventPayload, EventStream, RuntimeEvent};
use rocky_storage::{FindingStore, StorageError, TaskStore};
use std::fmt;

/// Spawns a specialist mini-ROCKY and reports it. Admission refusal returns
/// before anything is constructed or emitted, so a refused spawn leaves the
/// event stream untouched.
#[allow(clippy::too_many_arguments)]
pub fn spawn_mini(
    scheduler: AgentScheduler,
    active_workers: usize,
    worker_id: &str,
    parent_task_id: &str,
    role: &SpecialistRole,
    depth: u8,
    deadline_ms: u64,
    stream: &mut EventStream,
) -> Result<(Worker, RuntimeEvent), OrchestratorError> {
    let worker = spawn_specialist(
        scheduler,
        active_workers,
        worker_id,
        parent_task_id,
        role,
        depth,
        deadline_ms,
    )?;
    let event = stream.emit(
        parent_task_id,
        EventPayload::AgentSpawned {
            agent_id: worker.id().into(),
        },
    )?;
    Ok((worker, event))
}

/// Spawns only for a live parent task. Ghost tasks (no row) and finished
/// tasks (terminal state) refuse before admission, construction, or
/// emission, so no worker can ever belong to work that is over — or never
/// was. Active states are exactly the task machine's non-terminal ones.
#[allow(clippy::too_many_arguments)]
pub fn spawn_checked(
    scheduler: AgentScheduler,
    active_workers: usize,
    worker_id: &str,
    parent_task_id: &str,
    role: &SpecialistRole,
    depth: u8,
    deadline_ms: u64,
    store: &impl TaskStore,
    stream: &mut EventStream,
) -> Result<(Worker, RuntimeEvent), OrchestratorError> {
    let record = store
        .get(parent_task_id)?
        .ok_or(StorageError::TaskNotFound)?;
    match record.state {
        TaskState::Created
        | TaskState::Planned
        | TaskState::Running
        | TaskState::WaitingForApproval => {}
        TaskState::Completed | TaskState::Failed | TaskState::Cancelled => {
            return Err(OrchestratorError::TaskNotActive);
        }
    }
    spawn_mini(
        scheduler,
        active_workers,
        worker_id,
        parent_task_id,
        role,
        depth,
        deadline_ms,
        stream,
    )
}

/// Persists a board's fresh findings and reports each one. Re-publishing is
/// quiet: already-stored findings are skipped by ID with no new events.
pub fn publish_board(
    store: &mut impl FindingStore,
    board: &rocky_agents::FindingBoard,
    stream: &mut EventStream,
) -> Result<Vec<RuntimeEvent>, OrchestratorError> {
    let fresh = rocky_runtime::boards::persist_board(store, board)?;
    let mut events = Vec::with_capacity(fresh.len());
    for finding_id in fresh {
        events.push(stream.emit(board.task_id(), EventPayload::AgentFinding { finding_id })?);
    }
    Ok(events)
}

/// Forwards step-run payloads to the stream under one task correlation.
pub fn emit_all(
    stream: &mut EventStream,
    task_id: &str,
    payloads: Vec<EventPayload>,
) -> Result<Vec<RuntimeEvent>, OrchestratorError> {
    let mut events = Vec::with_capacity(payloads.len());
    for payload in payloads {
        events.push(stream.emit(task_id, payload)?);
    }
    Ok(events)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrchestratorError {
    Spawn(rocky_agents::SpawnWorkerError),
    Storage(StorageError),
    Event(EventError),
    TaskNotActive,
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "orchestrator error: {self:?}")
    }
}

impl std::error::Error for OrchestratorError {}

impl From<rocky_agents::SpawnWorkerError> for OrchestratorError {
    fn from(error: rocky_agents::SpawnWorkerError) -> Self {
        Self::Spawn(error)
    }
}

impl From<StorageError> for OrchestratorError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<EventError> for OrchestratorError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_agents::{AgentLimits, AgentScheduler, Finding, FindingBoard, SpecialistRole};
    use rocky_domain::CapabilityKind;
    use rocky_ipc::{EventPayload, EventStream};
    use rocky_storage::{FindingStore, InMemoryTaskStore, TaskStore};

    fn scheduler() -> AgentScheduler {
        AgentScheduler::new(AgentLimits {
            max_active: 3,
            max_depth: 1,
            max_steps: 10,
        })
    }

    fn scout() -> SpecialistRole {
        SpecialistRole::new(
            "scout",
            "Reads files and reports",
            vec![CapabilityKind::FilesystemRead],
            5,
        )
        .expect("valid test role")
    }

    fn board() -> FindingBoard {
        let mut board = FindingBoard::new("task-1", 8).expect("valid test board");
        board
            .post(
                Finding::new(
                    "f-1",
                    "task-1",
                    "scout",
                    "ports pinned",
                    "e1",
                    80,
                    vec![],
                    "x",
                )
                .expect("valid test finding"),
            )
            .expect("post finding");
        board
            .post(
                Finding::new("f-2", "task-1", "scout", "deps old", "e2", 60, vec![], "y")
                    .expect("valid test finding"),
            )
            .expect("post finding");
        board
    }

    #[test]
    fn spawn_mini_emits_agent_spawned() {
        let mut stream = EventStream::default();
        let (worker, event) = spawn_mini(
            scheduler(),
            0,
            "w-1",
            "task-1",
            &scout(),
            1,
            1000,
            &mut stream,
        )
        .expect("spawn mini");

        assert_eq!(worker.id(), "w-1");
        assert_eq!(worker.parent_task_id(), "task-1");
        assert_eq!(
            event.payload,
            EventPayload::AgentSpawned {
                agent_id: "w-1".into(),
            }
        );
        assert_eq!(event.correlation_id, "task-1");
    }

    #[test]
    fn spawn_mini_refusal_emits_nothing() {
        let mut stream = EventStream::default();
        assert!(
            spawn_mini(
                scheduler(),
                3,
                "w-9",
                "task-1",
                &scout(),
                1,
                1000,
                &mut stream
            )
            .is_err()
        );
        // The refusal emitted nothing: the next event keeps sequence 1.
        let event = stream
            .emit("task-1", EventPayload::TaskCompleted)
            .expect("emit event");
        assert_eq!(event.sequence, 1);
    }

    #[test]
    fn publish_board_persists_and_reports_findings() {
        let mut store = InMemoryTaskStore::default();
        let mut stream = EventStream::default();

        let events = publish_board(&mut store, &board(), &mut stream).expect("publish board");
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].payload,
            EventPayload::AgentFinding {
                finding_id: "f-1".into(),
            }
        );
        assert_eq!(events[0].correlation_id, "task-1");
        assert_eq!(
            store.findings_for_task("task-1").expect("task query").len(),
            2
        );

        // Re-publishing is quiet: nothing new persisted, nothing emitted.
        let encore = publish_board(&mut store, &board(), &mut stream).expect("republish");
        assert!(encore.is_empty());
    }

    #[test]
    fn emit_all_forwards_payloads_in_order() {
        let mut stream = EventStream::default();
        let events = emit_all(
            &mut stream,
            "task-1",
            vec![
                EventPayload::ToolRequested {
                    tool_id: "a.read".into(),
                },
                EventPayload::ToolCompleted {
                    tool_id: "a.read".into(),
                },
            ],
        )
        .expect("emit events");

        assert_eq!(events.len(), 2);
        assert_eq!((events[0].sequence, events[1].sequence), (1, 2));
        assert_eq!(events[0].correlation_id, "task-1");
    }

    fn live_store() -> InMemoryTaskStore {
        let mut store = InMemoryTaskStore::default();
        store
            .create(
                rocky_storage::TaskRecord::new("task-1", "Map the repo").expect("valid test task"),
            )
            .expect("create task");
        store
    }

    #[test]
    fn spawn_checked_refuses_ghost_and_finished_tasks() {
        // Ghost task: no row, no worker, no event.
        let ghost = InMemoryTaskStore::default();
        let mut stream = EventStream::default();
        assert_eq!(
            spawn_checked(
                scheduler(),
                0,
                "w-1",
                "task-ghost",
                &scout(),
                1,
                1000,
                &ghost,
                &mut stream
            ),
            Err(OrchestratorError::Storage(
                rocky_storage::StorageError::TaskNotFound
            ))
        );

        // Finished task: the row exists but the work is over.
        let mut done = live_store();
        done.transition("task-1", rocky_domain::TaskState::Planned)
            .expect("plan task");
        done.transition("task-1", rocky_domain::TaskState::Running)
            .expect("begin task");
        done.transition("task-1", rocky_domain::TaskState::Completed)
            .expect("complete task");
        assert_eq!(
            spawn_checked(
                scheduler(),
                0,
                "w-1",
                "task-1",
                &scout(),
                1,
                1000,
                &done,
                &mut stream
            ),
            Err(OrchestratorError::TaskNotActive)
        );

        // Neither refusal emitted anything.
        let event = stream
            .emit("task-1", EventPayload::TaskCompleted)
            .expect("emit event");
        assert_eq!(event.sequence, 1);
    }

    #[test]
    fn spawn_checked_admits_live_tasks() {
        let live = live_store();
        let mut stream = EventStream::default();
        let (worker, event) = spawn_checked(
            scheduler(),
            0,
            "w-1",
            "task-1",
            &scout(),
            1,
            1000,
            &live,
            &mut stream,
        )
        .expect("spawn checked");

        assert_eq!(worker.parent_task_id(), "task-1");
        assert_eq!(
            event.payload,
            EventPayload::AgentSpawned {
                agent_id: "w-1".into(),
            }
        );
    }
}
