//! Task lifecycle sessions: every state change is persisted and emitted.
//!
//! A session binds one task ID to a store and an event stream so no
//! transition can happen without leaving both a storage revision and a UI
//! event behind. Persistence runs first because SQLite is authoritative;
//! event emission follows and is infallible for validated IDs.

use rocky_domain::{GoalContract, TaskState};
use rocky_ipc::{EventError, EventPayload, EventStream, RuntimeEvent};
use rocky_storage::{ContractStore, StorageError, TaskRecord, TaskStore};
use std::fmt;

/// One task's lifecycle, pinned to its persisted record.
///
/// The session mirrors the stored state after every successful step and
/// carries the frozen contract, so the goal and constraints that authorized
/// the work travel with it. All methods take the store and stream per call
/// so the caller keeps ownership of both and sessions never hold database
/// borrows across awaits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSession {
    task_id: String,
    state: TaskState,
    revision: u64,
    contract: GoalContract,
}

impl TaskSession {
    /// Creates the task row from a frozen goal contract and emits `TaskCreated`.
    ///
    /// Taking the contract instead of loose strings keeps the persisted goal
    /// identical to the frozen one by construction: there is no second goal
    /// value that could drift. The contract itself is persisted alongside
    /// the row so rehydrated sessions see the same freeze.
    pub fn start(
        store: &mut (impl TaskStore + ContractStore),
        events: &mut EventStream,
        contract: &GoalContract,
    ) -> Result<(Self, RuntimeEvent), SessionError> {
        let record = TaskRecord::new(contract.task_id(), contract.goal())?;
        store.create(record)?;
        store.save_contract(contract)?;
        let session = Self {
            task_id: contract.task_id().into(),
            state: TaskState::Created,
            revision: 1,
            contract: contract.clone(),
        };
        let event = events.emit(
            &session.task_id,
            EventPayload::TaskCreated {
                task_id: session.task_id.clone(),
            },
        )?;
        Ok((session, event))
    }

    pub fn plan(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
    ) -> Result<RuntimeEvent, SessionError> {
        self.advance(store, events, TaskState::Planned)
    }

    pub fn begin(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
    ) -> Result<RuntimeEvent, SessionError> {
        self.advance(store, events, TaskState::Running)
    }

    pub fn hold_for_approval(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
    ) -> Result<RuntimeEvent, SessionError> {
        self.advance(store, events, TaskState::WaitingForApproval)
    }

    pub fn resume(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
    ) -> Result<RuntimeEvent, SessionError> {
        self.advance(store, events, TaskState::Running)
    }

    pub fn complete(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
    ) -> Result<RuntimeEvent, SessionError> {
        self.persist(store, TaskState::Completed)?;
        Ok(events.emit(&self.task_id, EventPayload::TaskCompleted)?)
    }

    /// Fails the task with a mandatory reason. Evidence-based completion
    /// requires knowing why work stopped, so blank reasons are rejected
    /// before anything is persisted.
    pub fn fail(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
        reason: &str,
    ) -> Result<RuntimeEvent, SessionError> {
        if reason.trim().is_empty() {
            return Err(SessionError::EmptyReason);
        }
        self.persist(store, TaskState::Failed)?;
        Ok(events.emit(
            &self.task_id,
            EventPayload::TaskFailed {
                reason: reason.into(),
            },
        )?)
    }

    pub fn cancel(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
    ) -> Result<RuntimeEvent, SessionError> {
        self.advance(store, events, TaskState::Cancelled)
    }

    /// Rehydrates a session from its persisted row so a dropped session can
    /// continue exactly where it stopped. The row is authoritative: state and
    /// revision mirror storage, never local memory.
    pub fn load(
        store: &(impl TaskStore + ContractStore),
        task_id: &str,
    ) -> Result<Self, SessionError> {
        let record = store.get(task_id)?.ok_or(StorageError::TaskNotFound)?;
        // Rows predating contract persistence have no freeze to restore;
        // refusing loudly beats running under an unknown contract.
        let contract = store
            .load_contract(task_id)?
            .ok_or(StorageError::ContractNotFound)?;
        Ok(Self {
            task_id: record.id,
            state: record.state,
            revision: record.revision,
            contract,
        })
    }

    pub fn contract(&self) -> &GoalContract {
        &self.contract
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn state(&self) -> TaskState {
        self.state
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Persists the transition, mirrors the stored record, then emits the
    /// state-change event. A rejected transition returns before any mutation,
    /// so failed steps leave neither a revision nor an event behind.
    fn advance(
        &mut self,
        store: &mut impl TaskStore,
        events: &mut EventStream,
        next: TaskState,
    ) -> Result<RuntimeEvent, SessionError> {
        let from = self.persist(store, next)?;
        Ok(events.emit(
            &self.task_id,
            EventPayload::TaskStateChanged { from, to: next },
        )?)
    }

    /// Single persistence point: the store validates the transition, so an
    /// illegal step fails here with the stored row and the session untouched.
    fn persist(
        &mut self,
        store: &mut impl TaskStore,
        next: TaskState,
    ) -> Result<TaskState, SessionError> {
        let from = self.state;
        let record = store.transition(&self.task_id, next)?;
        self.state = record.state;
        self.revision = record.revision;
        Ok(from)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionError {
    Storage(StorageError),
    Event(EventError),
    EmptyReason,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "task session error: {self:?}")
    }
}

impl std::error::Error for SessionError {}

impl From<StorageError> for SessionError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<EventError> for SessionError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_ipc::{EventPayload, EventStream};
    use rocky_storage::InMemoryTaskStore;

    fn stream() -> EventStream {
        EventStream::default()
    }

    fn store() -> InMemoryTaskStore {
        InMemoryTaskStore::default()
    }

    fn contract(goal: &str) -> GoalContract {
        GoalContract::new("task-1", goal, vec!["read-only".into()]).expect("valid test contract")
    }

    #[test]
    fn full_lifecycle_persists_and_emits_every_step() {
        let mut store = store();
        let mut events = stream();

        let (mut session, created) =
            TaskSession::start(&mut store, &mut events, &contract("Read a document"))
                .expect("start session");
        assert_eq!(created.sequence, 1);
        assert_eq!(
            created.payload,
            EventPayload::TaskCreated {
                task_id: "task-1".into(),
            }
        );

        let planned = session.plan(&mut store, &mut events).expect("plan");
        let begun = session.begin(&mut store, &mut events).expect("begin");
        let completed = session.complete(&mut store, &mut events).expect("complete");
        assert_eq!(
            (planned.sequence, begun.sequence, completed.sequence),
            (2, 3, 4)
        );
        assert_eq!(completed.payload, EventPayload::TaskCompleted);

        let stored = store
            .get("task-1")
            .expect("storage query")
            .expect("stored task");
        assert_eq!(stored.state, TaskState::Completed);
        assert_eq!(stored.revision, 4);
    }

    #[test]
    fn approval_hold_and_resume_round_trip() {
        let mut store = store();
        let mut events = stream();
        let (mut session, _) =
            TaskSession::start(&mut store, &mut events, &contract("Write a note"))
                .expect("start session");
        session.plan(&mut store, &mut events).expect("plan");
        session.begin(&mut store, &mut events).expect("begin");

        let held = session
            .hold_for_approval(&mut store, &mut events)
            .expect("hold");
        assert_eq!(
            held.payload,
            EventPayload::TaskStateChanged {
                from: TaskState::Running,
                to: TaskState::WaitingForApproval,
            }
        );
        let resumed = session.resume(&mut store, &mut events).expect("resume");
        assert_eq!(
            resumed.payload,
            EventPayload::TaskStateChanged {
                from: TaskState::WaitingForApproval,
                to: TaskState::Running,
            }
        );
        session.complete(&mut store, &mut events).expect("complete");
        assert_eq!(session.state(), TaskState::Completed);
    }

    #[test]
    fn invalid_transition_changes_nothing_and_emits_nothing() {
        let mut store = store();
        let mut events = stream();
        let (mut session, _) =
            TaskSession::start(&mut store, &mut events, &contract("Read a document"))
                .expect("start session");

        assert!(matches!(
            session.complete(&mut store, &mut events),
            Err(SessionError::Storage(StorageError::InvalidStateTransition))
        ));
        let stored = store
            .get("task-1")
            .expect("storage query")
            .expect("stored task");
        assert_eq!((stored.state, stored.revision), (TaskState::Created, 1));

        // The failed step emitted nothing: the next event keeps the sequence.
        let planned = session.plan(&mut store, &mut events).expect("plan");
        assert_eq!(planned.sequence, 2);
    }

    #[test]
    fn fail_carries_its_reason_and_ends_the_task() {
        let mut store = store();
        let mut events = stream();
        let (mut session, _) = TaskSession::start(&mut store, &mut events, &contract("Run a tool"))
            .expect("start session");
        session.plan(&mut store, &mut events).expect("plan");
        session.begin(&mut store, &mut events).expect("begin");

        let failed = session
            .fail(&mut store, &mut events, "tool timed out")
            .expect("fail");
        assert_eq!(
            failed.payload,
            EventPayload::TaskFailed {
                reason: "tool timed out".into(),
            }
        );
        assert!(matches!(
            session.resume(&mut store, &mut events),
            Err(SessionError::Storage(StorageError::InvalidStateTransition))
        ));
    }

    #[test]
    fn cancel_from_running_reports_the_state_change() {
        let mut store = store();
        let mut events = stream();
        let (mut session, _) = TaskSession::start(&mut store, &mut events, &contract("Run a tool"))
            .expect("start session");
        session.plan(&mut store, &mut events).expect("plan");
        session.begin(&mut store, &mut events).expect("begin");

        let cancelled = session.cancel(&mut store, &mut events).expect("cancel");
        assert_eq!(
            cancelled.payload,
            EventPayload::TaskStateChanged {
                from: TaskState::Running,
                to: TaskState::Cancelled,
            }
        );
        assert_eq!(session.state(), TaskState::Cancelled);
    }

    #[test]
    fn start_rejects_a_blank_goal_at_the_contract() {
        // The contract is the only goal source, so a blank goal never reaches
        // the store: validation fails before any row or event exists.
        assert_eq!(
            GoalContract::new("task-1", "  ", vec![]),
            Err(rocky_domain::DomainError::EmptyGoal)
        );
    }

    #[test]
    fn fail_rejects_a_blank_reason() {
        let mut store = store();
        let mut events = stream();
        let (mut session, _) = TaskSession::start(&mut store, &mut events, &contract("Run a tool"))
            .expect("start session");
        session.plan(&mut store, &mut events).expect("plan");
        session.begin(&mut store, &mut events).expect("begin");

        assert_eq!(
            session.fail(&mut store, &mut events, "  "),
            Err(SessionError::EmptyReason)
        );
    }

    #[test]
    fn start_freezes_and_restores_the_contract() {
        let mut store = InMemoryTaskStore::default();
        let mut events = EventStream::default();
        let contract = GoalContract::new("task-1", "Read a document", vec!["read-only".into()])
            .expect("valid test contract");

        let (session, _) =
            TaskSession::start(&mut store, &mut events, &contract).expect("start session");
        assert_eq!(session.contract(), &contract);

        let loaded = TaskSession::load(&store, "task-1").expect("load session");
        assert_eq!(loaded.contract(), &contract);
        assert_eq!(loaded.contract().constraints(), &["read-only".to_string()]);
    }
}
