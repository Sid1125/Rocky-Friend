//! Persistence contracts for runtime metadata.
//!
//! The in-memory implementation is useful for tests. A SQLite adapter can implement the same
//! boundary without exposing database access to domain, policy, or tool-definition crates.

use rocky_audit::{AuditEvent, AuditOutcome};
use rocky_domain::{
    ApprovalRecord, AutonomyLevel, Capability, CapabilityKind, GoalContract, TaskState,
    content_digest,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRecord {
    pub id: String,
    pub user_goal: String,
    pub state: TaskState,
    pub revision: u64,
}

impl TaskRecord {
    pub fn new(id: impl Into<String>, user_goal: impl Into<String>) -> Result<Self, StorageError> {
        let id = id.into();
        let user_goal = user_goal.into();
        if id.trim().is_empty() {
            return Err(StorageError::EmptyTaskId);
        }
        if user_goal.trim().is_empty() {
            return Err(StorageError::EmptyGoal);
        }
        Ok(Self {
            id,
            user_goal,
            state: TaskState::Created,
            revision: 1,
        })
    }
}

/// Storage abstraction for authoritative task metadata.
pub trait TaskStore {
    fn create(&mut self, task: TaskRecord) -> Result<(), StorageError>;
    fn get(&self, task_id: &str) -> Result<Option<TaskRecord>, StorageError>;
    fn transition(&mut self, task_id: &str, next: TaskState) -> Result<TaskRecord, StorageError>;
    /// Lists every task in ID order. The task-visibility backend: what the
    /// UI shows is exactly what the store holds, with no other source.
    fn list_tasks(&self) -> Result<Vec<TaskRecord>, StorageError>;
}

/// Test and local-prototype implementation with atomic per-operation updates.
#[derive(Default)]
pub struct InMemoryTaskStore {
    tasks: BTreeMap<String, TaskRecord>,
    approvals: BTreeMap<String, ApprovalRecord>,
    evidence: BTreeMap<String, EvidenceRecord>,
    findings: BTreeMap<String, FindingRecord>,
    contracts: BTreeMap<String, GoalContract>,
}

impl TaskStore for InMemoryTaskStore {
    fn create(&mut self, task: TaskRecord) -> Result<(), StorageError> {
        if self.tasks.contains_key(&task.id) {
            return Err(StorageError::DuplicateTask);
        }
        self.tasks.insert(task.id.clone(), task);
        Ok(())
    }

    fn get(&self, task_id: &str) -> Result<Option<TaskRecord>, StorageError> {
        Ok(self.tasks.get(task_id).cloned())
    }

    fn list_tasks(&self) -> Result<Vec<TaskRecord>, StorageError> {
        // BTreeMap iterates in key order, so ID order is structural, not sorted.
        Ok(self.tasks.values().cloned().collect())
    }

    fn transition(&mut self, task_id: &str, next: TaskState) -> Result<TaskRecord, StorageError> {
        let task = self
            .tasks
            .get_mut(task_id)
            .ok_or(StorageError::TaskNotFound)?;
        task.state = task
            .state
            .transition(next)
            .map_err(|_| StorageError::InvalidStateTransition)?;
        task.revision = task
            .revision
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?;
        Ok(task.clone())
    }
}

/// SQLite implementation of the task-storage boundary.
pub struct SqliteTaskStore {
    connection: Connection,
}

impl SqliteTaskStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let connection = Connection::open(path).map_err(database_error)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self, StorageError> {
        Self::from_connection(Connection::open_in_memory().map_err(database_error)?)
    }

    fn from_connection(connection: Connection) -> Result<Self, StorageError> {
        migrate(&connection)?;
        Ok(Self { connection })
    }

    /// Persists an audit event without providing mutation or deletion APIs.
    pub fn append_audit(&self, event: &AuditEvent) -> Result<(), StorageError> {
        self.connection
            .execute(
                "INSERT INTO audit_events
                 (task_id, sequence, actor, action, autonomy_level, outcome)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    event.task_id,
                    sqlite_revision(event.sequence)?,
                    event.actor,
                    event.action,
                    autonomy_name(event.autonomy_level),
                    outcome_name(event.outcome),
                ],
            )
            .map_err(database_error)?;
        Ok(())
    }

    pub fn audit_count(&self, task_id: &str) -> Result<u64, StorageError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM audit_events WHERE task_id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        u64::try_from(count).map_err(|_| StorageError::CorruptRevision)
    }

    /// Reads a task's audit trail in sequence order. Together with
    /// [`Self::append_audit`] this is the audit-visibility backend: what the
    /// gate recorded is byte-for-byte what the UI can show.
    pub fn audit_events(&self, task_id: &str) -> Result<Vec<AuditEvent>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT task_id, sequence, actor, action, autonomy_level, outcome
                 FROM audit_events WHERE task_id = ?1 ORDER BY sequence",
            )
            .map_err(database_error)?;
        statement
            .query_map([task_id], |row| {
                let autonomy: String = row.get(4)?;
                let outcome: String = row.get(5)?;
                let sequence: i64 = row.get(1)?;
                Ok(AuditEvent {
                    task_id: row.get(0)?,
                    sequence: u64::try_from(sequence).map_err(|_| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(
                            StorageError::CorruptRevision,
                        ))
                    })?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    autonomy_level: parse_autonomy(&autonomy).map_err(|error| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                    })?,
                    outcome: parse_outcome(&outcome).map_err(|error| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                    })?,
                })
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)
    }
}

const SCHEMA_VERSION: u32 = 6;

const APPROVALS_TABLE: &str = "CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY NOT NULL,
                    action_hash TEXT NOT NULL UNIQUE,
                    capability_kind TEXT NOT NULL,
                    capability_scope TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL,
                    standing INTEGER NOT NULL DEFAULT 0
                 );";

const EVIDENCE_TABLE: &str = "CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY NOT NULL,
                    task_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    bytes BLOB NOT NULL
                 );";

const FINDINGS_TABLE: &str = "CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY NOT NULL,
                    task_id TEXT NOT NULL,
                    source_agent TEXT NOT NULL,
                    hypothesis TEXT NOT NULL,
                    evidence_ref TEXT NOT NULL,
                    confidence_pct INTEGER NOT NULL,
                    recommended_action TEXT NOT NULL
                 );";

const FINDING_ARTIFACTS_TABLE: &str = "CREATE TABLE IF NOT EXISTS finding_artifacts (
                    finding_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    artifact TEXT NOT NULL,
                    PRIMARY KEY (finding_id, position)
                 );";

fn migrate(connection: &Connection) -> Result<(), StorageError> {
    let version: u32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(database_error)?;
    if version > SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion(version));
    }
    // Incremental steps so databases created at any older version upgrade
    // through every intermediate schema instead of jumping blindly.
    if version < 1 {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY NOT NULL,
                    user_goal TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS audit_events (
                    task_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    autonomy_level TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    PRIMARY KEY (task_id, sequence)
                 );",
            )
            .map_err(database_error)?;
    }
    if version < 2 {
        connection
            .execute_batch(APPROVALS_TABLE)
            .map_err(database_error)?;
    }
    if version < 3 {
        connection
            .execute_batch(EVIDENCE_TABLE)
            .map_err(database_error)?;
    }
    if version < 5 {
        // Findings and their artifacts are new tables with no old shape to
        // preserve, so plain idempotent creation is the whole upgrade.
        connection
            .execute_batch(FINDINGS_TABLE)
            .map_err(database_error)?;
        connection
            .execute_batch(FINDING_ARTIFACTS_TABLE)
            .map_err(database_error)?;
    }
    if version < 4 {
        // Older approvals tables lack the standing flag; existing rows keep
        // their single-action meaning through the zero default. The column
        // check keeps this step idempotent for fresh databases (whose table
        // already has it) and for interrupted past migrations.
        let has_standing: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('approvals') WHERE name = 'standing'",
                [],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if has_standing == 0 {
            connection
                .execute_batch(
                    "ALTER TABLE approvals ADD COLUMN standing INTEGER NOT NULL DEFAULT 0;",
                )
                .map_err(database_error)?;
        }
    }
    if version < 6 {
        // Goal contracts are new tables with no old shape: idempotent
        // creation is the whole upgrade.
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS task_contracts (
                    task_id TEXT PRIMARY KEY NOT NULL,
                    goal TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS task_contract_constraints (
                    task_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    constraint_text TEXT NOT NULL,
                    PRIMARY KEY (task_id, position)
                 );",
            )
            .map_err(database_error)?;
    }
    if version != SCHEMA_VERSION {
        connection
            .execute_batch("PRAGMA user_version = 6;")
            .map_err(database_error)?;
    }
    Ok(())
}

impl TaskStore for SqliteTaskStore {
    fn create(&mut self, task: TaskRecord) -> Result<(), StorageError> {
        self.connection
            .execute(
                "INSERT INTO tasks (id, user_goal, state, revision) VALUES (?1, ?2, ?3, ?4)",
                params![
                    task.id,
                    task.user_goal,
                    state_name(task.state),
                    sqlite_revision(task.revision)?
                ],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    StorageError::DuplicateTask
                } else {
                    database_error(error)
                }
            })?;
        Ok(())
    }

    fn get(&self, task_id: &str) -> Result<Option<TaskRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT id, user_goal, state, revision FROM tasks WHERE id = ?1",
                [task_id],
                |row| {
                    let state: String = row.get(2)?;
                    let revision: i64 = row.get(3)?;
                    Ok(TaskRecord {
                        id: row.get(0)?,
                        user_goal: row.get(1)?,
                        state: parse_state(&state).map_err(|error| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                        })?,
                        revision: u64::try_from(revision).map_err(|_| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(
                                StorageError::CorruptRevision,
                            ))
                        })?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    fn list_tasks(&self) -> Result<Vec<TaskRecord>, StorageError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, user_goal, state, revision FROM tasks ORDER BY id")
            .map_err(database_error)?;
        statement
            .query_map([], |row| {
                let state: String = row.get(2)?;
                let revision: i64 = row.get(3)?;
                Ok(TaskRecord {
                    id: row.get(0)?,
                    user_goal: row.get(1)?,
                    state: parse_state(&state).map_err(|error| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                    })?,
                    revision: u64::try_from(revision).map_err(|_| {
                        rusqlite::Error::ToSqlConversionFailure(Box::new(
                            StorageError::CorruptRevision,
                        ))
                    })?,
                })
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)
    }

    fn transition(&mut self, task_id: &str, next: TaskState) -> Result<TaskRecord, StorageError> {
        let transaction = self.connection.transaction().map_err(database_error)?;
        let mut task = transaction
            .query_row(
                "SELECT id, user_goal, state, revision FROM tasks WHERE id = ?1",
                [task_id],
                |row| {
                    let state: String = row.get(2)?;
                    let revision: i64 = row.get(3)?;
                    Ok(TaskRecord {
                        id: row.get(0)?,
                        user_goal: row.get(1)?,
                        state: parse_state(&state).map_err(|error| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(error))
                        })?,
                        revision: u64::try_from(revision).map_err(|_| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(
                                StorageError::CorruptRevision,
                            ))
                        })?,
                    })
                },
            )
            .optional()
            .map_err(database_error)?
            .ok_or(StorageError::TaskNotFound)?;
        task.state = task
            .state
            .transition(next)
            .map_err(|_| StorageError::InvalidStateTransition)?;
        task.revision = task
            .revision
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?;
        transaction
            .execute(
                "UPDATE tasks SET state = ?1, revision = ?2 WHERE id = ?3",
                params![
                    state_name(task.state),
                    sqlite_revision(task.revision)?,
                    task.id
                ],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(task)
    }
}

fn state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Created => "created",
        TaskState::Planned => "planned",
        TaskState::Running => "running",
        TaskState::WaitingForApproval => "waiting_for_approval",
        TaskState::Completed => "completed",
        TaskState::Failed => "failed",
        TaskState::Cancelled => "cancelled",
    }
}

fn autonomy_name(level: AutonomyLevel) -> &'static str {
    match level {
        AutonomyLevel::A0 => "a0",
        AutonomyLevel::A1 => "a1",
        AutonomyLevel::A2 => "a2",
        AutonomyLevel::A3 => "a3",
        AutonomyLevel::A4 => "a4",
    }
}

fn outcome_name(outcome: AuditOutcome) -> &'static str {
    match outcome {
        AuditOutcome::Approved => "approved",
        AuditOutcome::ApprovalRequired => "approval_required",
        AuditOutcome::Queued => "queued",
        AuditOutcome::Denied => "denied",
        AuditOutcome::Cancelled => "cancelled",
    }
}

fn parse_autonomy(value: &str) -> Result<AutonomyLevel, StorageError> {
    match value {
        "a0" => Ok(AutonomyLevel::A0),
        "a1" => Ok(AutonomyLevel::A1),
        "a2" => Ok(AutonomyLevel::A2),
        "a3" => Ok(AutonomyLevel::A3),
        "a4" => Ok(AutonomyLevel::A4),
        _ => Err(StorageError::CorruptAudit),
    }
}

fn parse_outcome(value: &str) -> Result<AuditOutcome, StorageError> {
    match value {
        "approved" => Ok(AuditOutcome::Approved),
        "approval_required" => Ok(AuditOutcome::ApprovalRequired),
        "queued" => Ok(AuditOutcome::Queued),
        "denied" => Ok(AuditOutcome::Denied),
        "cancelled" => Ok(AuditOutcome::Cancelled),
        _ => Err(StorageError::CorruptAudit),
    }
}

fn capability_kind_name(kind: CapabilityKind) -> &'static str {
    match kind {
        CapabilityKind::FilesystemRead => "filesystem_read",
        CapabilityKind::FilesystemWrite => "filesystem_write",
        CapabilityKind::ProcessExecute => "process_execute",
        CapabilityKind::NetworkConnect => "network_connect",
        CapabilityKind::BrowserInteract => "browser_interact",
    }
}

fn parse_capability_kind(value: &str) -> Result<CapabilityKind, StorageError> {
    match value {
        "filesystem_read" => Ok(CapabilityKind::FilesystemRead),
        "filesystem_write" => Ok(CapabilityKind::FilesystemWrite),
        "process_execute" => Ok(CapabilityKind::ProcessExecute),
        "network_connect" => Ok(CapabilityKind::NetworkConnect),
        "browser_interact" => Ok(CapabilityKind::BrowserInteract),
        _ => Err(StorageError::CorruptCapability),
    }
}

fn parse_state(value: &str) -> Result<TaskState, StorageError> {
    match value {
        "created" => Ok(TaskState::Created),
        "planned" => Ok(TaskState::Planned),
        "running" => Ok(TaskState::Running),
        "waiting_for_approval" => Ok(TaskState::WaitingForApproval),
        "completed" => Ok(TaskState::Completed),
        "failed" => Ok(TaskState::Failed),
        "cancelled" => Ok(TaskState::Cancelled),
        _ => Err(StorageError::CorruptState),
    }
}

fn database_error(error: rusqlite::Error) -> StorageError {
    StorageError::Database(error.to_string())
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(error, _)
            if error.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn sqlite_revision(revision: u64) -> Result<i64, StorageError> {
    i64::try_from(revision).map_err(|_| StorageError::RevisionOverflow)
}

fn sqlite_timestamp(value: u64) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::InvalidApprovalExpiry)
}

/// Maximum bytes per captured evidence entry. Tool outputs are already
/// bounded by their executors; this second bound keeps the evidence store
/// itself honest no matter which producer calls it.
pub const MAX_EVIDENCE_BYTES: usize = 65_536;

/// Maximum evidence entries per task. Completion evidence is a pointer set,
/// not an archive: old entries are never deleted, so the count must cap.
pub const MAX_EVIDENCE_PER_TASK: usize = 32;

/// A captured tool output bound to its task.
///
/// The digest is a content address computed with [`content_digest`]: equal
/// bytes always produce equal digests, so verifiers can re-hash and compare
/// without trusting the store. IDs are store-assigned per-task sequences
/// (`task:seq`) and need no randomness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecord {
    pub id: String,
    pub task_id: String,
    pub tool_id: String,
    pub digest: String,
    pub bytes: Vec<u8>,
}

/// Persistence boundary for completion evidence.
pub trait EvidenceStore {
    fn capture(
        &mut self,
        task_id: &str,
        tool_id: &str,
        bytes: Vec<u8>,
    ) -> Result<EvidenceRecord, StorageError>;
    fn evidence(&self, id: &str) -> Result<Option<EvidenceRecord>, StorageError>;
    fn evidence_for_task(&self, task_id: &str) -> Result<Vec<EvidenceRecord>, StorageError>;
}

fn checked_evidence_inputs(task_id: &str, tool_id: &str, bytes: &[u8]) -> Result<(), StorageError> {
    if task_id.trim().is_empty() {
        return Err(StorageError::EmptyTaskId);
    }
    if tool_id.trim().is_empty() {
        return Err(StorageError::EmptyToolId);
    }
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(StorageError::EvidenceTooLarge);
    }
    Ok(())
}

impl EvidenceStore for InMemoryTaskStore {
    fn capture(
        &mut self,
        task_id: &str,
        tool_id: &str,
        bytes: Vec<u8>,
    ) -> Result<EvidenceRecord, StorageError> {
        checked_evidence_inputs(task_id, tool_id, &bytes)?;
        let sequence = self
            .evidence
            .values()
            .filter(|item| item.task_id == task_id)
            .count()
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?;
        if sequence > MAX_EVIDENCE_PER_TASK {
            return Err(StorageError::EvidenceStoreFull);
        }
        let record = EvidenceRecord {
            id: format!("{task_id}:{sequence}"),
            task_id: task_id.into(),
            tool_id: tool_id.into(),
            digest: content_digest(&[&bytes]),
            bytes,
        };
        self.evidence.insert(record.id.clone(), record.clone());
        Ok(record)
    }

    fn evidence(&self, id: &str) -> Result<Option<EvidenceRecord>, StorageError> {
        Ok(self.evidence.get(id).cloned())
    }

    fn evidence_for_task(&self, task_id: &str) -> Result<Vec<EvidenceRecord>, StorageError> {
        Ok(self
            .evidence
            .values()
            .filter(|item| item.task_id == task_id)
            .cloned()
            .collect())
    }
}

impl SqliteTaskStore {
    fn evidence_count(&self, task_id: &str) -> Result<usize, StorageError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM evidence WHERE task_id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        usize::try_from(count).map_err(|_| StorageError::CorruptRevision)
    }
}

impl EvidenceStore for SqliteTaskStore {
    fn capture(
        &mut self,
        task_id: &str,
        tool_id: &str,
        bytes: Vec<u8>,
    ) -> Result<EvidenceRecord, StorageError> {
        checked_evidence_inputs(task_id, tool_id, &bytes)?;
        let sequence = self
            .evidence_count(task_id)?
            .checked_add(1)
            .ok_or(StorageError::RevisionOverflow)?;
        if sequence > MAX_EVIDENCE_PER_TASK {
            return Err(StorageError::EvidenceStoreFull);
        }
        let record = EvidenceRecord {
            id: format!("{task_id}:{sequence}"),
            task_id: task_id.into(),
            tool_id: tool_id.into(),
            digest: content_digest(&[&bytes]),
            bytes,
        };
        self.connection
            .execute(
                "INSERT INTO evidence (id, task_id, tool_id, digest, bytes)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    record.id,
                    record.task_id,
                    record.tool_id,
                    record.digest,
                    record.bytes,
                ],
            )
            .map_err(database_error)?;
        Ok(record)
    }

    fn evidence(&self, id: &str) -> Result<Option<EvidenceRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT id, task_id, tool_id, digest, bytes FROM evidence WHERE id = ?1",
                [id],
                |row| {
                    Ok(EvidenceRecord {
                        id: row.get(0)?,
                        task_id: row.get(1)?,
                        tool_id: row.get(2)?,
                        digest: row.get(3)?,
                        bytes: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    fn evidence_for_task(&self, task_id: &str) -> Result<Vec<EvidenceRecord>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, task_id, tool_id, digest, bytes FROM evidence
                 WHERE task_id = ?1 ORDER BY rowid",
            )
            .map_err(database_error)?;
        statement
            .query_map([task_id], |row| {
                Ok(EvidenceRecord {
                    id: row.get(0)?,
                    task_id: row.get(1)?,
                    tool_id: row.get(2)?,
                    digest: row.get(3)?,
                    bytes: row.get(4)?,
                })
            })
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)
    }
}

/// Maximum affected artifacts stored per finding. Mirrors the board's bound
/// so persistence can never hold what validation would reject.
pub const MAX_FINDING_ARTIFACTS: usize = 16;

/// Maximum findings stored per task. Old findings are never deleted, so the
/// count must cap to bound memory on a laptop.
pub const MAX_FINDINGS_PER_TASK: usize = 64;

/// A persisted worker finding. Artifacts ride in their own rows (see the
/// store implementation), so arbitrary text survives byte-for-byte with no
/// escaping scheme to attack or corrupt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingRecord {
    pub id: String,
    pub task_id: String,
    pub source_agent: String,
    pub hypothesis: String,
    pub evidence_ref: String,
    pub confidence_pct: u8,
    pub affected_artifacts: Vec<String>,
    pub recommended_action: String,
}

/// Persistence boundary for worker findings.
pub trait FindingStore {
    #[allow(clippy::too_many_arguments)]
    fn post_finding(
        &mut self,
        id: &str,
        task_id: &str,
        source_agent: &str,
        hypothesis: &str,
        evidence_ref: &str,
        confidence_pct: u8,
        affected_artifacts: Vec<String>,
        recommended_action: &str,
    ) -> Result<FindingRecord, StorageError>;
    fn finding(&self, id: &str) -> Result<Option<FindingRecord>, StorageError>;
    fn findings_for_task(&self, task_id: &str) -> Result<Vec<FindingRecord>, StorageError>;
}

#[allow(clippy::too_many_arguments)]
fn checked_finding_inputs(
    id: &str,
    task_id: &str,
    source_agent: &str,
    hypothesis: &str,
    evidence_ref: &str,
    affected_artifacts: &[String],
    recommended_action: &str,
) -> Result<(), StorageError> {
    if id.trim().is_empty() || task_id.trim().is_empty() {
        return Err(StorageError::EmptyTaskId);
    }
    if source_agent.trim().is_empty()
        || hypothesis.trim().is_empty()
        || evidence_ref.trim().is_empty()
        || recommended_action.trim().is_empty()
    {
        return Err(StorageError::EmptyFindingText);
    }
    if affected_artifacts.len() > MAX_FINDING_ARTIFACTS {
        return Err(StorageError::TooManyFindingArtifacts);
    }
    if affected_artifacts.iter().any(|item| item.trim().is_empty()) {
        return Err(StorageError::EmptyFindingText);
    }
    Ok(())
}

impl FindingStore for InMemoryTaskStore {
    #[allow(clippy::too_many_arguments)]
    fn post_finding(
        &mut self,
        id: &str,
        task_id: &str,
        source_agent: &str,
        hypothesis: &str,
        evidence_ref: &str,
        confidence_pct: u8,
        affected_artifacts: Vec<String>,
        recommended_action: &str,
    ) -> Result<FindingRecord, StorageError> {
        checked_finding_inputs(
            id,
            task_id,
            source_agent,
            hypothesis,
            evidence_ref,
            &affected_artifacts,
            recommended_action,
        )?;
        if self.findings.contains_key(id) {
            return Err(StorageError::DuplicateFinding);
        }
        let count = self
            .findings
            .values()
            .filter(|item| item.task_id == task_id)
            .count();
        if count >= MAX_FINDINGS_PER_TASK {
            return Err(StorageError::FindingStoreFull);
        }
        let record = FindingRecord {
            id: id.into(),
            task_id: task_id.into(),
            source_agent: source_agent.into(),
            hypothesis: hypothesis.into(),
            evidence_ref: evidence_ref.into(),
            confidence_pct,
            affected_artifacts,
            recommended_action: recommended_action.into(),
        };
        self.findings.insert(record.id.clone(), record.clone());
        Ok(record)
    }

    fn finding(&self, id: &str) -> Result<Option<FindingRecord>, StorageError> {
        Ok(self.findings.get(id).cloned())
    }

    fn findings_for_task(&self, task_id: &str) -> Result<Vec<FindingRecord>, StorageError> {
        Ok(self
            .findings
            .values()
            .filter(|item| item.task_id == task_id)
            .cloned()
            .collect())
    }
}

impl SqliteTaskStore {
    fn finding_count(&self, task_id: &str) -> Result<usize, StorageError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE task_id = ?1",
                [task_id],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        usize::try_from(count).map_err(|_| StorageError::CorruptRevision)
    }

    fn artifacts_for(&self, finding_id: &str) -> Result<Vec<String>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT artifact FROM finding_artifacts
                 WHERE finding_id = ?1 ORDER BY position",
            )
            .map_err(database_error)?;
        statement
            .query_map([finding_id], |row| row.get(0))
            .map_err(database_error)?
            .collect::<Result<Vec<String>, _>>()
            .map_err(database_error)
    }

    fn read_finding(&self, id: &str) -> Result<Option<FindingRecord>, StorageError> {
        let row: Option<(String, String, String, String, String, i64, String)> = self
            .connection
            .query_row(
                "SELECT id, task_id, source_agent, hypothesis, evidence_ref,
                    confidence_pct, recommended_action
                 FROM findings WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        row.map(
            |(id, task_id, source_agent, hypothesis, evidence_ref, confidence, action)| {
                let artifacts = self.artifacts_for(&id)?;
                let confidence_pct =
                    u8::try_from(confidence).map_err(|_| StorageError::CorruptRevision)?;
                Ok(FindingRecord {
                    id,
                    task_id,
                    source_agent,
                    hypothesis,
                    evidence_ref,
                    confidence_pct,
                    affected_artifacts: artifacts,
                    recommended_action: action,
                })
            },
        )
        .transpose()
    }
}

impl FindingStore for SqliteTaskStore {
    #[allow(clippy::too_many_arguments)]
    fn post_finding(
        &mut self,
        id: &str,
        task_id: &str,
        source_agent: &str,
        hypothesis: &str,
        evidence_ref: &str,
        confidence_pct: u8,
        affected_artifacts: Vec<String>,
        recommended_action: &str,
    ) -> Result<FindingRecord, StorageError> {
        checked_finding_inputs(
            id,
            task_id,
            source_agent,
            hypothesis,
            evidence_ref,
            &affected_artifacts,
            recommended_action,
        )?;
        if self.finding_count(task_id)? >= MAX_FINDINGS_PER_TASK {
            return Err(StorageError::FindingStoreFull);
        }
        self.connection
            .execute(
                "INSERT INTO findings
                 (id, task_id, source_agent, hypothesis, evidence_ref,
                  confidence_pct, recommended_action)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    task_id,
                    source_agent,
                    hypothesis,
                    evidence_ref,
                    i64::from(confidence_pct),
                    recommended_action,
                ],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    StorageError::DuplicateFinding
                } else {
                    database_error(error)
                }
            })?;
        for (position, artifact) in affected_artifacts.iter().enumerate() {
            let position = i64::try_from(position).map_err(|_| StorageError::RevisionOverflow)?;
            self.connection
                .execute(
                    "INSERT INTO finding_artifacts (finding_id, position, artifact)
                     VALUES (?1, ?2, ?3)",
                    params![id, position, artifact],
                )
                .map_err(database_error)?;
        }
        self.read_finding(id)?
            .ok_or_else(|| database_error(rusqlite::Error::QueryReturnedNoRows))
    }

    fn finding(&self, id: &str) -> Result<Option<FindingRecord>, StorageError> {
        self.read_finding(id)
    }

    fn findings_for_task(&self, task_id: &str) -> Result<Vec<FindingRecord>, StorageError> {
        let mut statement = self
            .connection
            .prepare("SELECT id FROM findings WHERE task_id = ?1 ORDER BY rowid")
            .map_err(database_error)?;
        let ids = statement
            .query_map([task_id], |row| row.get::<_, String>(0))
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)?;
        ids.iter()
            .map(|id| {
                self.read_finding(id)?
                    .ok_or_else(|| database_error(rusqlite::Error::QueryReturnedNoRows))
            })
            .collect()
    }
}

/// Persistence boundary for frozen goal contracts.
///
/// Contracts arrive pre-validated from [`GoalContract::new`]: the store
/// checks nothing but Duplication, so a re-frozen goal fails loudly instead
/// of silently replacing the freeze.
pub trait ContractStore {
    fn save_contract(&mut self, contract: &GoalContract) -> Result<(), StorageError>;
    fn load_contract(&self, task_id: &str) -> Result<Option<GoalContract>, StorageError>;
}

impl ContractStore for InMemoryTaskStore {
    fn save_contract(&mut self, contract: &GoalContract) -> Result<(), StorageError> {
        if self.contracts.contains_key(contract.task_id()) {
            return Err(StorageError::DuplicateContract);
        }
        self.contracts
            .insert(contract.task_id().into(), contract.clone());
        Ok(())
    }

    fn load_contract(&self, task_id: &str) -> Result<Option<GoalContract>, StorageError> {
        Ok(self.contracts.get(task_id).cloned())
    }
}

impl SqliteTaskStore {
    fn read_contract(&self, task_id: &str) -> Result<Option<GoalContract>, StorageError> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT task_id, goal FROM task_contracts WHERE task_id = ?1",
                [task_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        row.map(|(task_id, goal)| {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT constraint_text FROM task_contract_constraints
                     WHERE task_id = ?1 ORDER BY position",
                )
                .map_err(database_error)?;
            let constraints = statement
                .query_map([&task_id], |row| row.get::<_, String>(0))
                .map_err(database_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(database_error)?;
            // Rows were validated at save time through the same constructor,
            // so a parse failure means database corruption, not bad input.
            GoalContract::new(task_id, goal, constraints).map_err(|_| StorageError::CorruptContract)
        })
        .transpose()
    }
}

impl ContractStore for SqliteTaskStore {
    fn save_contract(&mut self, contract: &GoalContract) -> Result<(), StorageError> {
        let transaction = self.connection.transaction().map_err(database_error)?;
        let inserted = transaction
            .execute(
                "INSERT INTO task_contracts (task_id, goal) VALUES (?1, ?2)",
                params![contract.task_id(), contract.goal()],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    StorageError::DuplicateContract
                } else {
                    database_error(error)
                }
            })?;
        debug_assert_eq!(inserted, 1);
        for (position, constraint) in contract.constraints().iter().enumerate() {
            let position = i64::try_from(position).map_err(|_| StorageError::RevisionOverflow)?;
            transaction
                .execute(
                    "INSERT INTO task_contract_constraints (task_id, position, constraint_text)
                     VALUES (?1, ?2, ?3)",
                    params![contract.task_id(), position, constraint],
                )
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)?;
        Ok(())
    }

    fn load_contract(&self, task_id: &str) -> Result<Option<GoalContract>, StorageError> {
        self.read_contract(task_id)
    }
}

/// Persistence boundary for approvals with expiry and revocation.
pub trait ApprovalStore {
    fn save_approval(&mut self, approval: ApprovalRecord) -> Result<(), StorageError>;
    fn get_approval(&self, action_hash: &str) -> Result<Option<ApprovalRecord>, StorageError>;
    fn revoke_approval(&mut self, action_hash: &str) -> Result<(), StorageError>;
    fn is_approved(&self, action_hash: &str, now_unix_secs: u64) -> Result<bool, StorageError>;
    /// Lists every standing area-trust grant, including revoked and expired
    /// ones: the gate is the single enforcement point that decides validity.
    fn standing_approvals(&self) -> Result<Vec<ApprovalRecord>, StorageError>;
}

impl ApprovalStore for InMemoryTaskStore {
    fn save_approval(&mut self, approval: ApprovalRecord) -> Result<(), StorageError> {
        if self.approvals.contains_key(&approval.action_hash)
            || self.approvals.values().any(|item| item.id == approval.id)
        {
            return Err(StorageError::DuplicateApproval);
        }
        self.approvals
            .insert(approval.action_hash.clone(), approval);
        Ok(())
    }

    fn get_approval(&self, action_hash: &str) -> Result<Option<ApprovalRecord>, StorageError> {
        Ok(self.approvals.get(action_hash).cloned())
    }

    fn revoke_approval(&mut self, action_hash: &str) -> Result<(), StorageError> {
        self.approvals
            .get_mut(action_hash)
            .map(|approval| approval.revoked = true)
            .ok_or(StorageError::ApprovalNotFound)
    }

    fn is_approved(&self, action_hash: &str, now_unix_secs: u64) -> Result<bool, StorageError> {
        Ok(self
            .get_approval(action_hash)?
            .is_some_and(|approval| approval.is_valid_at(now_unix_secs)))
    }

    fn standing_approvals(&self) -> Result<Vec<ApprovalRecord>, StorageError> {
        Ok(self
            .approvals
            .values()
            .filter(|approval| approval.standing)
            .cloned()
            .collect())
    }
}

impl SqliteTaskStore {
    /// Persists an approval without providing update-in-place or deletion APIs.
    /// Revocation flows through [`ApprovalStore::revoke_approval`].
    pub fn save_approval_record(&mut self, approval: &ApprovalRecord) -> Result<(), StorageError> {
        self.connection
            .execute(
                "INSERT INTO approvals
                 (id, action_hash, capability_kind, capability_scope, expires_at, revoked,
                  standing)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    approval.id,
                    approval.action_hash,
                    capability_kind_name(approval.capability.kind),
                    approval.capability.scope,
                    sqlite_timestamp(approval.expires_at_unix_secs)?,
                    i64::from(approval.revoked),
                    i64::from(approval.standing),
                ],
            )
            .map_err(|error| {
                if is_constraint_violation(&error) {
                    StorageError::DuplicateApproval
                } else {
                    database_error(error)
                }
            })?;
        Ok(())
    }

    /// Fetches an approval by its action hash.
    pub fn fetch_approval(
        &self,
        action_hash: &str,
    ) -> Result<Option<ApprovalRecord>, StorageError> {
        self.connection
            .query_row(
                "SELECT id, action_hash, capability_kind, capability_scope, expires_at, revoked,
                    standing FROM approvals WHERE action_hash = ?1",
                [action_hash],
                map_approval_row,
            )
            .optional()
            .map_err(database_error)
    }

    /// Lists every standing area-trust grant in insertion order.
    pub fn fetch_standing_approvals(&self) -> Result<Vec<ApprovalRecord>, StorageError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, action_hash, capability_kind, capability_scope, expires_at, revoked,
                    standing FROM approvals WHERE standing = 1 ORDER BY rowid",
            )
            .map_err(database_error)?;
        statement
            .query_map([], map_approval_row)
            .map_err(database_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(database_error)
    }
}

/// Maps one approvals row. Shared by hash lookup and standing listing so the
/// two paths can never disagree on what a stored approval means.
fn map_approval_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRecord> {
    let kind: String = row.get(2)?;
    let scope: String = row.get(3)?;
    let expires_at: i64 = row.get(4)?;
    let revoked: i64 = row.get(5)?;
    let capability = Capability::new(
        parse_capability_kind(&kind)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?,
        scope,
    )
    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    Ok(ApprovalRecord {
        id: row.get(0)?,
        action_hash: row.get(1)?,
        capability,
        expires_at_unix_secs: u64::try_from(expires_at).map_err(|_| {
            rusqlite::Error::ToSqlConversionFailure(Box::new(StorageError::CorruptRevision))
        })?,
        revoked: revoked != 0,
        standing: row.get::<_, i64>(6)? != 0,
    })
}

impl ApprovalStore for SqliteTaskStore {
    fn save_approval(&mut self, approval: ApprovalRecord) -> Result<(), StorageError> {
        self.save_approval_record(&approval)
    }

    fn get_approval(&self, action_hash: &str) -> Result<Option<ApprovalRecord>, StorageError> {
        self.fetch_approval(action_hash)
    }

    fn revoke_approval(&mut self, action_hash: &str) -> Result<(), StorageError> {
        let updated = self
            .connection
            .execute(
                "UPDATE approvals SET revoked = 1 WHERE action_hash = ?1",
                [action_hash],
            )
            .map_err(database_error)?;
        if updated == 0 {
            return Err(StorageError::ApprovalNotFound);
        }
        Ok(())
    }

    fn is_approved(&self, action_hash: &str, now_unix_secs: u64) -> Result<bool, StorageError> {
        Ok(self
            .fetch_approval(action_hash)?
            .is_some_and(|approval| approval.is_valid_at(now_unix_secs)))
    }

    fn standing_approvals(&self) -> Result<Vec<ApprovalRecord>, StorageError> {
        self.fetch_standing_approvals()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageError {
    EmptyTaskId,
    EmptyGoal,
    DuplicateTask,
    TaskNotFound,
    InvalidStateTransition,
    RevisionOverflow,
    CorruptState,
    CorruptRevision,
    CorruptCapability,
    CorruptAudit,
    EmptyApprovalId,
    EmptyActionHash,
    InvalidApprovalExpiry,
    DuplicateApproval,
    ApprovalNotFound,
    EmptyToolId,
    EvidenceTooLarge,
    EvidenceStoreFull,
    EmptyFindingText,
    TooManyFindingArtifacts,
    DuplicateFinding,
    FindingStoreFull,
    DuplicateContract,
    ContractNotFound,
    CorruptContract,
    UnsupportedSchemaVersion(u32),
    Database(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "storage error: {self:?}")
    }
}

impl std::error::Error for StorageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transitions_are_persisted_with_monotonic_revisions() {
        let mut store = InMemoryTaskStore::default();
        store
            .create(TaskRecord::new("task-1", "Read a document").expect("valid task"))
            .expect("new task");

        let planned = store
            .transition("task-1", TaskState::Planned)
            .expect("valid transition");

        assert_eq!(planned.state, TaskState::Planned);
        assert_eq!(planned.revision, 2);
    }

    #[test]
    fn invalid_transition_does_not_mutate_the_persisted_task() {
        let mut store = InMemoryTaskStore::default();
        store
            .create(TaskRecord::new("task-1", "Read a document").expect("valid task"))
            .expect("new task");

        assert_eq!(
            store.transition("task-1", TaskState::Completed),
            Err(StorageError::InvalidStateTransition)
        );
        let stored = store
            .get("task-1")
            .expect("storage query")
            .expect("stored task");
        assert_eq!(stored.state, TaskState::Created);
        assert_eq!(stored.revision, 1);
    }

    #[test]
    fn duplicate_task_ids_are_rejected() {
        let mut store = InMemoryTaskStore::default();
        let task = TaskRecord::new("task-1", "Read a document").expect("valid task");
        store.create(task.clone()).expect("new task");

        assert_eq!(store.create(task), Err(StorageError::DuplicateTask));
    }

    #[test]
    fn sqlite_store_persists_task_state_across_queries() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        store
            .create(TaskRecord::new("task-1", "Read a document").expect("valid task"))
            .expect("new task");
        store
            .transition("task-1", TaskState::Planned)
            .expect("valid transition");

        let stored = store
            .get("task-1")
            .expect("storage query")
            .expect("stored task");
        assert_eq!(stored.state, TaskState::Planned);
        assert_eq!(stored.revision, 2);
    }

    #[test]
    fn sqlite_store_appends_audit_events() {
        let store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        let event = AuditEvent {
            sequence: 1,
            task_id: "task-1".into(),
            actor: "runtime".into(),
            action: "filesystem.read".into(),
            autonomy_level: AutonomyLevel::A0,
            outcome: AuditOutcome::Approved,
        };

        store.append_audit(&event).expect("append audit event");
        assert_eq!(store.audit_count("task-1").expect("audit count"), 1);
    }

    fn evidence_bytes() -> Vec<u8> {
        b"file bytes \x00 with nul".to_vec()
    }

    #[test]
    fn capture_returns_a_content_addressed_record() {
        let mut store = InMemoryTaskStore::default();
        let record = store
            .capture("task-1", "filesystem.read", evidence_bytes())
            .expect("capture evidence");

        assert_eq!(record.id, "task-1:1");
        assert_eq!(record.digest, content_digest(&[&evidence_bytes()]));
        assert_eq!(record.bytes, evidence_bytes());
        assert_eq!(
            store
                .evidence("task-1:1")
                .expect("evidence query")
                .expect("stored evidence")
                .bytes,
            evidence_bytes()
        );
        assert_eq!(
            store.evidence_for_task("task-1").expect("task query").len(),
            1
        );
        assert!(
            store
                .evidence_for_task("task-2")
                .expect("task query")
                .is_empty()
        );
    }

    #[test]
    fn capture_rejects_blank_bindings_and_oversized_bytes() {
        let mut store = InMemoryTaskStore::default();
        assert_eq!(
            store.capture("  ", "filesystem.read", evidence_bytes()),
            Err(StorageError::EmptyTaskId)
        );
        assert_eq!(
            store.capture("task-1", "  ", evidence_bytes()),
            Err(StorageError::EmptyToolId)
        );
        assert_eq!(
            store.capture("task-1", "filesystem.read", vec![0; MAX_EVIDENCE_BYTES + 1]),
            Err(StorageError::EvidenceTooLarge)
        );
    }

    #[test]
    fn capture_rejects_posts_beyond_the_per_task_cap() {
        let mut store = InMemoryTaskStore::default();
        for _ in 0..MAX_EVIDENCE_PER_TASK {
            store
                .capture("task-1", "filesystem.read", b"x".to_vec())
                .expect("capture evidence");
        }
        assert_eq!(
            store.capture("task-1", "filesystem.read", b"x".to_vec()),
            Err(StorageError::EvidenceStoreFull)
        );
        // Other tasks are unaffected by one task's cap.
        assert!(
            store
                .capture("task-2", "filesystem.read", b"x".to_vec())
                .is_ok()
        );
    }

    #[test]
    fn sqlite_evidence_matches_in_memory_parity() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        let record = store
            .capture("task-1", "filesystem.read", evidence_bytes())
            .expect("capture evidence");

        assert_eq!(record.id, "task-1:1");
        assert_eq!(record.digest, content_digest(&[&evidence_bytes()]));
        let stored = store
            .evidence("task-1:1")
            .expect("evidence query")
            .expect("stored evidence");
        assert_eq!(stored.bytes, evidence_bytes());
        assert_eq!(
            store.evidence_for_task("task-1").expect("task query").len(),
            1
        );
        assert_eq!(
            store.capture("  ", "filesystem.read", evidence_bytes()),
            Err(StorageError::EmptyTaskId)
        );
        assert_eq!(
            store.capture("task-1", "filesystem.read", vec![0; MAX_EVIDENCE_BYTES + 1]),
            Err(StorageError::EvidenceTooLarge)
        );
    }

    #[test]
    fn sqlite_duplicate_task_ids_match_in_memory_parity() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        let task = TaskRecord::new("task-1", "Read a document").expect("valid task");
        store.create(task.clone()).expect("new task");

        assert_eq!(store.create(task), Err(StorageError::DuplicateTask));
    }

    #[test]
    fn sqlite_invalid_transition_does_not_mutate_the_persisted_task() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        store
            .create(TaskRecord::new("task-1", "Read a document").expect("valid task"))
            .expect("new task");

        assert_eq!(
            store.transition("task-1", TaskState::Completed),
            Err(StorageError::InvalidStateTransition)
        );
        let stored = store
            .get("task-1")
            .expect("storage query")
            .expect("stored task");
        assert_eq!(stored.state, TaskState::Created);
        assert_eq!(stored.revision, 1);
    }

    #[test]
    fn revision_overflow_is_rejected_instead_of_wrapping() {
        let mut store = InMemoryTaskStore::default();
        store
            .create(TaskRecord {
                id: "task-1".into(),
                user_goal: "Read a document".into(),
                state: TaskState::Created,
                revision: u64::MAX,
            })
            .expect("new task");

        assert_eq!(
            store.transition("task-1", TaskState::Planned),
            Err(StorageError::RevisionOverflow)
        );
    }

    fn approval(capability_scope: &str) -> ApprovalRecord {
        ApprovalRecord::new(
            "approval-1",
            "hash-1",
            Capability::new(
                rocky_domain::CapabilityKind::FilesystemWrite,
                capability_scope.to_string(),
            )
            .expect("valid test capability"),
            1_000,
        )
        .expect("valid test approval")
    }

    #[test]
    fn in_memory_approvals_enforce_expiry_and_revocation() {
        let mut store = InMemoryTaskStore::default();
        store
            .save_approval(approval("C:/workspace"))
            .expect("save approval");

        assert!(store.is_approved("hash-1", 999).expect("validity query"));
        assert!(!store.is_approved("hash-1", 1_000).expect("validity query"));
        assert!(!store.is_approved("missing", 999).expect("validity query"));

        store.revoke_approval("hash-1").expect("revoke approval");
        assert!(!store.is_approved("hash-1", 999).expect("validity query"));
        assert_eq!(
            store.save_approval(approval("C:/workspace")),
            Err(StorageError::DuplicateApproval)
        );
        assert_eq!(
            store.revoke_approval("missing"),
            Err(StorageError::ApprovalNotFound)
        );
    }

    #[test]
    fn sqlite_approvals_enforce_expiry_and_revocation() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        store
            .save_approval(approval("C:/workspace"))
            .expect("save approval");

        let stored = store
            .get_approval("hash-1")
            .expect("approval query")
            .expect("stored approval");
        assert_eq!(stored.expires_at_unix_secs, 1_000);
        assert!(store.is_approved("hash-1", 999).expect("validity query"));
        assert!(!store.is_approved("hash-1", 1_000).expect("validity query"));

        store.revoke_approval("hash-1").expect("revoke approval");
        assert!(!store.is_approved("hash-1", 999).expect("validity query"));
        assert_eq!(
            store.save_approval(approval("C:/workspace")),
            Err(StorageError::DuplicateApproval)
        );
        assert_eq!(
            store.revoke_approval("missing"),
            Err(StorageError::ApprovalNotFound)
        );
    }

    fn standing_grant(scope: &str) -> ApprovalRecord {
        ApprovalRecord::new_standing(
            "approval-standing-1",
            "standing:filesystem_write:C:/workspace",
            Capability::new(
                rocky_domain::CapabilityKind::FilesystemWrite,
                scope.to_string(),
            )
            .expect("valid test capability"),
            1_000,
        )
        .expect("valid test approval")
    }

    #[test]
    fn in_memory_standing_grants_list_separately() {
        let mut store = InMemoryTaskStore::default();
        store
            .save_approval(approval("C:/workspace"))
            .expect("save approval");
        store
            .save_approval(standing_grant("C:/workspace"))
            .expect("save standing grant");

        let standing = store.standing_approvals().expect("standing query");
        assert_eq!(standing.len(), 1);
        assert!(standing[0].standing);
    }

    #[test]
    fn sqlite_standing_grants_round_trip_with_their_flag() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        store
            .save_approval(approval("C:/workspace"))
            .expect("save approval");
        store
            .save_approval(standing_grant("C:/workspace"))
            .expect("save standing grant");

        let stored = store
            .get_approval("standing:filesystem_write:C:/workspace")
            .expect("approval query")
            .expect("stored approval");
        assert!(stored.standing);
        let plain = store
            .get_approval("hash-1")
            .expect("approval query")
            .expect("stored approval");
        assert!(!plain.standing);
        let standing = store.standing_approvals().expect("standing query");
        assert_eq!(standing.len(), 1);
    }

    #[test]
    fn old_version3_files_gain_the_standing_column_on_open() {
        let path = std::env::temp_dir().join(format!("rocky-migrate-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            // Simulate a database left behind by the previous release: schema
            // version 3 whose approvals table has no standing column.
            let connection = rusqlite::Connection::open(&path).expect("open migration fixture");
            connection
                .execute_batch(
                    "CREATE TABLE tasks (
                        id TEXT PRIMARY KEY NOT NULL,
                        user_goal TEXT NOT NULL,
                        state TEXT NOT NULL,
                        revision INTEGER NOT NULL
                     );
                     CREATE TABLE audit_events (
                        task_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        actor TEXT NOT NULL,
                        action TEXT NOT NULL,
                        autonomy_level TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        PRIMARY KEY (task_id, sequence)
                     );
                     CREATE TABLE approvals (
                        id TEXT PRIMARY KEY NOT NULL,
                        action_hash TEXT NOT NULL UNIQUE,
                        capability_kind TEXT NOT NULL,
                        capability_scope TEXT NOT NULL,
                        expires_at INTEGER NOT NULL,
                        revoked INTEGER NOT NULL
                     );
                     CREATE TABLE evidence (
                        id TEXT PRIMARY KEY NOT NULL,
                        task_id TEXT NOT NULL,
                        tool_id TEXT NOT NULL,
                        digest TEXT NOT NULL,
                        bytes BLOB NOT NULL
                     );
                     PRAGMA user_version = 3;",
                )
                .expect("write old schema");
        }

        let mut store = SqliteTaskStore::open(&path).expect("migrated open");
        store
            .save_approval(standing_grant("C:/workspace"))
            .expect("save standing grant");
        let stored = store
            .get_approval("standing:filesystem_write:C:/workspace")
            .expect("approval query")
            .expect("stored approval");
        assert!(stored.standing);
        assert_eq!(store.standing_approvals().expect("standing query").len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    fn finding_artifacts() -> Vec<String> {
        vec![
            "config.toml".to_string(),
            "weird\nname \x00-free".to_string(),
        ]
    }

    #[test]
    fn findings_round_trip_with_artifacts_intact() {
        let mut store = InMemoryTaskStore::default();
        let record = store
            .post_finding(
                "f-1",
                "task-1",
                "researcher",
                "The port is pinned",
                "evidence:config.toml:12",
                80,
                finding_artifacts(),
                "Restart with the pinned port",
            )
            .expect("post finding");

        assert_eq!(record.id, "f-1");
        assert_eq!(record.confidence_pct, 80);
        let stored = store
            .finding("f-1")
            .expect("finding query")
            .expect("stored finding");
        // Artifacts ride in their own rows, so hostile content survives
        // byte-for-byte instead of through an escaping scheme.
        assert_eq!(stored.affected_artifacts, finding_artifacts());
        let listed = store.findings_for_task("task-1").expect("task query");
        assert_eq!(listed.len(), 1);
        assert!(
            store
                .findings_for_task("task-2")
                .expect("task query")
                .is_empty()
        );
        assert!(store.finding("missing").expect("finding query").is_none());
    }

    #[test]
    fn findings_reject_blank_fields_and_duplicates() {
        let mut store = InMemoryTaskStore::default();
        assert_eq!(
            store.post_finding("f-1", "task-1", "  ", "h", "e", 50, vec![], "a"),
            Err(StorageError::EmptyFindingText)
        );
        store
            .post_finding("f-1", "task-1", "r", "h", "e", 50, vec![], "a")
            .expect("post finding");
        assert_eq!(
            store.post_finding("f-1", "task-1", "r", "h", "e", 50, vec![], "a"),
            Err(StorageError::DuplicateFinding)
        );
        assert_eq!(
            store.post_finding(
                "f-2",
                "task-1",
                "r",
                "h",
                "e",
                50,
                vec!["a".to_string(); MAX_FINDING_ARTIFACTS + 1],
                "a"
            ),
            Err(StorageError::TooManyFindingArtifacts)
        );
    }

    #[test]
    fn sqlite_findings_match_in_memory_parity() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        store
            .post_finding(
                "f-1",
                "task-1",
                "researcher",
                "The port is pinned",
                "evidence:config.toml:12",
                80,
                finding_artifacts(),
                "Restart with the pinned port",
            )
            .expect("post finding");

        let stored = store
            .finding("f-1")
            .expect("finding query")
            .expect("stored finding");
        assert_eq!(stored.affected_artifacts, finding_artifacts());
        assert_eq!(
            store.findings_for_task("task-1").expect("task query").len(),
            1
        );
    }

    #[test]
    fn findings_reject_posts_beyond_the_per_task_cap() {
        let mut store = InMemoryTaskStore::default();
        for index in 0..MAX_FINDINGS_PER_TASK {
            store
                .post_finding(
                    &format!("f-{index}"),
                    "task-1",
                    "researcher",
                    "hypothesis",
                    "evidence",
                    50,
                    vec![],
                    "action",
                )
                .expect("post finding");
        }
        assert_eq!(
            store.post_finding("f-over", "task-1", "r", "h", "e", 50, vec![], "a"),
            Err(StorageError::FindingStoreFull)
        );
        assert!(
            store
                .post_finding("f-other", "task-2", "r", "h", "e", 50, vec![], "a")
                .is_ok()
        );
    }

    #[test]
    fn audit_trail_reads_back_what_the_gate_wrote() {
        let store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        let first = AuditEvent {
            sequence: 1,
            task_id: "task-1".into(),
            actor: "runtime".into(),
            action: "filesystem.read".into(),
            autonomy_level: AutonomyLevel::A0,
            outcome: AuditOutcome::Approved,
        };
        let second = AuditEvent {
            sequence: 2,
            task_id: "task-1".into(),
            actor: "runtime".into(),
            action: "filesystem.write".into(),
            autonomy_level: AutonomyLevel::A3,
            outcome: AuditOutcome::ApprovalRequired,
        };
        store.append_audit(&first).expect("append first");
        store.append_audit(&second).expect("append second");

        assert_eq!(
            store.audit_events("task-1").expect("audit query"),
            vec![first, second]
        );
        assert!(
            store
                .audit_events("task-2")
                .expect("audit query")
                .is_empty()
        );
    }

    fn contract() -> GoalContract {
        GoalContract::new("task-1", "Read a document", vec!["read-only".into()])
            .expect("valid test contract")
    }

    #[test]
    fn contracts_round_trip_with_constraints_intact() {
        let mut store = InMemoryTaskStore::default();
        store.save_contract(&contract()).expect("save contract");

        let stored = store
            .load_contract("task-1")
            .expect("contract query")
            .expect("stored contract");
        assert_eq!(stored, contract());
        assert!(
            store
                .load_contract("task-2")
                .expect("contract query")
                .is_none()
        );
        assert_eq!(
            store.save_contract(&contract()),
            Err(StorageError::DuplicateContract)
        );
    }

    #[test]
    fn sqlite_contracts_match_in_memory_parity() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        store.save_contract(&contract()).expect("save contract");

        let stored = store
            .load_contract("task-1")
            .expect("contract query")
            .expect("stored contract");
        assert_eq!(stored, contract());
        assert_eq!(
            store.save_contract(&contract()),
            Err(StorageError::DuplicateContract)
        );
    }

    #[test]
    fn task_listing_shows_every_task_in_id_order() {
        let mut store = InMemoryTaskStore::default();
        assert!(store.list_tasks().expect("list").is_empty());
        for id in ["task-b", "task-a", "task-c"] {
            store
                .create(TaskRecord::new(id, "goal").expect("valid task"))
                .expect("create task");
        }

        let listed = store.list_tasks().expect("list tasks");
        let ids: Vec<&str> = listed.iter().map(|task| task.id.as_str()).collect();
        assert_eq!(ids, vec!["task-a", "task-b", "task-c"]);
    }

    #[test]
    fn sqlite_task_listing_matches_in_memory_parity() {
        let mut store = SqliteTaskStore::open_in_memory().expect("in-memory database");
        for id in ["task-b", "task-a"] {
            store
                .create(TaskRecord::new(id, "goal").expect("valid task"))
                .expect("create task");
        }

        let listed = store.list_tasks().expect("list tasks");
        let ids: Vec<&str> = listed.iter().map(|task| task.id.as_str()).collect();
        assert_eq!(ids, vec!["task-a", "task-b"]);
    }
}
