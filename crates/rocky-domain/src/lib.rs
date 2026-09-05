//! Pure domain types shared by ROCKY subsystems.
//!
//! This crate deliberately contains no operating-system, model-provider, or UI access.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A cheap, cloneable signal for cooperative cancellation.
///
/// This is the single cancellation currency shared by workers, the gate,
/// and executors: cancelling one handle is visible everywhere its clones
/// travel, so revoking work stops in-flight execution at the next boundary.
/// The flag carries no authority and performs no I/O; owners must still drop
/// or await the underlying work.
#[derive(Clone, Debug, Default)]
pub struct CancelFlag {
    flag: Arc<AtomicBool>,
}

impl CancelFlag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Idempotent and safe to call multiple times.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// The autonomy level required for an operation.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AutonomyLevel {
    /// Observe or read only.
    A0,
    /// Safe, reversible action.
    A1,
    /// A write or change that policy may approve.
    A2,
    /// Consequential action that requires explicit confirmation.
    A3,
    /// An operation that is forbidden.
    A4,
}

/// A structured kind of external authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityKind {
    FilesystemRead,
    FilesystemWrite,
    ProcessExecute,
    NetworkConnect,
    BrowserInteract,
}

/// A capability and its narrowly scoped target.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Capability {
    pub kind: CapabilityKind,
    pub scope: String,
}

impl Capability {
    /// Creates a capability when its scope is non-empty and contains no NUL byte.
    pub fn new(kind: CapabilityKind, scope: impl Into<String>) -> Result<Self, DomainError> {
        let scope = scope.into();
        if scope.trim().is_empty() {
            return Err(DomainError::EmptyScope);
        }
        if scope.contains('\0') {
            return Err(DomainError::InvalidScope);
        }
        Ok(Self { kind, scope })
    }
}

/// The lifecycle of a user task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    Created,
    Planned,
    Running,
    WaitingForApproval,
    Completed,
    Failed,
    Cancelled,
}

impl TaskState {
    /// Validates and applies a state transition.
    pub fn transition(self, next: Self) -> Result<Self, DomainError> {
        use TaskState::*;
        let valid = matches!(
            (self, next),
            (Created, Planned | Cancelled)
                | (Planned, Running | Cancelled)
                | (Running, WaitingForApproval | Completed | Failed | Cancelled)
                | (WaitingForApproval, Running | Failed | Cancelled)
        );
        if valid {
            Ok(next)
        } else {
            Err(DomainError::InvalidTaskTransition {
                from: self,
                to: next,
            })
        }
    }
}

/// Computes a stable FNV-1a hex digest over byte chunks.
///
/// Used for content-addressed references (evidence digests, action hashes).
/// FNV-1a is chosen over the default hasher so digests stay identical across
/// compiler versions and persisted references keep matching. This is an
/// integrity reference, not a cryptographic commitment: it binds bytes to a
/// short name, it does not authenticate them.
pub fn content_digest(chunks: &[&[u8]]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for chunk in chunks {
        for byte in chunk.iter() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{hash:016x}")
}

/// A persisted user approval for one hashed action.
///
/// The caller supplies the current time when checking validity, so approval
/// checks perform no clock reads and stay testable. An approval is usable
/// only while it is not revoked and `now_unix_secs` is strictly before expiry.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApprovalRecord {
    pub id: String,
    pub action_hash: String,
    pub capability: Capability,
    pub expires_at_unix_secs: u64,
    pub revoked: bool,
    /// A standing approval authorizes any future action its capability scope
    /// covers, instead of exactly one hashed action. It is the "trust this
    /// area" grant: broader by design, so it must always carry a short,
    /// explicit expiry and stay revocable like any other approval.
    pub standing: bool,
}

impl ApprovalRecord {
    /// Creates an approval that must expire: a zero expiry is rejected so
    /// approvals can never be accidentally unbounded.
    pub fn new(
        id: impl Into<String>,
        action_hash: impl Into<String>,
        capability: Capability,
        expires_at_unix_secs: u64,
    ) -> Result<Self, DomainError> {
        let id = id.into();
        let action_hash = action_hash.into();
        if id.trim().is_empty() {
            return Err(DomainError::EmptyApprovalId);
        }
        if action_hash.trim().is_empty() {
            return Err(DomainError::EmptyActionHash);
        }
        if expires_at_unix_secs == 0 {
            return Err(DomainError::InvalidApprovalExpiry);
        }
        Ok(Self {
            id,
            action_hash,
            capability,
            expires_at_unix_secs,
            revoked: false,
            standing: false,
        })
    }

    /// Creates a standing area-trust grant with the same validation as a
    /// single-action approval. Callers must pass a scope-derived canonical
    /// hash (see the runtime's standing-grant helper) so re-trusting one
    /// scope collides loudly instead of stacking duplicate grants.
    pub fn new_standing(
        id: impl Into<String>,
        action_hash: impl Into<String>,
        capability: Capability,
        expires_at_unix_secs: u64,
    ) -> Result<Self, DomainError> {
        let mut record = Self::new(id, action_hash, capability, expires_at_unix_secs)?;
        record.standing = true;
        Ok(record)
    }

    /// Returns true only when the approval is unrevoked and unexpired.
    pub fn is_valid_at(&self, now_unix_secs: u64) -> bool {
        !self.revoked && now_unix_secs < self.expires_at_unix_secs
    }
}

/// Maximum constraints per goal contract. Constraints are short scope and
/// policy notes, not documents: a longer list belongs in task findings.
pub const MAX_CONSTRAINTS: usize = 16;

/// A frozen goal contract: the task's goal plus its constraints, fixed before
/// planning starts and immutable afterwards.
///
/// Fields are private with read-only accessors, so freezing is enforced by
/// construction rather than convention: no caller can widen the goal or drop
/// a constraint mid-task. Sessions take the contract itself as input, which
/// keeps the persisted goal identical to the frozen one by construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoalContract {
    task_id: String,
    goal: String,
    constraints: Vec<String>,
}

impl GoalContract {
    pub fn new(
        task_id: impl Into<String>,
        goal: impl Into<String>,
        constraints: Vec<String>,
    ) -> Result<Self, DomainError> {
        let task_id = task_id.into();
        let goal = goal.into();
        if task_id.trim().is_empty() {
            return Err(DomainError::EmptyTaskId);
        }
        if goal.trim().is_empty() {
            return Err(DomainError::EmptyGoal);
        }
        if constraints.len() > MAX_CONSTRAINTS {
            return Err(DomainError::TooManyConstraints);
        }
        if constraints.iter().any(|item| item.trim().is_empty()) {
            return Err(DomainError::EmptyConstraint);
        }
        Ok(Self {
            task_id,
            goal,
            constraints,
        })
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn goal(&self) -> &str {
        &self.goal
    }

    pub fn constraints(&self) -> &[String] {
        &self.constraints
    }
}

/// A domain validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    EmptyScope,
    InvalidScope,
    EmptyApprovalId,
    EmptyActionHash,
    InvalidApprovalExpiry,
    EmptyTaskId,
    EmptyGoal,
    EmptyConstraint,
    TooManyConstraints,
    InvalidTaskTransition { from: TaskState, to: TaskState },
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScope => write!(formatter, "capability scope must not be empty"),
            Self::InvalidScope => write!(formatter, "capability scope contains invalid characters"),
            Self::EmptyApprovalId => write!(formatter, "approval id must not be empty"),
            Self::EmptyActionHash => write!(formatter, "approval action hash must not be empty"),
            Self::InvalidApprovalExpiry => {
                write!(
                    formatter,
                    "approval expiry must be a non-zero unix timestamp"
                )
            }
            Self::EmptyTaskId => write!(formatter, "task id must not be empty"),
            Self::EmptyGoal => write!(formatter, "task goal must not be empty"),
            Self::EmptyConstraint => write!(formatter, "goal constraint must not be empty"),
            Self::TooManyConstraints => write!(formatter, "goal has too many constraints"),
            Self::InvalidTaskTransition { from, to } => {
                write!(formatter, "invalid task transition from {from:?} to {to:?}")
            }
        }
    }
}

impl std::error::Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_empty_capability_scope() {
        assert_eq!(
            Capability::new(CapabilityKind::FilesystemRead, " "),
            Err(DomainError::EmptyScope)
        );
    }

    #[test]
    fn prevents_terminal_tasks_from_restarting() {
        assert_eq!(
            TaskState::Completed.transition(TaskState::Running),
            Err(DomainError::InvalidTaskTransition {
                from: TaskState::Completed,
                to: TaskState::Running,
            })
        );
    }

    #[test]
    fn approvals_require_a_bounded_expiry() {
        let capability = Capability::new(CapabilityKind::FilesystemWrite, "C:/workspace")
            .expect("valid test capability");
        assert_eq!(
            ApprovalRecord::new("approval-1", "hash-1", capability, 0),
            Err(DomainError::InvalidApprovalExpiry)
        );
    }

    #[test]
    fn approvals_are_valid_only_while_unrevoked_and_unexpired() {
        let capability = Capability::new(CapabilityKind::FilesystemWrite, "C:/workspace")
            .expect("valid test capability");
        let mut approval = ApprovalRecord::new("approval-1", "hash-1", capability, 1_000)
            .expect("valid test approval");

        assert!(approval.is_valid_at(999));
        assert!(!approval.is_valid_at(1_000));
        approval.revoked = true;
        assert!(!approval.is_valid_at(999));
    }

    #[test]
    fn standing_grants_carry_their_flag() {
        let capability = Capability::new(CapabilityKind::FilesystemWrite, "C:/workspace")
            .expect("valid test capability");
        let single = ApprovalRecord::new("a-1", "hash-1", capability.clone(), 1_000)
            .expect("valid test approval");
        let standing = ApprovalRecord::new_standing("a-2", "hash-2", capability, 1_000)
            .expect("valid test approval");

        assert!(!single.standing);
        assert!(standing.standing);
        assert!(standing.is_valid_at(999));
    }

    fn contract() -> GoalContract {
        GoalContract::new("task-1", "Summarize this file", vec!["read-only".into()])
            .expect("valid test contract")
    }

    #[test]
    fn goal_contract_freezes_its_inputs() {
        let contract = contract();
        assert_eq!(contract.task_id(), "task-1");
        assert_eq!(contract.goal(), "Summarize this file");
        assert_eq!(contract.constraints(), &["read-only".to_string()]);
    }

    #[test]
    fn goal_contracts_reject_blank_core_fields() {
        assert_eq!(
            GoalContract::new("  ", "goal", vec![]),
            Err(DomainError::EmptyTaskId)
        );
        assert_eq!(
            GoalContract::new("task-1", "  ", vec![]),
            Err(DomainError::EmptyGoal)
        );
        assert_eq!(
            GoalContract::new("task-1", "goal", vec!["  ".into()]),
            Err(DomainError::EmptyConstraint)
        );
    }

    #[test]
    fn goal_contracts_bound_their_constraint_list() {
        let constraints = vec!["c".to_string(); MAX_CONSTRAINTS + 1];
        assert_eq!(
            GoalContract::new("task-1", "goal", constraints),
            Err(DomainError::TooManyConstraints)
        );
    }

    #[test]
    fn content_digest_is_stable_and_content_bound() {
        assert_eq!(content_digest(&[b"rocky"]), content_digest(&[b"rocky"]));
        assert_eq!(content_digest(&[b"a", b"b"]), content_digest(&[b"ab"]));
        assert_ne!(content_digest(&[b"rocky"]), content_digest(&[b"Rocky"]));
        assert_ne!(content_digest(&[b"rocky"]), content_digest(&[b"rocky!"]));
        assert_eq!(content_digest(&[]).len(), 16);
    }

    #[test]
    fn cancel_flags_share_state_across_clones() {
        let flag = CancelFlag::new();
        let shared = flag.clone();

        assert!(!flag.is_cancelled());
        assert!(!shared.is_cancelled());
        flag.cancel();
        assert!(shared.is_cancelled());
        // Cancelling twice is harmless.
        flag.cancel();
        assert!(flag.is_cancelled());
    }
}
