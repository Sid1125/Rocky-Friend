//! Approval UI decisions: applying user approve/deny commands to the store.
//!
//! The UI speaks in [`IpcCommand`]s carrying only an action hash. This module
//! binds each decision to a capability and a bounded expiry at application
//! time, so a well-formed but unauthorized command can never mint authority
//! by itself: approvals still pass the gate's hash, scope, expiry, and
//! revocation checks before any permit issues.

use rocky_domain::{ApprovalRecord, Capability};
use rocky_ipc::{CommandPayload, IpcCommand};
use rocky_storage::{ApprovalStore, StorageError};
use std::fmt;

/// Applies an `ApproveAction` command: persists a bounded approval binding
/// the command's action hash to the caller-supplied capability.
///
/// The expiry must lie strictly after `now`: an already-expired approval is
/// rejected instead of stored. The returned record is immediately usable by
/// [`crate::RuntimeGate::issue_permit_with_approval`].
pub fn approve_command_decision(
    store: &mut impl ApprovalStore,
    command: &IpcCommand,
    capability: &Capability,
    now_unix_secs: u64,
    expires_at_unix_secs: u64,
) -> Result<ApprovalRecord, DecisionError> {
    let CommandPayload::ApproveAction { action_hash } = &command.payload else {
        return Err(DecisionError::WrongCommand);
    };
    if expires_at_unix_secs <= now_unix_secs {
        return Err(DecisionError::ExpiredExpiry);
    }
    let record = ApprovalRecord::new(
        format!("approval-{action_hash}"),
        action_hash.clone(),
        capability.clone(),
        expires_at_unix_secs,
    )?;
    store.save_approval(record.clone())?;
    Ok(record)
}

/// Applies a `DenyAction` command: revokes any approval for the command's
/// action hash. Returns whether an approval was actually revoked, so callers
/// can distinguish "denied and retracted" from "there was nothing to deny".
///
/// A deny retracts the exact-hash approval only. Standing area-trust grants
/// are deliberately untouched: withdrawing broad trust is a separate,
/// explicit act (revoke the grant's canonical hash), never a side effect of
/// refusing one action.
pub fn deny_command_decision(
    store: &mut impl ApprovalStore,
    command: &IpcCommand,
) -> Result<bool, DecisionError> {
    let CommandPayload::DenyAction { action_hash } = &command.payload else {
        return Err(DecisionError::WrongCommand);
    };
    match store.revoke_approval(action_hash) {
        Ok(()) => Ok(true),
        Err(StorageError::ApprovalNotFound) => Ok(false),
        Err(error) => Err(DecisionError::Storage(error)),
    }
}

/// Revokes an approval and stops its worker in one order.
///
/// Deny validation runs first, so a malformed command touches neither the
/// store nor the worker. Then the approval is revoked and the worker is
/// cancelled: revocation without stopping leaves in-flight execution holding
/// a just-killed permission's momentum, and stopping without revoking
/// leaves the permission live for the next attempt. An already-terminal
/// worker is already stopped, which satisfies — not errors — the order.
/// Returns whether an approval was actually retracted.
pub fn revoke_and_stop(
    store: &mut impl ApprovalStore,
    command: &IpcCommand,
    worker: &mut rocky_agents::Worker,
) -> Result<bool, DecisionError> {
    let revoked = deny_command_decision(store, command)?;
    let _ = worker.cancel();
    Ok(revoked)
}
///
/// Scope-derived rather than action-derived, so re-trusting one scope
/// collides on save instead of stacking duplicate grants. The gate never
/// compares this hash against actions; it authorizes by scope coverage.
/// Canonical hash for a standing area-trust grant over a capability.
pub fn standing_grant_hash(capability: &Capability) -> String {
    use rocky_domain::CapabilityKind as Kind;
    let kind = match capability.kind {
        Kind::FilesystemRead => "filesystem_read",
        Kind::FilesystemWrite => "filesystem_write",
        Kind::ProcessExecute => "process_execute",
        Kind::NetworkConnect => "network_connect",
        Kind::BrowserInteract => "browser_interact",
    };
    format!("standing:{kind}:{}", capability.scope)
}

/// Applies an `ApproveAction` command as standing area trust: persists a
/// scope-bound grant the gate accepts for any covered future action until
/// its expiry. The command's own action hash is only checked for variant
/// shape; the stored grant carries the canonical scope hash.
pub fn approve_standing_decision(
    store: &mut impl ApprovalStore,
    command: &IpcCommand,
    capability: &Capability,
    now_unix_secs: u64,
    expires_at_unix_secs: u64,
) -> Result<ApprovalRecord, DecisionError> {
    if !matches!(command.payload, CommandPayload::ApproveAction { .. }) {
        return Err(DecisionError::WrongCommand);
    }
    if expires_at_unix_secs <= now_unix_secs {
        return Err(DecisionError::ExpiredExpiry);
    }
    let hash = standing_grant_hash(capability);
    let record = ApprovalRecord::new_standing(
        format!("approval-{hash}"),
        hash,
        capability.clone(),
        expires_at_unix_secs,
    )?;
    store.save_approval(record.clone())?;
    Ok(record)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecisionError {
    WrongCommand,
    ExpiredExpiry,
    Domain(rocky_domain::DomainError),
    Storage(StorageError),
}

impl fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "approval decision error: {self:?}")
    }
}

impl std::error::Error for DecisionError {}

impl From<rocky_domain::DomainError> for DecisionError {
    fn from(error: rocky_domain::DomainError) -> Self {
        Self::Domain(error)
    }
}

impl From<StorageError> for DecisionError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_domain::{ApprovalRecord, Capability, CapabilityKind};
    use rocky_ipc::{CommandPayload, IpcCommand};
    use rocky_storage::{ApprovalStore, InMemoryTaskStore};

    fn capability() -> Capability {
        Capability::new(CapabilityKind::FilesystemWrite, "C:/workspace")
            .expect("valid test capability")
    }

    fn approve_command() -> IpcCommand {
        IpcCommand::new(
            "cmd-1",
            "task-1",
            CommandPayload::ApproveAction {
                action_hash: "abc123".into(),
            },
        )
        .expect("valid command")
    }

    fn deny_command() -> IpcCommand {
        IpcCommand::new(
            "cmd-2",
            "task-1",
            CommandPayload::DenyAction {
                action_hash: "abc123".into(),
            },
        )
        .expect("valid command")
    }

    #[test]
    fn approve_persists_a_bounded_usable_approval() {
        let mut store = InMemoryTaskStore::default();
        let record =
            approve_command_decision(&mut store, &approve_command(), &capability(), 999, 1_000)
                .expect("approve decision");

        assert_eq!(record.action_hash, "abc123");
        assert_eq!(record.expires_at_unix_secs, 1_000);
        assert!(record.is_valid_at(999));
        assert!(store.is_approved("abc123", 999).expect("validity query"));
    }

    #[test]
    fn approve_rejects_an_already_expired_expiry() {
        let mut store = InMemoryTaskStore::default();
        assert_eq!(
            approve_command_decision(&mut store, &approve_command(), &capability(), 1_000, 1_000),
            Err(DecisionError::ExpiredExpiry)
        );
        assert!(
            store
                .get_approval("abc123")
                .expect("approval query")
                .is_none()
        );
    }

    #[test]
    fn approve_rejects_a_non_approval_command() {
        let mut store = InMemoryTaskStore::default();
        let cancel =
            IpcCommand::new("cmd-3", "task-1", CommandPayload::CancelTask).expect("valid command");
        assert_eq!(
            approve_command_decision(&mut store, &cancel, &capability(), 999, 1_000),
            Err(DecisionError::WrongCommand)
        );
    }

    #[test]
    fn deny_revokes_an_existing_approval() {
        let mut store = InMemoryTaskStore::default();
        approve_command_decision(&mut store, &approve_command(), &capability(), 999, 1_000)
            .expect("approve decision");

        assert_eq!(deny_command_decision(&mut store, &deny_command()), Ok(true));
        assert!(!store.is_approved("abc123", 999).expect("validity query"));
    }

    #[test]
    fn approve_twice_never_silently_overwrites() {
        use rocky_storage::StorageError;

        let mut store = InMemoryTaskStore::default();
        approve_command_decision(&mut store, &approve_command(), &capability(), 999, 1_000)
            .expect("first approve");
        // The second approve for the same action fails loudly instead of
        // resetting the expiry behind the user's back.
        assert_eq!(
            approve_command_decision(&mut store, &approve_command(), &capability(), 999, 2_000),
            Err(DecisionError::Storage(StorageError::DuplicateApproval))
        );
        let stored = store
            .get_approval("abc123")
            .expect("approval query")
            .expect("stored approval");
        assert_eq!(stored.expires_at_unix_secs, 1_000);
    }

    #[test]
    fn deny_without_an_approval_is_a_quiet_no() {
        let mut store = InMemoryTaskStore::default();
        assert_eq!(
            deny_command_decision(&mut store, &deny_command()),
            Ok(false)
        );
    }

    #[test]
    fn deny_rejects_a_non_deny_command() {
        let mut store = InMemoryTaskStore::default();
        assert_eq!(
            deny_command_decision(&mut store, &approve_command()),
            Err(DecisionError::WrongCommand)
        );
    }

    #[test]
    fn standing_grant_hash_is_scope_derived() {
        assert_eq!(
            standing_grant_hash(&capability()),
            "standing:filesystem_write:C:/workspace"
        );
    }

    #[test]
    fn approve_standing_persists_a_gate_usable_grant() {
        use crate::{ExecutionDecision, ResourceMode, RuntimeGate};
        use rocky_domain::{AutonomyLevel, CapabilityKind};
        use rocky_resources::ResourceGovernor;
        use rocky_tools::{ToolBroker, ToolDefinition, ToolRequest};

        let mut store = InMemoryTaskStore::default();
        let record =
            approve_standing_decision(&mut store, &approve_command(), &capability(), 999, 1_000)
                .expect("approve standing");
        assert!(record.standing);

        // The persisted grant authorizes a covered future action by scope.
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.write",
                    rocky_domain::Capability::new(CapabilityKind::FilesystemWrite, "C:/workspace")
                        .expect("valid test capability"),
                    AutonomyLevel::A3,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));
        let mut policy = rocky_policy::Policy::deny_all(AutonomyLevel::A3);
        policy.grant(capability());
        let request = ToolRequest {
            tool_id: "filesystem.write".into(),
            requested_capability: rocky_domain::Capability::new(
                CapabilityKind::FilesystemWrite,
                "C:/workspace/other.txt",
            )
            .expect("valid test capability"),
            arguments: Vec::new(),
        };
        let standing = store.standing_approvals().expect("standing query");
        assert!(matches!(
            gate.issue_permit_with_standing_approval(
                "task-9",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                &standing,
                999,
                &crate::CancellationToken::new(),
            )
            .expect("standing pipeline runs"),
            ExecutionDecision::Permitted(_)
        ));
    }

    #[test]
    fn approve_standing_rejects_a_non_approval_command() {
        let mut store = InMemoryTaskStore::default();
        let cancel =
            IpcCommand::new("cmd-3", "task-1", CommandPayload::CancelTask).expect("valid command");
        assert_eq!(
            approve_standing_decision(&mut store, &cancel, &capability(), 999, 1_000),
            Err(DecisionError::WrongCommand)
        );
    }

    fn running_worker() -> rocky_agents::Worker {
        let scheduler = rocky_agents::AgentScheduler::new(rocky_agents::AgentLimits {
            max_active: 3,
            max_depth: 1,
            max_steps: 10,
        });
        let spec = scheduler
            .admit(0, "scout", 1, 5, 1000)
            .expect("valid test spec");
        let mut worker =
            rocky_agents::Worker::new("w-1", "task-1", spec).expect("valid test worker");
        worker.enqueue().expect("enqueue worker");
        worker.start(100).expect("start worker");
        worker
    }

    fn approval_for_deny() -> (InMemoryTaskStore, IpcCommand) {
        let mut store = InMemoryTaskStore::default();
        let approval = ApprovalRecord::new("approval-1", "abc123", capability(), 1_000)
            .expect("valid test approval");
        store.save_approval(approval).expect("save approval");
        (
            store,
            IpcCommand::new(
                "cmd-2",
                "task-1",
                CommandPayload::DenyAction {
                    action_hash: "abc123".into(),
                },
            )
            .expect("valid command"),
        )
    }

    #[test]
    fn revoke_and_stop_retracts_and_halts() {
        let (mut store, deny) = approval_for_deny();
        let mut worker = running_worker();

        assert_eq!(revoke_and_stop(&mut store, &deny, &mut worker), Ok(true));
        assert!(!store.is_approved("abc123", 999).expect("validity"));
        assert_eq!(worker.state(), rocky_agents::WorkerState::Cancelled);
        assert!(worker.is_cancelled());
    }

    #[test]
    fn revoke_and_stop_halts_even_without_an_approval() {
        let mut store = InMemoryTaskStore::default();
        let (_, deny) = approval_for_deny();
        let mut worker = running_worker();

        // Nothing to revoke, but the worker still stops: a deny is a stop
        // order for the work, not just paperwork for the approval.
        assert_eq!(revoke_and_stop(&mut store, &deny, &mut worker), Ok(false));
        assert_eq!(worker.state(), rocky_agents::WorkerState::Cancelled);
    }

    #[test]
    fn revoke_and_stop_validates_before_touching_anything() {
        let (mut store, _) = approval_for_deny();
        let mut worker = running_worker();
        let cancel =
            IpcCommand::new("cmd-3", "task-1", CommandPayload::CancelTask).expect("valid command");

        assert_eq!(
            revoke_and_stop(&mut store, &cancel, &mut worker),
            Err(DecisionError::WrongCommand)
        );
        assert_eq!(worker.state(), rocky_agents::WorkerState::Running);
        assert!(!worker.is_cancelled());
        assert!(store.is_approved("abc123", 999).expect("validity"));
    }
}
