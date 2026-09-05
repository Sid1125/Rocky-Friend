//! Composition root for policy, resource, tool-contract, and audit guards.
//!
//! The runtime intentionally stops at authorization. Executor adapters belong at the edge and
//! must consume only an approved outcome.

use rocky_audit::{AuditLog, AuditOutcome};
use rocky_domain::{ApprovalRecord, Capability, content_digest};
use rocky_policy::{Policy, PolicyDecision, scope_covers};
use rocky_resources::{Admission, ResourceGovernor, ResourceMode};
use rocky_tools::{ToolBroker, ToolError, ToolRequest};

/// The gate's cancellation handle. A re-export of the domain's shared flag,
/// so workers, the gate, and executors observe one signal: the name stays
/// for existing call sites, the currency is shared.
pub use rocky_domain::CancelFlag as CancellationToken;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeOutcome {
    Approved,
    ApprovalRequired,
    QueuedForResources,
    RejectedForResources,
    Denied,
    Cancelled,
}

/// A runtime-issued authorization token. Its fields are private, so only this crate can create it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionPermit {
    task_id: String,
    tool_id: String,
    requested_capability: Capability,
    granted_capability: Capability,
    arguments: Vec<String>,
}

impl ExecutionPermit {
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn tool_id(&self) -> &str {
        &self.tool_id
    }

    pub fn requested_capability(&self) -> &Capability {
        &self.requested_capability
    }

    pub fn granted_capability(&self) -> &Capability {
        &self.granted_capability
    }

    /// The exact brokered arguments. Executors must run byte-for-byte these
    /// and nothing else; any substitution is a broken chain.
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionDecision {
    Permitted(ExecutionPermit),
    ApprovalRequired,
    QueuedForResources,
    RejectedForResources,
    Denied,
    Cancelled,
}

/// UI-facing autonomy tier for a decision: green ran, orange waits on the
/// user or resources, red is stopped. Tiers describe friction only; the
/// decision itself stays the enforcement record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutonomyTier {
    Green,
    Orange,
    Red,
}

impl ExecutionDecision {
    pub fn tier(&self) -> AutonomyTier {
        match self {
            Self::Permitted(_) => AutonomyTier::Green,
            Self::ApprovalRequired | Self::QueuedForResources => AutonomyTier::Orange,
            Self::RejectedForResources | Self::Denied | Self::Cancelled => AutonomyTier::Red,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    Tool(ToolError),
    PolicyInconsistency,
}

impl From<ToolError> for RuntimeError {
    fn from(error: ToolError) -> Self {
        Self::Tool(error)
    }
}

/// Coordinates the mandatory pre-execution checks for a proposed tool invocation.
pub struct RuntimeGate {
    broker: ToolBroker,
    governor: ResourceGovernor,
    audit: AuditLog,
}

pub mod boards;
pub mod decisions;
pub mod driver;
pub mod session;

impl RuntimeGate {
    pub fn new(broker: ToolBroker, governor: ResourceGovernor) -> Self {
        Self {
            broker,
            governor,
            audit: AuditLog::default(),
        }
    }

    /// Evaluates policy first, then resource availability, and audits every outcome.
    ///
    /// A cancelled token stops the tool before any policy or resource check.
    pub fn evaluate_tool(
        &mut self,
        task_id: &str,
        active_workers: usize,
        resource_mode: ResourceMode,
        request: &ToolRequest,
        policy: &Policy,
        cancellation: &CancellationToken,
    ) -> Result<RuntimeOutcome, ToolError> {
        let autonomy_level = self.broker.autonomy_level(request)?;
        if cancellation.is_cancelled() {
            self.audit.append(
                task_id,
                "runtime",
                &request.tool_id,
                autonomy_level,
                AuditOutcome::Cancelled,
            );
            return Ok(RuntimeOutcome::Cancelled);
        }
        let decision = self.broker.authorize(request, policy)?;
        let (outcome, audit_outcome) = match decision {
            PolicyDecision::Denied(_) => (RuntimeOutcome::Denied, AuditOutcome::Denied),
            PolicyDecision::RequiresApproval => (
                RuntimeOutcome::ApprovalRequired,
                AuditOutcome::ApprovalRequired,
            ),
            PolicyDecision::Approved => match self.governor.admit(resource_mode, active_workers) {
                Admission::Admit => (RuntimeOutcome::Approved, AuditOutcome::Approved),
                Admission::Queue => (RuntimeOutcome::QueuedForResources, AuditOutcome::Queued),
                Admission::Reject => (RuntimeOutcome::RejectedForResources, AuditOutcome::Denied),
            },
        };

        self.audit.append(
            task_id,
            "runtime",
            &request.tool_id,
            autonomy_level,
            audit_outcome,
        );
        Ok(outcome)
    }

    /// Issues an executor permit only after the complete policy and resource pipeline succeeds.
    pub fn issue_permit(
        &mut self,
        task_id: &str,
        active_workers: usize,
        resource_mode: ResourceMode,
        request: &ToolRequest,
        policy: &Policy,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionDecision, RuntimeError> {
        let outcome = self.evaluate_tool(
            task_id,
            active_workers,
            resource_mode,
            request,
            policy,
            cancellation,
        )?;
        self.decision_for_outcome(task_id, request, policy, outcome)
    }

    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// Consumes a persisted approval for consequential (`ApprovalRequired`) work.
    ///
    /// Stale approvals (missing, expired, revoked) leave the request waiting,
    /// so the user can re-approve. An approval bound to a different action or
    /// covering a narrower scope is denied outright as a possible replay.
    /// A valid approval still passes resource admission: approval never
    /// bypasses backpressure.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_permit_with_approval(
        &mut self,
        task_id: &str,
        active_workers: usize,
        resource_mode: ResourceMode,
        request: &ToolRequest,
        policy: &Policy,
        approval: Option<&ApprovalRecord>,
        now_unix_secs: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionDecision, RuntimeError> {
        let outcome = self.evaluate_tool(
            task_id,
            active_workers,
            resource_mode,
            request,
            policy,
            cancellation,
        )?;
        if outcome != RuntimeOutcome::ApprovalRequired {
            return self.decision_for_outcome(task_id, request, policy, outcome);
        }
        let Some(approval) = approval else {
            return Ok(ExecutionDecision::ApprovalRequired);
        };
        if !approval.is_valid_at(now_unix_secs) {
            return Ok(ExecutionDecision::ApprovalRequired);
        }
        let autonomy_level = self.broker.autonomy_level(request)?;
        if approval.action_hash
            != action_hash(
                task_id,
                &request.tool_id,
                &request.requested_capability,
                &request.arguments,
            )
            || !scope_covers(&approval.capability, &request.requested_capability)
        {
            self.audit.append(
                task_id,
                "runtime",
                &request.tool_id,
                autonomy_level,
                AuditOutcome::Denied,
            );
            return Ok(ExecutionDecision::Denied);
        }
        match self.governor.admit(resource_mode, active_workers) {
            Admission::Admit => self.admit_approved(task_id, request, policy),
            Admission::Queue => {
                self.audit.append(
                    task_id,
                    "runtime",
                    &request.tool_id,
                    autonomy_level,
                    AuditOutcome::Queued,
                );
                Ok(ExecutionDecision::QueuedForResources)
            }
            Admission::Reject => {
                self.audit.append(
                    task_id,
                    "runtime",
                    &request.tool_id,
                    autonomy_level,
                    AuditOutcome::Denied,
                );
                Ok(ExecutionDecision::RejectedForResources)
            }
        }
    }

    /// Consumes a standing area-trust grant for consequential work.
    ///
    /// Unlike an exact approval, a standing grant binds a scope rather than
    /// one action hash, so any request its capability covers may proceed
    /// without re-prompting. The guarantees stay tight: the request must
    /// still reach `ApprovalRequired` through policy (standing trust never
    /// overrides a `Denied`), the grant must be unrevoked and unexpired, and
    /// resource admission still applies. No covering grant means the request
    /// keeps waiting — inapplicable trust is not an attack, so it is never a
    /// denial.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_permit_with_standing_approval(
        &mut self,
        task_id: &str,
        active_workers: usize,
        resource_mode: ResourceMode,
        request: &ToolRequest,
        policy: &Policy,
        standing: &[ApprovalRecord],
        now_unix_secs: u64,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionDecision, RuntimeError> {
        let outcome = self.evaluate_tool(
            task_id,
            active_workers,
            resource_mode,
            request,
            policy,
            cancellation,
        )?;
        if outcome != RuntimeOutcome::ApprovalRequired {
            return self.decision_for_outcome(task_id, request, policy, outcome);
        }
        let covering = standing.iter().find(|grant| {
            grant.standing
                && grant.is_valid_at(now_unix_secs)
                && scope_covers(&grant.capability, &request.requested_capability)
        });
        let Some(_) = covering else {
            return Ok(ExecutionDecision::ApprovalRequired);
        };
        match self.governor.admit(resource_mode, active_workers) {
            Admission::Admit => self.admit_approved(task_id, request, policy),
            Admission::Queue => {
                let autonomy_level = self.broker.autonomy_level(request)?;
                self.audit.append(
                    task_id,
                    "runtime",
                    &request.tool_id,
                    autonomy_level,
                    AuditOutcome::Queued,
                );
                Ok(ExecutionDecision::QueuedForResources)
            }
            Admission::Reject => {
                let autonomy_level = self.broker.autonomy_level(request)?;
                self.audit.append(
                    task_id,
                    "runtime",
                    &request.tool_id,
                    autonomy_level,
                    AuditOutcome::Denied,
                );
                Ok(ExecutionDecision::RejectedForResources)
            }
        }
    }

    /// Builds the permit for an approved request and audits the approval.
    /// Shared by the exact-approval and standing-grant paths so both leave
    /// identical evidence.
    fn admit_approved(
        &mut self,
        task_id: &str,
        request: &ToolRequest,
        policy: &Policy,
    ) -> Result<ExecutionDecision, RuntimeError> {
        let autonomy_level = self.broker.autonomy_level(request)?;
        let decision =
            self.decision_for_outcome(task_id, request, policy, RuntimeOutcome::Approved)?;
        self.audit.append(
            task_id,
            "runtime",
            &request.tool_id,
            autonomy_level,
            AuditOutcome::Approved,
        );
        Ok(decision)
    }

    fn decision_for_outcome(
        &self,
        task_id: &str,
        request: &ToolRequest,
        policy: &Policy,
        outcome: RuntimeOutcome,
    ) -> Result<ExecutionDecision, RuntimeError> {
        let decision = match outcome {
            RuntimeOutcome::Approved => {
                let granted_capability = policy
                    .matching_grant(&request.requested_capability)
                    .ok_or(RuntimeError::PolicyInconsistency)?;
                ExecutionDecision::Permitted(ExecutionPermit {
                    task_id: task_id.into(),
                    tool_id: request.tool_id.clone(),
                    requested_capability: request.requested_capability.clone(),
                    granted_capability,
                    arguments: request.arguments.clone(),
                })
            }
            RuntimeOutcome::ApprovalRequired => ExecutionDecision::ApprovalRequired,
            RuntimeOutcome::QueuedForResources => ExecutionDecision::QueuedForResources,
            RuntimeOutcome::RejectedForResources => ExecutionDecision::RejectedForResources,
            RuntimeOutcome::Denied => ExecutionDecision::Denied,
            RuntimeOutcome::Cancelled => ExecutionDecision::Cancelled,
        };
        Ok(decision)
    }
}

/// Binds an approval to exactly one action.
///
/// Approval savers and this gate must use the same function, so an approval
/// granted for one task, tool, scope, or argument list can never authorize
/// another action. Arguments are hashed because `--dry-run` and `--force`
/// are different actions even when the program is identical.
/// FNV-1a is used instead of the default hasher so the hash is stable across
/// compiler versions and persisted approvals keep matching.
pub fn action_hash(
    task_id: &str,
    tool_id: &str,
    capability: &Capability,
    arguments: &[String],
) -> String {
    let tag = capability_kind_tag(capability);
    let mut chunks: Vec<&[u8]> = vec![
        task_id.as_bytes(),
        &[0],
        tool_id.as_bytes(),
        &[0],
        tag.as_bytes(),
        &[0],
        capability.scope.as_bytes(),
    ];
    for argument in arguments {
        chunks.push(&[0]);
        chunks.push(argument.as_bytes());
    }
    // NUL separators keep adjacent fields from running together: without
    // them ("ab","c") and ("a","bc") would hash identically.
    content_digest(&chunks)
}

fn capability_kind_tag(capability: &Capability) -> &'static str {
    use rocky_domain::CapabilityKind as Kind;
    match capability.kind {
        Kind::FilesystemRead => "filesystem_read",
        Kind::FilesystemWrite => "filesystem_write",
        Kind::ProcessExecute => "process_execute",
        Kind::NetworkConnect => "network_connect",
        Kind::BrowserInteract => "browser_interact",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_domain::ApprovalRecord;
    use rocky_domain::{AutonomyLevel, Capability, CapabilityKind};
    use rocky_tools::ToolDefinition;

    fn capability(kind: CapabilityKind, scope: &str) -> Capability {
        Capability::new(kind, scope).expect("valid test capability")
    }

    fn write_runtime() -> RuntimeGate {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.write",
                    capability(CapabilityKind::FilesystemWrite, "C:/workspace"),
                    AutonomyLevel::A3,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        RuntimeGate::new(broker, ResourceGovernor::new(3))
    }

    fn write_request() -> ToolRequest {
        ToolRequest {
            tool_id: "filesystem.write".into(),
            requested_capability: capability(
                CapabilityKind::FilesystemWrite,
                "C:/workspace/note.txt",
            ),
            arguments: Vec::new(),
        }
    }

    fn write_policy() -> Policy {
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(capability(CapabilityKind::FilesystemWrite, "C:/workspace"));
        policy
    }

    fn approval_for(task_id: &str, request: &ToolRequest, expires_at: u64) -> ApprovalRecord {
        ApprovalRecord::new(
            "approval-1",
            action_hash(
                task_id,
                &request.tool_id,
                &request.requested_capability,
                &request.arguments,
            ),
            capability(CapabilityKind::FilesystemWrite, "C:/workspace"),
            expires_at,
        )
        .expect("valid test approval")
    }

    fn runtime() -> RuntimeGate {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.read",
                    capability(CapabilityKind::FilesystemRead, "C:/workspace"),
                    AutonomyLevel::A0,
                    1_000,
                    true,
                )
                .expect("valid fixed tool definition"),
            )
            .expect("first registration succeeds");
        RuntimeGate::new(broker, ResourceGovernor::new(3))
    }

    #[test]
    fn policy_denial_stops_the_tool_before_resource_admission() {
        let mut runtime = runtime();
        let policy = Policy::deny_all(AutonomyLevel::A3);
        let request = ToolRequest {
            tool_id: "filesystem.read".into(),
            requested_capability: capability(
                CapabilityKind::FilesystemRead,
                "C:/workspace/readme.md",
            ),
            arguments: Vec::new(),
        };

        assert_eq!(
            runtime
                .evaluate_tool(
                    "task-1",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    &CancellationToken::new(),
                )
                .expect("registered tool request"),
            RuntimeOutcome::Denied
        );
        assert_eq!(runtime.audit().events()[0].outcome, AuditOutcome::Denied);
    }

    #[test]
    fn resource_pressure_stops_an_otherwise_authorized_tool() {
        let mut runtime = runtime();
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(capability(CapabilityKind::FilesystemRead, "C:/workspace"));
        let request = ToolRequest {
            tool_id: "filesystem.read".into(),
            requested_capability: capability(
                CapabilityKind::FilesystemRead,
                "C:/workspace/readme.md",
            ),
            arguments: Vec::new(),
        };

        assert_eq!(
            runtime
                .evaluate_tool(
                    "task-2",
                    0,
                    ResourceMode::Critical,
                    &request,
                    &policy,
                    &CancellationToken::new(),
                )
                .expect("registered tool request"),
            RuntimeOutcome::RejectedForResources
        );
    }

    #[test]
    fn cancellation_stops_the_tool_before_policy_evaluation() {
        let mut runtime = runtime();
        let policy = Policy::deny_all(AutonomyLevel::A0);
        let request = ToolRequest {
            tool_id: "filesystem.read".into(),
            requested_capability: capability(
                CapabilityKind::FilesystemRead,
                "C:/workspace/readme.md",
            ),
            arguments: Vec::new(),
        };
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert_eq!(
            runtime
                .evaluate_tool(
                    "task-1",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    &cancellation,
                )
                .expect("registered tool request"),
            RuntimeOutcome::Cancelled
        );
        assert_eq!(runtime.audit().events()[0].outcome, AuditOutcome::Cancelled);
    }

    #[test]
    fn cancellation_tokens_share_state_across_clones() {
        let token = CancellationToken::new();
        let worker_copy = token.clone();

        assert!(!worker_copy.is_cancelled());
        token.cancel();
        assert!(worker_copy.is_cancelled());
    }

    #[test]
    fn action_hash_binds_task_tool_scope_and_arguments() {
        let first = capability(CapabilityKind::FilesystemWrite, "C:/workspace/note.txt");
        let second = capability(CapabilityKind::FilesystemWrite, "C:/workspace/other.txt");
        let empty: Vec<String> = Vec::new();

        assert_eq!(
            action_hash("task-1", "filesystem.write", &first, &empty),
            action_hash("task-1", "filesystem.write", &first, &empty)
        );
        assert_ne!(
            action_hash("task-1", "filesystem.write", &first, &empty),
            action_hash("task-2", "filesystem.write", &first, &empty)
        );
        assert_ne!(
            action_hash("task-1", "filesystem.write", &first, &empty),
            action_hash("task-1", "filesystem.write", &second, &empty)
        );
        // Same program, different flags: different actions, different hashes.
        assert_ne!(
            action_hash("task-1", "process.execute", &first, &empty),
            action_hash(
                "task-1",
                "process.execute",
                &first,
                &["--force".to_string()]
            )
        );
    }

    #[test]
    fn valid_approval_converts_approval_required_into_permit() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let approval = approval_for("task-approval", &request, 1_000);

        match runtime
            .issue_permit_with_approval(
                "task-approval",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                Some(&approval),
                999,
                &CancellationToken::new(),
            )
            .expect("approval pipeline runs")
        {
            ExecutionDecision::Permitted(permit) => {
                assert_eq!(permit.task_id(), "task-approval");
                assert_eq!(permit.tool_id(), "filesystem.write");
            }
            other => panic!("expected permit, got {other:?}"),
        }
    }

    #[test]
    fn expired_approval_leaves_work_waiting_for_approval() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let approval = approval_for("task-approval", &request, 1_000);

        assert_eq!(
            runtime
                .issue_permit_with_approval(
                    "task-approval",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    Some(&approval),
                    1_000,
                    &CancellationToken::new(),
                )
                .expect("approval pipeline runs"),
            ExecutionDecision::ApprovalRequired
        );
    }

    #[test]
    fn revoked_approval_leaves_work_waiting_for_approval() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let mut approval = approval_for("task-approval", &request, 1_000);
        approval.revoked = true;

        assert_eq!(
            runtime
                .issue_permit_with_approval(
                    "task-approval",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    Some(&approval),
                    999,
                    &CancellationToken::new(),
                )
                .expect("approval pipeline runs"),
            ExecutionDecision::ApprovalRequired
        );
    }

    #[test]
    fn missing_approval_leaves_work_waiting_for_approval() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();

        assert_eq!(
            runtime
                .issue_permit_with_approval(
                    "task-approval",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    None,
                    999,
                    &CancellationToken::new(),
                )
                .expect("approval pipeline runs"),
            ExecutionDecision::ApprovalRequired
        );
    }

    #[test]
    fn approval_for_another_action_is_denied_as_replay() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let other_request = ToolRequest {
            tool_id: "filesystem.write".into(),
            requested_capability: capability(
                CapabilityKind::FilesystemWrite,
                "C:/workspace/other.txt",
            ),
            arguments: Vec::new(),
        };
        let approval = approval_for("task-approval", &other_request, 1_000);

        assert_eq!(
            runtime
                .issue_permit_with_approval(
                    "task-approval",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    Some(&approval),
                    999,
                    &CancellationToken::new(),
                )
                .expect("approval pipeline runs"),
            ExecutionDecision::Denied
        );
    }

    #[test]
    fn approval_for_other_arguments_is_denied_as_replay() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let mut request = write_request();
        request.arguments = vec!["--dry-run".to_string()];
        let approval = approval_for("task-approval", &request, 1_000);

        // Same task, tool, and scope — but the invocation swaps flags after
        // approval. The hash binds arguments, so the swap is a denial.
        let mut swapped = write_request();
        swapped.arguments = vec!["--force".to_string()];
        assert_eq!(
            runtime
                .issue_permit_with_approval(
                    "task-approval",
                    0,
                    ResourceMode::Normal,
                    &swapped,
                    &policy,
                    Some(&approval),
                    999,
                    &CancellationToken::new(),
                )
                .expect("approval pipeline runs"),
            ExecutionDecision::Denied
        );
    }

    #[test]
    fn narrower_approval_scope_is_denied() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let mut approval = approval_for("task-approval", &request, 1_000);
        approval.capability = capability(CapabilityKind::FilesystemWrite, "C:/workspace/other.txt");

        assert_eq!(
            runtime
                .issue_permit_with_approval(
                    "task-approval",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    Some(&approval),
                    999,
                    &CancellationToken::new(),
                )
                .expect("approval pipeline runs"),
            ExecutionDecision::Denied
        );
    }

    #[test]
    fn cancellation_beats_a_valid_approval() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let approval = approval_for("task-approval", &request, 1_000);
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert_eq!(
            runtime
                .issue_permit_with_approval(
                    "task-approval",
                    0,
                    ResourceMode::Normal,
                    &request,
                    &policy,
                    Some(&approval),
                    999,
                    &cancellation,
                )
                .expect("approval pipeline runs"),
            ExecutionDecision::Cancelled
        );
    }

    fn standing_grant(expires_at: u64) -> ApprovalRecord {
        ApprovalRecord::new_standing(
            "approval-standing-1",
            "standing:filesystem_write:C:/workspace",
            capability(CapabilityKind::FilesystemWrite, "C:/workspace"),
            expires_at,
        )
        .expect("valid test approval")
    }

    fn with_standing(
        runtime: &mut RuntimeGate,
        policy: &Policy,
        request: &ToolRequest,
        standing: &[ApprovalRecord],
        mode: ResourceMode,
    ) -> ExecutionDecision {
        runtime
            .issue_permit_with_standing_approval(
                "task-approval",
                0,
                mode,
                request,
                policy,
                standing,
                999,
                &CancellationToken::new(),
            )
            .expect("standing pipeline runs")
    }

    #[test]
    fn standing_grant_converts_approval_required_into_permit() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let grant = standing_grant(1_000);

        match with_standing(
            &mut runtime,
            &policy,
            &request,
            &[grant],
            ResourceMode::Normal,
        ) {
            ExecutionDecision::Permitted(permit) => {
                assert_eq!(permit.tool_id(), "filesystem.write");
            }
            other => panic!("expected permit, got {other:?}"),
        }
    }

    #[test]
    fn stale_standing_grants_keep_work_waiting() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();

        let expired = standing_grant(999);
        assert_eq!(
            with_standing(
                &mut runtime,
                &policy,
                &request,
                &[expired],
                ResourceMode::Normal
            ),
            ExecutionDecision::ApprovalRequired
        );

        let mut revoked = standing_grant(1_000);
        revoked.revoked = true;
        assert_eq!(
            with_standing(
                &mut runtime,
                &policy,
                &request,
                &[revoked],
                ResourceMode::Normal
            ),
            ExecutionDecision::ApprovalRequired
        );
    }

    #[test]
    fn inapplicable_standing_grant_is_waiting_not_denial() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let mut narrow = standing_grant(1_000);
        narrow.capability = capability(CapabilityKind::FilesystemWrite, "C:/workspace/other.txt");

        assert_eq!(
            with_standing(
                &mut runtime,
                &policy,
                &request,
                &[narrow],
                ResourceMode::Normal
            ),
            ExecutionDecision::ApprovalRequired
        );
    }

    #[test]
    fn standing_grant_never_overrides_a_denial() {
        let mut runtime = write_runtime();
        let ungranted = Policy::deny_all(AutonomyLevel::A3);
        let request = write_request();
        let grant = standing_grant(1_000);

        assert_eq!(
            with_standing(
                &mut runtime,
                &ungranted,
                &request,
                &[grant],
                ResourceMode::Normal
            ),
            ExecutionDecision::Denied
        );
    }

    #[test]
    fn standing_grant_respects_resource_backpressure() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let grant = standing_grant(1_000);

        assert_eq!(
            with_standing(
                &mut runtime,
                &policy,
                &request,
                &[grant],
                ResourceMode::Critical
            ),
            ExecutionDecision::RejectedForResources
        );
    }

    #[test]
    fn decisions_report_their_autonomy_tier() {
        let mut runtime = write_runtime();
        let policy = write_policy();
        let request = write_request();
        let grant = standing_grant(1_000);

        let permitted = with_standing(
            &mut runtime,
            &policy,
            &request,
            &[grant],
            ResourceMode::Normal,
        );
        assert_eq!(permitted.tier(), AutonomyTier::Green);
        assert_eq!(
            ExecutionDecision::ApprovalRequired.tier(),
            AutonomyTier::Orange
        );
        assert_eq!(
            ExecutionDecision::QueuedForResources.tier(),
            AutonomyTier::Orange
        );
        assert_eq!(ExecutionDecision::Denied.tier(), AutonomyTier::Red);
        assert_eq!(
            ExecutionDecision::RejectedForResources.tier(),
            AutonomyTier::Red
        );
        assert_eq!(ExecutionDecision::Cancelled.tier(), AutonomyTier::Red);
    }
}
