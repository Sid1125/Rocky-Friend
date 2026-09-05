use rocky_domain::{AutonomyLevel, Capability, CapabilityKind};
use rocky_policy::Policy;
use rocky_resources::{ResourceGovernor, ResourceMode};
use rocky_runtime::{CancellationToken, RuntimeGate, RuntimeOutcome};
use rocky_tools::{ToolBroker, ToolDefinition, ToolRequest};

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

#[test]
fn consequential_write_is_held_for_explicit_approval() {
    let mut runtime = write_runtime();
    let mut policy = Policy::deny_all(AutonomyLevel::A3);
    policy.grant(capability(CapabilityKind::FilesystemWrite, "C:/workspace"));
    let request = ToolRequest {
        tool_id: "filesystem.write".into(),
        requested_capability: capability(CapabilityKind::FilesystemWrite, "C:/workspace/note.txt"),
        arguments: Vec::new(),
    };

    assert_eq!(
        runtime
            .evaluate_tool(
                "task-approval",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                &CancellationToken::new(),
            )
            .expect("registered request"),
        RuntimeOutcome::ApprovalRequired
    );
}

#[test]
fn normal_work_is_queued_when_normal_capacity_is_exhausted() {
    // A0 makes this test a resource-path check rather than an approval-path check.
    let mut read_broker = ToolBroker::default();
    read_broker
        .register(
            ToolDefinition::new(
                "filesystem.read",
                capability(CapabilityKind::FilesystemRead, "C:/workspace"),
                AutonomyLevel::A0,
                1_000,
                true,
            )
            .expect("valid tool definition"),
        )
        .expect("first registration succeeds");
    let mut read_runtime = RuntimeGate::new(read_broker, ResourceGovernor::new(1));
    let mut read_policy = Policy::deny_all(AutonomyLevel::A3);
    read_policy.grant(capability(CapabilityKind::FilesystemRead, "C:/workspace"));
    let read_request = ToolRequest {
        tool_id: "filesystem.read".into(),
        requested_capability: capability(CapabilityKind::FilesystemRead, "C:/workspace/note.txt"),
        arguments: Vec::new(),
    };

    assert_eq!(
        read_runtime
            .evaluate_tool(
                "task-queue",
                1,
                ResourceMode::Normal,
                &read_request,
                &read_policy,
                &CancellationToken::new(),
            )
            .expect("registered request"),
        RuntimeOutcome::QueuedForResources
    );
}
