//! Permit-bound evidence capture: executor output becomes task evidence.
//!
//! The collector takes the same permit the executor consumed plus the exact
//! bytes it returned, and records them under the permit's task and tool. The
//! digest lets verifiers re-hash the output without trusting the store.

use rocky_runtime::ExecutionPermit;
use rocky_storage::{EvidenceRecord, EvidenceStore, StorageError};

/// Records executor output as task evidence bound to the consuming permit.
///
/// The task and tool IDs come from the permit, never from caller strings, so
/// output cannot be misfiled under another task. Size and count bounds are
/// enforced by the store.
pub fn capture_permit_evidence(
    store: &mut impl EvidenceStore,
    permit: &ExecutionPermit,
    bytes: Vec<u8>,
) -> Result<EvidenceRecord, StorageError> {
    store.capture(permit.task_id(), permit.tool_id(), bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_domain::{AutonomyLevel, Capability, CapabilityKind};
    use rocky_policy::Policy;
    use rocky_resources::{ResourceGovernor, ResourceMode};
    use rocky_runtime::{CancellationToken, ExecutionDecision, RuntimeGate};
    use rocky_storage::{EvidenceStore, InMemoryTaskStore};
    use rocky_tools::{ToolBroker, ToolDefinition, ToolRequest};
    use std::fs;

    fn test_root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("rocky-chain-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    #[test]
    fn read_output_becomes_verifiable_task_evidence() {
        let root = test_root();
        let file_path = root.join("note.txt");
        fs::write(&file_path, b"evidence bytes").expect("write test file");
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let requested = file_path.to_str().expect("test path is UTF-8").to_string();

        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.read",
                    Capability::new(CapabilityKind::FilesystemRead, grant.clone())
                        .expect("valid test capability"),
                    AutonomyLevel::A0,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::FilesystemRead, grant).expect("valid test grant"),
        );
        let request = ToolRequest {
            tool_id: "filesystem.read".into(),
            requested_capability: Capability::new(CapabilityKind::FilesystemRead, requested)
                .expect("valid test capability"),
            arguments: Vec::new(),
        };
        let cancellation = CancellationToken::new();
        let permit = match gate
            .issue_permit(
                "task-1",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                &cancellation,
            )
            .expect("permit pipeline runs")
        {
            ExecutionDecision::Permitted(permit) => permit,
            other => panic!("expected permit, got {other:?}"),
        };

        let output = super::super::FilesystemReadExecutor::new(1024)
            .expect("valid limit")
            .read(&permit, &cancellation)
            .expect("authorized read");
        let mut store = InMemoryTaskStore::default();
        let record = capture_permit_evidence(&mut store, &permit, output.bytes.clone())
            .expect("capture evidence");

        // The record is bound to the permit and re-verifiable from the bytes.
        assert_eq!(record.task_id, "task-1");
        assert_eq!(record.tool_id, "filesystem.read");
        assert_eq!(record.bytes, b"evidence bytes");
        assert_eq!(
            record.digest,
            rocky_domain::content_digest(&[b"evidence bytes"])
        );
        assert_eq!(
            store.evidence_for_task("task-1").expect("task query").len(),
            1
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn oversized_output_is_rejected_at_capture() {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.read",
                    Capability::new(CapabilityKind::FilesystemRead, "C:/grant")
                        .expect("valid test capability"),
                    AutonomyLevel::A0,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::FilesystemRead, "C:/grant").expect("valid test grant"),
        );
        let request = ToolRequest {
            tool_id: "filesystem.read".into(),
            requested_capability: Capability::new(CapabilityKind::FilesystemRead, "C:/grant/f.txt")
                .expect("valid test capability"),
            arguments: Vec::new(),
        };
        let permit = match gate
            .issue_permit(
                "task-1",
                0,
                ResourceMode::Normal,
                &request,
                &policy,
                &CancellationToken::new(),
            )
            .expect("permit pipeline runs")
        {
            ExecutionDecision::Permitted(permit) => permit,
            other => panic!("expected permit, got {other:?}"),
        };

        let mut store = InMemoryTaskStore::default();
        assert_eq!(
            capture_permit_evidence(
                &mut store,
                &permit,
                vec![0; rocky_storage::MAX_EVIDENCE_BYTES + 1],
            ),
            Err(rocky_storage::StorageError::EvidenceTooLarge)
        );
    }
}
