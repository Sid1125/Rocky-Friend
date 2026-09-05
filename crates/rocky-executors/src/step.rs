//! Bounded agent step loop: model proposal to evidenced execution.
//!
//! One step asks the model what to do, authorizes each proposal through the
//! gate, runs permitted tools, and captures evidence. Scopes come from the
//! [`InvocationTable`], never from model output: the model picks tools and
//! arguments, authority stays entirely in policy and permits.

use super::{
    AllowlistedProcessExecutor, FilesystemReadExecutor, evidence::capture_permit_evidence,
};
use rocky_agents::Worker;
use rocky_domain::{Capability, CapabilityKind};
use rocky_ipc::EventPayload;
use rocky_models::{ModelError, ModelProvider, ModelRequest};
use rocky_policy::Policy;
use rocky_resources::ResourceMode;
use rocky_runtime::{CancellationToken, ExecutionDecision, ExecutionPermit, RuntimeGate};
use rocky_storage::{EvidenceStore, StorageError};
use rocky_tools::ToolRequest;
use std::fmt;

/// Maximum model proposals honored per step. A flooding model aborts the run
/// loudly instead of spawning unbounded work.
pub const MAX_PROPOSALS_PER_STEP: usize = 4;

/// Tool IDs the step runner can dispatch. The table binds each tool to its
/// scope; anything else is denied without a permit attempt.
const SUPPORTED_TOOLS: [&str; 2] = ["filesystem.read", "process.execute"];

/// Binds one tool ID to the capability scope the model may invoke it with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolBinding {
    pub tool_id: String,
    pub capability: Capability,
}

/// The set of tools a model may propose, with their fixed scopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationTable {
    bindings: Vec<ToolBinding>,
}

impl InvocationTable {
    /// Validates tool IDs up front so dispatch can never meet an unknown
    /// tool: fail fast at table construction, not mid-run.
    pub fn new(bindings: Vec<ToolBinding>) -> Result<Self, TableError> {
        for binding in &bindings {
            if binding.tool_id.trim().is_empty() {
                return Err(TableError::EmptyToolId);
            }
            if !SUPPORTED_TOOLS.contains(&binding.tool_id.as_str()) {
                return Err(TableError::UnsupportedTool(binding.tool_id.clone()));
            }
        }
        let mut seen = Vec::with_capacity(bindings.len());
        for binding in &bindings {
            if seen.contains(&binding.tool_id) {
                return Err(TableError::DuplicateTool(binding.tool_id.clone()));
            }
            seen.push(binding.tool_id.clone());
        }
        Ok(Self { bindings })
    }

    fn find(&self, tool_id: &str) -> Option<&ToolBinding> {
        self.bindings.iter().find(|item| item.tool_id == tool_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TableError {
    EmptyToolId,
    UnsupportedTool(String),
    DuplicateTool(String),
}

impl fmt::Display for TableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invocation table error: {self:?}")
    }
}

impl std::error::Error for TableError {}

/// One executed proposal: what the gate decided and where its evidence lives.
///
/// The capability is present exactly when the tool was table-known: unknown
/// tools die before any scope exists for them. Arguments always ride along
/// so UI events can name the exact action without re-deriving anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutedStep {
    pub tool_id: String,
    pub capability: Option<Capability>,
    pub arguments: Vec<String>,
    pub decision: ExecutionDecision,
    pub evidence_id: Option<String>,
}

/// A bounded run: executed proposals, model calls made, and whether
/// cancellation cut the run short (partial evidence still reported).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepRun {
    pub task_id: String,
    pub executed: Vec<ExecutedStep>,
    pub model_calls: usize,
    pub cancelled: bool,
}

impl StepRun {
    /// Observational UI events for the run, in execution order. Every
    /// proposal attempt emits `ToolRequested`; permits add approval and
    /// completion; approval holds name the exact action hash the UI must
    /// approve. Anything else emitted nothing beyond the attempt.
    pub fn events(&self) -> Vec<EventPayload> {
        let mut events = Vec::new();
        for step in &self.executed {
            events.push(EventPayload::ToolRequested {
                tool_id: step.tool_id.clone(),
            });
            match &step.decision {
                ExecutionDecision::Permitted(_) => {
                    events.push(EventPayload::ToolApproved {
                        tool_id: step.tool_id.clone(),
                    });
                    events.push(EventPayload::ToolCompleted {
                        tool_id: step.tool_id.clone(),
                    });
                }
                ExecutionDecision::ApprovalRequired => {
                    // The hash needs a capability, which only table-known
                    // tools carry; unknown tools can never reach this arm
                    // because they are denied before the gate.
                    if let Some(capability) = &step.capability {
                        events.push(EventPayload::ApprovalRequired {
                            action_id: rocky_runtime::action_hash(
                                &self.task_id,
                                &step.tool_id,
                                capability,
                                &step.arguments,
                            ),
                        });
                    }
                }
                ExecutionDecision::QueuedForResources
                | ExecutionDecision::RejectedForResources
                | ExecutionDecision::Denied
                | ExecutionDecision::Cancelled => {}
            }
        }
        events
    }
}

/// Runs the model-to-evidence loop with the executors this runner owns.
///
/// Timeouts for process execution come from construction because tool
/// definitions live behind the gate: the runner carries the operational
/// half, the gate carries the authorization half.
pub struct StepRunner {
    reader: FilesystemReadExecutor,
    process: AllowlistedProcessExecutor,
    process_timeout_ms: u64,
}

impl StepRunner {
    pub fn new(
        reader: FilesystemReadExecutor,
        process: AllowlistedProcessExecutor,
        process_timeout_ms: u64,
    ) -> Self {
        Self {
            reader,
            process,
            process_timeout_ms,
        }
    }

    /// Runs up to `max_steps` model iterations. Each iteration makes exactly
    /// one model call; an iteration with no proposals ends the run. The loop
    /// is doubly bounded by `max_steps` and the per-step proposal cap, so no
    /// model can spin it forever.
    ///
    /// `worker` binds the run to a Mini-ROCKY when present: its role tools
    /// gate every proposal, its cancellation flag stops the run, and its
    /// step budget ends it — each model call consumes one budgeted step.
    /// `None` leaves the run workerless (direct/orchestrator-less use);
    /// production callers always pass the worker.
    #[allow(clippy::too_many_arguments)]
    pub fn run_steps(
        &self,
        gate: &mut RuntimeGate,
        provider: &dyn ModelProvider,
        model_request: &ModelRequest,
        table: &InvocationTable,
        policy: &Policy,
        store: &mut impl EvidenceStore,
        task_id: &str,
        mode: ResourceMode,
        active_workers: usize,
        max_steps: usize,
        mut worker: Option<&mut Worker>,
        cancellation: &CancellationToken,
    ) -> Result<StepRun, StepError> {
        // Clone once: the allowlist is tiny and this keeps borrows simple
        // across the mutable budget recording below.
        let tools: Option<Vec<CapabilityKind>> = worker.as_ref().map(|item| item.tools().to_vec());
        let mut run = StepRun {
            task_id: task_id.into(),
            executed: Vec::new(),
            model_calls: 0,
            cancelled: false,
        };
        for _ in 0..max_steps {
            if cancellation.is_cancelled()
                || worker.as_ref().is_some_and(|item| item.is_cancelled())
            {
                run.cancelled = true;
                return Ok(run);
            }
            if worker.as_ref().is_some_and(|item| item.is_exhausted()) {
                return Ok(run);
            }
            let response = provider.complete(model_request).map_err(StepError::Model)?;
            run.model_calls += 1;
            if response.proposed_tools.is_empty() {
                return Ok(run);
            }
            if response.proposed_tools.len() > MAX_PROPOSALS_PER_STEP {
                return Err(StepError::TooManyProposals);
            }
            if let Some(item) = worker.as_mut() {
                item.record_step().map_err(StepError::Worker)?;
            }
            for proposal in &response.proposed_tools {
                if cancellation.is_cancelled()
                    || worker.as_ref().is_some_and(|item| item.is_cancelled())
                {
                    run.cancelled = true;
                    return Ok(run);
                }
                run.executed.push(self.execute_proposal(
                    gate,
                    table,
                    policy,
                    store,
                    task_id,
                    mode,
                    active_workers,
                    tools.as_deref(),
                    cancellation,
                    &proposal.tool_id,
                    &proposal.arguments,
                )?);
            }
        }
        Ok(run)
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_proposal(
        &self,
        gate: &mut RuntimeGate,
        table: &InvocationTable,
        policy: &Policy,
        store: &mut impl EvidenceStore,
        task_id: &str,
        mode: ResourceMode,
        active_workers: usize,
        worker_tools: Option<&[CapabilityKind]>,
        cancellation: &CancellationToken,
        tool_id: &str,
        arguments: &[String],
    ) -> Result<ExecutedStep, StepError> {
        let Some(binding) = table.find(tool_id) else {
            // Unknown tools die here as denials: no permit is attempted, so
            // nothing executes and the run continues with the next proposal.
            return Ok(ExecutedStep {
                tool_id: tool_id.into(),
                capability: None,
                arguments: arguments.to_vec(),
                decision: ExecutionDecision::Denied,
                evidence_id: None,
            });
        };
        if worker_tools.is_some_and(|allowed| !allowed.contains(&binding.capability.kind)) {
            // The worker's role never granted this capability kind: deny
            // before the gate, before any audit or evidence exists for it.
            // `None` (workerless runs) skips this check.
            return Ok(ExecutedStep {
                tool_id: tool_id.into(),
                capability: Some(binding.capability.clone()),
                arguments: arguments.to_vec(),
                decision: ExecutionDecision::Denied,
                evidence_id: None,
            });
        }
        let request = ToolRequest {
            tool_id: tool_id.into(),
            requested_capability: binding.capability.clone(),
            arguments: arguments.to_vec(),
        };
        let decision = gate.issue_permit(
            task_id,
            active_workers,
            mode,
            &request,
            policy,
            cancellation,
        )?;
        let evidence_id = match &decision {
            ExecutionDecision::Permitted(permit) => {
                Some(self.dispatch(store, permit, cancellation)?.id)
            }
            _ => None,
        };
        Ok(ExecutedStep {
            tool_id: tool_id.into(),
            capability: Some(binding.capability.clone()),
            arguments: arguments.to_vec(),
            decision,
            evidence_id,
        })
    }

    /// Dispatches a permitted tool to its executor and captures the output.
    /// The permit preselects the tool, so this match cannot authorize
    /// anything the gate did not already permit.
    fn dispatch(
        &self,
        store: &mut impl EvidenceStore,
        permit: &ExecutionPermit,
        cancellation: &CancellationToken,
    ) -> Result<rocky_storage::EvidenceRecord, StepError> {
        let bytes = match permit.tool_id() {
            "filesystem.read" => {
                self.reader
                    .read(permit, cancellation)
                    .map_err(StepError::Executor)?
                    .bytes
            }
            "process.execute" => {
                let program = permit.requested_capability().scope.clone();
                self.process
                    .execute(
                        permit,
                        &program,
                        permit.arguments(),
                        self.process_timeout_ms,
                        cancellation,
                    )
                    .map_err(StepError::Executor)?
                    .stdout
            }
            _ => return Err(StepError::UnsupportedTool),
        };
        Ok(capture_permit_evidence(store, permit, bytes)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepError {
    Model(ModelError),
    Runtime(rocky_runtime::RuntimeError),
    Storage(StorageError),
    Executor(crate::ExecutorError),
    Worker(rocky_agents::WorkerError),
    TooManyProposals,
    UnsupportedTool,
}

impl fmt::Display for StepError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "step error: {self:?}")
    }
}

impl std::error::Error for StepError {}

impl From<ModelError> for StepError {
    fn from(error: ModelError) -> Self {
        Self::Model(error)
    }
}

impl From<rocky_runtime::RuntimeError> for StepError {
    fn from(error: rocky_runtime::RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<StorageError> for StepError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<crate::ExecutorError> for StepError {
    fn from(error: crate::ExecutorError) -> Self {
        Self::Executor(error)
    }
}

impl From<rocky_agents::WorkerError> for StepError {
    fn from(error: rocky_agents::WorkerError) -> Self {
        Self::Worker(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllowlistedProcessExecutor, FilesystemReadExecutor};
    use rocky_agents::Worker;
    use rocky_domain::{AutonomyLevel, Capability, CapabilityKind};
    use rocky_models::{ModelError, ModelProvider, ModelRequest, ModelResponse, ProposedToolCall};
    use rocky_policy::Policy;
    use rocky_resources::{ResourceGovernor, ResourceMode};
    use rocky_runtime::{CancellationToken, ExecutionDecision, RuntimeGate};
    use rocky_storage::{EvidenceStore, InMemoryTaskStore};
    use rocky_tools::{ToolBroker, ToolDefinition};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;

    /// A scripted stand-in for a model: replays queued responses and counts
    /// calls. The loop is what's under test, never model intelligence.
    struct ScriptedProvider {
        responses: RefCell<VecDeque<ModelResponse>>,
        calls: RefCell<usize>,
    }

    impl ScriptedProvider {
        fn replay(responses: Vec<ModelResponse>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                calls: RefCell::new(0),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.borrow()
        }
    }

    impl ModelProvider for ScriptedProvider {
        fn kind(&self) -> rocky_models::ProviderKind {
            rocky_models::ProviderKind::Local
        }

        fn complete(&self, _request: &ModelRequest) -> Result<ModelResponse, ModelError> {
            *self.calls.borrow_mut() += 1;
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or(ModelError::ProviderUnavailable)
        }
    }

    fn propose(tool_id: &str, arguments: Vec<&str>) -> ModelResponse {
        ModelResponse {
            text: "do it".into(),
            proposed_tools: vec![ProposedToolCall {
                tool_id: tool_id.into(),
                arguments: arguments.into_iter().map(str::to_string).collect(),
            }],
        }
    }

    fn quiet() -> ModelResponse {
        ModelResponse {
            text: "nothing to do".into(),
            proposed_tools: Vec::new(),
        }
    }

    fn test_root() -> std::path::PathBuf {
        // Atomic suffix: tests run in parallel threads sharing one PID, so
        // every root must be unique or tests delete each other's files.
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let slot = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rocky-step-{}-{slot}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    fn model_request() -> ModelRequest {
        ModelRequest::new("task-1", "summarize", 256, Vec::new()).expect("valid test request")
    }

    fn worker_with_tools(tools: &[CapabilityKind]) -> Worker {
        worker_with_tools_and_budget(tools, 100)
    }

    fn worker_with_tools_and_budget(tools: &[CapabilityKind], step_budget: u32) -> Worker {
        use rocky_agents::{AgentSpec, Worker};
        use rocky_domain::TaskState;
        Worker::new(
            "w-1",
            "task-1",
            AgentSpec {
                role: "test".into(),
                depth: 1,
                step_budget,
                deadline_ms: 60_000,
                state: TaskState::Created,
                tools: tools.to_vec(),
            },
        )
        .expect("valid test worker")
    }

    /// Gate + policy + table where `filesystem.read` of `file` is granted.
    /// The table binds the exact file path: scopes always come from here.
    fn read_setup(file: &str, grant: &str) -> (RuntimeGate, Policy, InvocationTable) {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "filesystem.read",
                    Capability::new(CapabilityKind::FilesystemRead, grant)
                        .expect("valid test capability"),
                    AutonomyLevel::A0,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::FilesystemRead, grant).expect("valid test grant"),
        );
        let table = InvocationTable::new(vec![ToolBinding {
            tool_id: "filesystem.read".into(),
            capability: Capability::new(CapabilityKind::FilesystemRead, file)
                .expect("valid test capability"),
        }])
        .expect("valid invocation table");
        (
            RuntimeGate::new(broker, ResourceGovernor::new(3)),
            policy,
            table,
        )
    }

    fn runner() -> StepRunner {
        StepRunner::new(
            FilesystemReadExecutor::new(65_536).expect("valid limit"),
            AllowlistedProcessExecutor::new(Vec::new(), 1024).expect("valid executor"),
            5_000,
        )
    }

    #[test]
    fn proposed_read_runs_to_evidenced_permit() {
        let root = test_root();
        let file_path = root.join("note.txt");
        fs::write(&file_path, b"step evidence").expect("write test file");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![propose("filesystem.read", vec![]), quiet()]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert!(!run.cancelled);
        assert_eq!(run.model_calls, 2);
        assert_eq!(run.executed.len(), 1);
        assert!(matches!(
            run.executed[0].decision,
            ExecutionDecision::Permitted(_)
        ));
        assert_eq!(run.executed[0].tool_id, "filesystem.read");
        let evidence_id = run.executed[0].evidence_id.clone().expect("evidence id");
        let record = store
            .evidence(&evidence_id)
            .expect("evidence query")
            .expect("stored evidence");
        assert_eq!(record.bytes, b"step evidence");
        // Two model calls: the proposal, then the quiet terminator.
        assert_eq!(provider.calls(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_tool_records_denial_and_continues() {
        let root = test_root();
        let file_path = root.join("note.txt");
        fs::write(&file_path, b"step evidence").expect("write test file");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let response = ModelResponse {
            text: "try everything".into(),
            proposed_tools: vec![
                ProposeToolCallShorthand::bogus(),
                ProposeToolCallShorthand::read(),
            ],
        };
        let provider = ScriptedProvider::replay(vec![response, quiet()]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert_eq!(run.executed.len(), 2);
        assert_eq!(run.executed[0].decision, ExecutionDecision::Denied);
        assert_eq!(run.executed[0].evidence_id, None);
        assert!(matches!(
            run.executed[1].decision,
            ExecutionDecision::Permitted(_)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// Test-only shorthand so the unknown-tool case reads plainly.
    struct ProposeToolCallShorthand;

    impl ProposeToolCallShorthand {
        fn bogus() -> ProposedToolCall {
            ProposedToolCall {
                tool_id: "teleport.execute".into(),
                arguments: Vec::new(),
            }
        }

        fn read() -> ProposedToolCall {
            ProposedToolCall {
                tool_id: "filesystem.read".into(),
                arguments: Vec::new(),
            }
        }
    }

    #[test]
    fn denied_proposal_skips_execution() {
        let root = test_root();
        let data = root.join("data");
        fs::create_dir_all(&data).expect("create data dir");
        let file_path = data.join("note.txt");
        fs::write(&file_path, b"step evidence").expect("write test file");
        // Grant covers an empty sibling directory: policy denies the file,
        // so nothing may execute and no evidence may exist.
        let grant_dir = root.join("grant");
        fs::create_dir_all(&grant_dir).expect("create grant dir");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = grant_dir.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![propose("filesystem.read", vec![]), quiet()]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert_eq!(run.executed.len(), 1);
        assert_eq!(run.executed[0].decision, ExecutionDecision::Denied);
        assert_eq!(run.executed[0].evidence_id, None);
        assert!(
            store
                .evidence_for_task("task-1")
                .expect("task query")
                .is_empty()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn run_stops_at_max_steps() {
        let root = test_root();
        let file_path = root.join("note.txt");
        fs::write(&file_path, b"step evidence").expect("write test file");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![
            propose("filesystem.read", vec![]),
            propose("filesystem.read", vec![]),
            propose("filesystem.read", vec![]),
        ]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                2,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert_eq!(run.executed.len(), 2);
        assert_eq!(provider.calls(), 2);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn quiet_model_ends_the_run() {
        let root = test_root();
        let file = root.join("note.txt");
        fs::write(&file, b"x").expect("write test file");
        let file = file.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![quiet()]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                None,
                &CancellationToken::new(),
            )
            .expect("step run");

        assert!(!run.cancelled);
        assert_eq!(run.model_calls, 1);
        assert!(run.executed.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cancellation_stops_before_the_first_model_call() {
        let root = test_root();
        let file = root.join("note.txt");
        fs::write(&file, b"x").expect("write test file");
        let file = file.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![propose("filesystem.read", vec![]), quiet()]);
        let mut store = InMemoryTaskStore::default();
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                None,
                &cancellation,
            )
            .expect("cancelled run still reports");

        assert!(run.cancelled);
        assert_eq!(provider.calls(), 0);
        assert!(run.executed.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn proposal_floods_abort_loudly() {
        let root = test_root();
        let file = root.join("note.txt");
        fs::write(&file, b"x").expect("write test file");
        let file = file.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let flood = ModelResponse {
            text: "flood".into(),
            proposed_tools: vec![ProposeToolCallShorthand::read(); MAX_PROPOSALS_PER_STEP + 1],
        };
        let provider = ScriptedProvider::replay(vec![flood]);
        let mut store = InMemoryTaskStore::default();

        assert_eq!(
            runner().run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            ),
            Err(StepError::TooManyProposals)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn invocation_table_rejects_unknown_executors() {
        assert_eq!(
            InvocationTable::new(vec![ToolBinding {
                tool_id: "teleport.execute".into(),
                capability: Capability::new(CapabilityKind::ProcessExecute, "x")
                    .expect("valid test capability"),
            }]),
            Err(TableError::UnsupportedTool("teleport.execute".into()))
        );
        assert_eq!(
            InvocationTable::new(vec![ToolBinding {
                tool_id: "  ".into(),
                capability: Capability::new(CapabilityKind::ProcessExecute, "x")
                    .expect("valid test capability"),
            }]),
            Err(TableError::EmptyToolId)
        );
    }

    #[test]
    fn proposed_process_run_dispatches_with_brokered_arguments() {
        let cargo = env!("CARGO").to_string();
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "process.execute",
                    Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                        .expect("valid test capability"),
                    AutonomyLevel::A2,
                    30_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                .expect("valid test grant"),
        );
        let table = InvocationTable::new(vec![ToolBinding {
            tool_id: "process.execute".into(),
            capability: Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                .expect("valid test capability"),
        }])
        .expect("valid invocation table");
        let provider =
            ScriptedProvider::replay(vec![propose("process.execute", vec!["--version"]), quiet()]);
        let mut store = InMemoryTaskStore::default();
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));
        let runner = StepRunner::new(
            FilesystemReadExecutor::new(1024).expect("valid limit"),
            AllowlistedProcessExecutor::new(vec![cargo], 65_536).expect("valid executor"),
            30_000,
        );

        let run = runner
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::ProcessExecute])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert_eq!(run.executed.len(), 1);
        assert!(matches!(
            run.executed[0].decision,
            ExecutionDecision::Permitted(_)
        ));
        let evidence_id = run.executed[0].evidence_id.clone().expect("evidence id");
        let record = store
            .evidence(&evidence_id)
            .expect("evidence query")
            .expect("stored evidence");
        assert!(record.bytes.starts_with(b"cargo "));
    }

    #[test]
    fn worker_without_the_capability_is_denied_before_the_gate() {
        // The worker is a file reader; the model proposes a process run the
        // policy would otherwise grant. Role allowlists win: denial happens
        // before any permit, audit, or evidence exists.
        let cargo = env!("CARGO").to_string();
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "process.execute",
                    Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                        .expect("valid test capability"),
                    AutonomyLevel::A2,
                    30_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                .expect("valid test grant"),
        );
        let table = InvocationTable::new(vec![ToolBinding {
            tool_id: "process.execute".into(),
            capability: Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                .expect("valid test capability"),
        }])
        .expect("valid invocation table");
        let provider =
            ScriptedProvider::replay(vec![propose("process.execute", vec!["--version"]), quiet()]);
        let mut store = InMemoryTaskStore::default();
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert_eq!(run.executed.len(), 1);
        assert_eq!(run.executed[0].decision, ExecutionDecision::Denied);
        assert_eq!(run.executed[0].evidence_id, None);
        assert!(gate.audit().events().is_empty());
    }

    #[test]
    fn permitted_run_emits_the_full_tool_lifecycle() {
        let root = test_root();
        let file_path = root.join("note.txt");
        fs::write(&file_path, b"step evidence").expect("write test file");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![propose("filesystem.read", vec![]), quiet()]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert_eq!(
            run.events(),
            vec![
                EventPayload::ToolRequested {
                    tool_id: "filesystem.read".into(),
                },
                EventPayload::ToolApproved {
                    tool_id: "filesystem.read".into(),
                },
                EventPayload::ToolCompleted {
                    tool_id: "filesystem.read".into(),
                },
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn denied_run_emits_only_the_attempt() {
        let root = test_root();
        let data = root.join("data");
        fs::create_dir_all(&data).expect("create data dir");
        let file_path = data.join("note.txt");
        fs::write(&file_path, b"step evidence").expect("write test file");
        // The grant covers an empty sibling directory, so the gate denies a
        // worker that is otherwise fully authorized for this tool kind.
        let grant_dir = root.join("grant");
        fs::create_dir_all(&grant_dir).expect("create grant dir");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = grant_dir.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![propose("filesystem.read", vec![]), quiet()]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::FilesystemRead])),
                &CancellationToken::new(),
            )
            .expect("step run");

        assert_eq!(run.executed.len(), 1);
        assert_eq!(run.executed[0].decision, ExecutionDecision::Denied);
        assert_eq!(
            run.events(),
            vec![EventPayload::ToolRequested {
                tool_id: "filesystem.read".into(),
            }]
        );
        assert!(
            store
                .evidence_for_task("task-1")
                .expect("task query")
                .is_empty()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn approval_required_run_names_the_action_hash() {
        // An A3 process tool: the gate holds the proposal for approval, so
        // nothing executes and the events name the exact pending action.
        let cargo = env!("CARGO").to_string();
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "process.execute",
                    Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                        .expect("valid test capability"),
                    AutonomyLevel::A3,
                    30_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(
            Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                .expect("valid test grant"),
        );
        let table = InvocationTable::new(vec![ToolBinding {
            tool_id: "process.execute".into(),
            capability: Capability::new(CapabilityKind::ProcessExecute, cargo.clone())
                .expect("valid test capability"),
        }])
        .expect("valid invocation table");
        let provider =
            ScriptedProvider::replay(vec![propose("process.execute", vec!["--version"]), quiet()]);
        let mut store = InMemoryTaskStore::default();
        let mut gate = RuntimeGate::new(broker, ResourceGovernor::new(3));

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools(&[CapabilityKind::ProcessExecute])),
                &CancellationToken::new(),
            )
            .expect("step run");

        let capability =
            Capability::new(CapabilityKind::ProcessExecute, cargo).expect("valid test capability");
        assert_eq!(
            run.executed[0].decision,
            ExecutionDecision::ApprovalRequired
        );
        assert_eq!(
            run.events(),
            vec![
                EventPayload::ToolRequested {
                    tool_id: "process.execute".into(),
                },
                EventPayload::ApprovalRequired {
                    action_id: rocky_runtime::action_hash(
                        "task-1",
                        "process.execute",
                        &capability,
                        &["--version".to_string()]
                    ),
                },
            ]
        );
    }

    #[test]
    fn exhausted_budget_ends_the_run_quietly() {
        let root = test_root();
        let file_path = root.join("note.txt");
        fs::write(&file_path, b"step evidence").expect("write test file");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![
            propose("filesystem.read", vec![]),
            propose("filesystem.read", vec![]),
            quiet(),
        ]);
        let mut store = InMemoryTaskStore::default();

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker_with_tools_and_budget(
                    &[CapabilityKind::FilesystemRead],
                    1,
                )),
                &CancellationToken::new(),
            )
            .expect("step run");

        // One budgeted model call ran; the second never happened.
        assert_eq!(run.executed.len(), 1);
        assert_eq!(run.model_calls, 1);
        assert!(!run.cancelled);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cancelled_worker_stops_the_loop() {
        let root = test_root();
        let file_path = root.join("note.txt");
        fs::write(&file_path, b"x").expect("write test file");
        let file = file_path.to_str().expect("test path is UTF-8").to_string();
        let grant = root.to_str().expect("test path is UTF-8").to_string();
        let (mut gate, policy, table) = read_setup(&file, &grant);
        let provider = ScriptedProvider::replay(vec![propose("filesystem.read", vec![]), quiet()]);
        let mut store = InMemoryTaskStore::default();
        let mut worker = worker_with_tools(&[CapabilityKind::FilesystemRead]);
        worker.cancel().expect("cancel worker");

        let run = runner()
            .run_steps(
                &mut gate,
                &provider,
                &model_request(),
                &table,
                &policy,
                &mut store,
                "task-1",
                ResourceMode::Normal,
                0,
                3,
                Some(&mut worker),
                &CancellationToken::new(),
            )
            .expect("cancelled run still reports");

        assert!(run.cancelled);
        assert_eq!(provider.calls(), 0);
        assert!(run.executed.is_empty());
        let _ = fs::remove_dir_all(&root);
    }
}
