//! Admission rules for logical, short-lived Mini-ROCKY jobs.

use rocky_domain::{CancelFlag, CapabilityKind, TaskState};
use rocky_resources::{Admission, ResourceGovernor, ResourceMode};

/// Bounds that prevent a task from recursively monopolizing the machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentLimits {
    pub max_active: usize,
    pub max_depth: u8,
    pub max_steps: u32,
}

/// A validated logical worker specification. It is not a model process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSpec {
    pub role: String,
    pub depth: u8,
    pub step_budget: u32,
    pub deadline_ms: u64,
    pub state: TaskState,
    /// Capability kinds this worker may invoke. Empty until a specialist
    /// role binds them: admission grants budgets, roles grant tools.
    pub tools: Vec<CapabilityKind>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnDenial {
    ActiveLimitReached,
    NestingLimitReached,
    EmptyRole,
    ZeroStepBudget,
    MissingDeadline,
    ResourceExhausted,
}

/// Validates worker creation; scheduling and model invocation remain outside this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentScheduler {
    limits: AgentLimits,
}

impl AgentScheduler {
    pub fn new(limits: AgentLimits) -> Self {
        Self { limits }
    }

    /// Admits a worker only if resource pressure allows it. Critical
    /// pressure refuses the spawn outright; every other mode falls through
    /// to the usual budget, depth, and deadline checks, so the scheduler and
    /// the gate read one shared pressure signal. A `Queue` verdict still
    /// admits the spec: the caller enqueues the worker and lets `start`
    /// wait its turn.
    pub fn admit_checked(
        self,
        mode: ResourceMode,
        active_workers: usize,
        role: impl Into<String>,
        depth: u8,
        step_budget: u32,
        deadline_ms: u64,
    ) -> Result<AgentSpec, SpawnDenial> {
        let governor = ResourceGovernor::new(self.limits.max_active);
        if governor.admit(mode, active_workers) == Admission::Reject {
            return Err(SpawnDenial::ResourceExhausted);
        }
        self.admit(active_workers, role, depth, step_budget, deadline_ms)
    }

    pub fn admit(
        self,
        active_workers: usize,
        role: impl Into<String>,
        depth: u8,
        step_budget: u32,
        deadline_ms: u64,
    ) -> Result<AgentSpec, SpawnDenial> {
        if active_workers >= self.limits.max_active {
            return Err(SpawnDenial::ActiveLimitReached);
        }
        if depth > self.limits.max_depth {
            return Err(SpawnDenial::NestingLimitReached);
        }
        let role = role.into();
        if role.trim().is_empty() {
            return Err(SpawnDenial::EmptyRole);
        }
        if step_budget == 0 || step_budget > self.limits.max_steps {
            return Err(SpawnDenial::ZeroStepBudget);
        }
        if deadline_ms == 0 {
            return Err(SpawnDenial::MissingDeadline);
        }
        Ok(AgentSpec {
            role,
            depth,
            step_budget,
            deadline_ms,
            state: TaskState::Created,
            tools: Vec::new(),
        })
    }
}

/// A worker's lifecycle: `Created -> Queued -> Running -> Waiting` with
/// `Completed | Failed | Cancelled | TimedOut` as final states.
///
/// Queued exists so the scheduler's queue accounting cannot be skipped: a
/// worker must be enqueued before it runs. Terminal states accept no further
/// transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerState {
    Created,
    Queued,
    Running,
    Waiting,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

impl WorkerState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::TimedOut
        )
    }
}

/// An admitted logical worker with an explicit lifecycle position.
///
/// Construction takes an [`AgentSpec`] the scheduler already admitted, so
/// budgets and deadlines are validated exactly once at admission. Only the
/// worker and parent-task IDs are validated here.
///
/// Workers compare by value except their cancellation flag: flag handles
/// are shared identity, not comparable state.
#[derive(Clone, Debug)]
pub struct Worker {
    id: String,
    parent_task_id: String,
    spec: AgentSpec,
    state: WorkerState,
    started_at_ms: Option<u64>,
    cancel_flag: CancelFlag,
    steps_used: u32,
}

impl Worker {
    pub fn new(
        id: impl Into<String>,
        parent_task_id: impl Into<String>,
        spec: AgentSpec,
    ) -> Result<Self, WorkerError> {
        let id = id.into();
        let parent_task_id = parent_task_id.into();
        if id.trim().is_empty() {
            return Err(WorkerError::EmptyId);
        }
        if parent_task_id.trim().is_empty() {
            return Err(WorkerError::EmptyParentTask);
        }
        Ok(Self {
            id,
            parent_task_id,
            spec,
            state: WorkerState::Created,
            started_at_ms: None,
            cancel_flag: CancelFlag::new(),
            steps_used: 0,
        })
    }

    /// Cancels this worker's shared flag. The same handle travels to the
    /// gate and executors, so revoking a worker stops its in-flight tool at
    /// the next enforcement boundary.
    pub fn cancel_flag(&self) -> CancelFlag {
        self.cancel_flag.clone()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_flag.is_cancelled()
    }

    /// Records one consumed step against the admitted budget. Past the
    /// budget the worker is exhausted and must stop asking for work: the
    /// orchestrator checks this between steps, so budgets bind even when
    /// the model would happily continue.
    pub fn record_step(&mut self) -> Result<(), WorkerError> {
        if self.is_exhausted() {
            return Err(WorkerError::BudgetExhausted);
        }
        self.steps_used += 1;
        Ok(())
    }

    pub fn steps_remaining(&self) -> u32 {
        self.spec.step_budget.saturating_sub(self.steps_used)
    }

    pub fn is_exhausted(&self) -> bool {
        self.steps_used >= self.spec.step_budget
    }
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The task this worker belongs to. Findings and budgets roll up here,
    /// and cross-task pollution is a construction-time impossibility.
    pub fn parent_task_id(&self) -> &str {
        &self.parent_task_id
    }

    pub fn spec(&self) -> &AgentSpec {
        &self.spec
    }

    /// The role allowlist for this worker. Steps check membership before
    /// any permit is attempted.
    pub fn tools(&self) -> &[CapabilityKind] {
        &self.spec.tools
    }

    pub fn state(&self) -> WorkerState {
        self.state
    }

    pub fn enqueue(&mut self) -> Result<(), WorkerError> {
        self.step(WorkerState::Queued, &[WorkerState::Created])
    }

    pub fn start(&mut self, now_ms: u64) -> Result<(), WorkerError> {
        self.step(WorkerState::Running, &[WorkerState::Queued])?;
        self.started_at_ms = Some(now_ms);
        Ok(())
    }

    pub fn wait(&mut self) -> Result<(), WorkerError> {
        self.step(WorkerState::Waiting, &[WorkerState::Running])
    }

    pub fn resume(&mut self) -> Result<(), WorkerError> {
        self.step(WorkerState::Running, &[WorkerState::Waiting])
    }

    pub fn complete(&mut self) -> Result<(), WorkerError> {
        self.step(
            WorkerState::Completed,
            &[WorkerState::Running, WorkerState::Waiting],
        )
    }

    pub fn fail(&mut self) -> Result<(), WorkerError> {
        self.step(
            WorkerState::Failed,
            &[WorkerState::Running, WorkerState::Waiting],
        )
    }

    pub fn cancel(&mut self) -> Result<(), WorkerError> {
        self.step(
            WorkerState::Cancelled,
            &[
                WorkerState::Created,
                WorkerState::Queued,
                WorkerState::Running,
                WorkerState::Waiting,
            ],
        )?;
        // Cancelling the lifecycle also stops in-flight tools: the shared
        // flag is observed by the gate and executors at their next check.
        self.cancel_flag.cancel();
        Ok(())
    }

    pub fn time_out(&mut self) -> Result<(), WorkerError> {
        self.step(
            WorkerState::TimedOut,
            &[WorkerState::Running, WorkerState::Waiting],
        )
    }

    /// Reports whether the worker's deadline has passed against caller time.
    /// Clocks are supplied, never read: the crate stays testable and free of
    /// ambient time authority. Unstarted workers never expire; saturating
    /// arithmetic keeps extreme clocks panic-free.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        match self.started_at_ms {
            None => false,
            Some(started) => started.saturating_add(self.spec.deadline_ms) <= now_ms,
        }
    }

    fn step(&mut self, next: WorkerState, allowed: &[WorkerState]) -> Result<(), WorkerError> {
        if self.state.is_terminal() {
            return Err(WorkerError::TerminalState);
        }
        if !allowed.contains(&self.state) {
            return Err(WorkerError::InvalidTransition);
        }
        self.state = next;
        Ok(())
    }
}

impl PartialEq for Worker {
    /// Value equality except the cancellation flag: flag handles are shared
    /// identity observed across threads, not comparable worker state.
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.parent_task_id == other.parent_task_id
            && self.spec == other.spec
            && self.state == other.state
            && self.started_at_ms == other.started_at_ms
            && self.steps_used == other.steps_used
    }
}

impl Eq for Worker {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerError {
    EmptyId,
    EmptyParentTask,
    InvalidTransition,
    TerminalState,
    BudgetExhausted,
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "worker error: {self:?}")
    }
}

impl std::error::Error for WorkerError {}

/// Spawns a worker in one step: scheduler admission first, lifecycle entry
/// second. The two validations stay in their home types — budgets and depth
/// at admission, identity at construction — and the combined error says
/// which layer refused.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    scheduler: AgentScheduler,
    active_workers: usize,
    id: impl Into<String>,
    parent_task_id: impl Into<String>,
    role: impl Into<String>,
    depth: u8,
    step_budget: u32,
    deadline_ms: u64,
) -> Result<Worker, SpawnWorkerError> {
    let spec = scheduler.admit(active_workers, role, depth, step_budget, deadline_ms)?;
    Ok(Worker::new(id, parent_task_id, spec)?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpawnWorkerError {
    Admission(SpawnDenial),
    Worker(WorkerError),
}

impl std::fmt::Display for SpawnWorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "spawn error: {self:?}")
    }
}

impl std::error::Error for SpawnWorkerError {}

impl From<SpawnDenial> for SpawnWorkerError {
    fn from(error: SpawnDenial) -> Self {
        Self::Admission(error)
    }
}

impl From<WorkerError> for SpawnWorkerError {
    fn from(error: WorkerError) -> Self {
        Self::Worker(error)
    }
}

/// One highly specialised mini-ROCKY kind: a narrow job description plus the
/// exact capability kinds it may invoke and its own step budget.
///
/// Specialisation is restriction. A role that can read only files cannot be
/// talked into running processes, no matter what the model proposes — the
/// tool list travels with the worker and gates dispatch downstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecialistRole {
    pub name: String,
    pub description: String,
    pub allowed_tools: Vec<CapabilityKind>,
    pub step_budget: u32,
}

impl SpecialistRole {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        allowed_tools: Vec<CapabilityKind>,
        step_budget: u32,
    ) -> Result<Self, RoleError> {
        let name = name.into();
        let description = description.into();
        if name.trim().is_empty() {
            return Err(RoleError::EmptyName);
        }
        if description.trim().is_empty() {
            return Err(RoleError::EmptyDescription);
        }
        if allowed_tools.is_empty() {
            return Err(RoleError::NoTools);
        }
        if step_budget == 0 {
            return Err(RoleError::ZeroStepBudget);
        }
        Ok(Self {
            name,
            description,
            allowed_tools,
            step_budget,
        })
    }

    /// Reports whether this role covers every needed capability kind.
    pub fn covers(&self, needed: &[CapabilityKind]) -> bool {
        needed.iter().all(|kind| self.allowed_tools.contains(kind))
    }
}

/// The known specialist kinds ROCKY can start. Selection is deterministic —
/// no model call decides who works — so routing stays auditable and cheap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpecialistRegistry {
    roles: Vec<SpecialistRole>,
}

impl SpecialistRegistry {
    pub fn new(roles: Vec<SpecialistRole>) -> Result<Self, RoleError> {
        if roles.is_empty() {
            return Err(RoleError::EmptyRegistry);
        }
        let mut names = Vec::with_capacity(roles.len());
        for role in &roles {
            if names.contains(&role.name) {
                return Err(RoleError::DuplicateRole(role.name.clone()));
            }
            names.push(role.name.clone());
        }
        Ok(Self { roles })
    }

    /// Returns every role covering all needed capability kinds, ordered by
    /// least privilege (fewest unneeded tools) and then by name, so the
    /// answer is deterministic. The caller picks the head: the mini-ROCKY
    /// that can do the job with the smallest authority.
    pub fn select_for_capability(&self, needed: &[CapabilityKind]) -> Vec<&SpecialistRole> {
        let mut matched: Vec<&SpecialistRole> = self
            .roles
            .iter()
            .filter(|role| role.covers(needed))
            .collect();
        matched.sort_by(|a, b| {
            let extra = |role: &&SpecialistRole| {
                role.allowed_tools
                    .iter()
                    .filter(|kind| !needed.contains(kind))
                    .count()
            };
            extra(a).cmp(&extra(b)).then_with(|| a.name.cmp(&b.name))
        });
        matched
    }
}

/// Spawns a worker as a named specialist: scheduler admission supplies the
/// budgets, the role supplies the name, step budget, and tool allowlist.
#[allow(clippy::too_many_arguments)]
pub fn spawn_specialist(
    scheduler: AgentScheduler,
    active_workers: usize,
    id: impl Into<String>,
    parent_task_id: impl Into<String>,
    role: &SpecialistRole,
    depth: u8,
    deadline_ms: u64,
) -> Result<Worker, SpawnWorkerError> {
    let mut spec = scheduler.admit(
        active_workers,
        role.name.clone(),
        depth,
        role.step_budget,
        deadline_ms,
    )?;
    spec.tools = role.allowed_tools.clone();
    Ok(Worker::new(id, parent_task_id, spec)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoleError {
    EmptyName,
    EmptyDescription,
    NoTools,
    ZeroStepBudget,
    EmptyRegistry,
    DuplicateRole(String),
}

impl std::fmt::Display for RoleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "specialist role error: {self:?}")
    }
}

impl std::error::Error for RoleError {}

/// Maximum subtasks per decomposition. Fan-out is bounded like everything
/// else: each subtask still passes individual scheduler admission.
pub const MAX_SUBTASKS: usize = 8;

/// One decomposed unit of work: an admitted worker spec plus its identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubtaskSpec {
    pub id: String,
    pub goal: String,
    pub spec: AgentSpec,
}

/// Splits a goal into validated subtasks one level deeper.
///
/// Every subtask passes the same [`AgentScheduler`] admission a lone worker
/// would, so decomposition can neither exceed worker capacity nor nesting
/// depth. Budgets and deadlines apply per subtask; dividing a parent budget
/// is the caller's policy, not this function's.
#[allow(clippy::too_many_arguments)]
pub fn decompose(
    limits: &AgentLimits,
    task_id: &str,
    goal: &str,
    role: &str,
    count: usize,
    step_budget: u32,
    deadline_ms: u64,
    parent_depth: u8,
    active_workers: usize,
) -> Result<Vec<SubtaskSpec>, DecomposeError> {
    if task_id.trim().is_empty() {
        return Err(DecomposeError::EmptyTask);
    }
    if goal.trim().is_empty() {
        return Err(DecomposeError::EmptyGoal);
    }
    if count == 0 {
        return Err(DecomposeError::EmptyDecomposition);
    }
    if count > MAX_SUBTASKS {
        return Err(DecomposeError::TooManySubtasks);
    }
    let depth = parent_depth.checked_add(1).ok_or(DecomposeError::TooDeep)?;
    if depth > limits.max_depth {
        return Err(DecomposeError::TooDeep);
    }
    if active_workers.saturating_add(count) > limits.max_active {
        return Err(DecomposeError::OverCapacity);
    }
    let scheduler = AgentScheduler::new(*limits);
    let mut subtasks = Vec::with_capacity(count);
    for index in 0..count {
        let spec = scheduler.admit(
            active_workers + index,
            role,
            depth,
            step_budget,
            deadline_ms,
        )?;
        subtasks.push(SubtaskSpec {
            id: format!("{task_id}-s{}", index + 1),
            goal: goal.into(),
            spec,
        });
    }
    Ok(subtasks)
}

/// Returns the strongest finding: highest confidence, earliest posted on
/// ties. Aggregation reads; it never mutates the board.
pub fn best_finding(board: &FindingBoard) -> Option<&Finding> {
    let mut best: Option<&Finding> = None;
    for finding in board.findings() {
        let replace = match &best {
            None => true,
            Some(current) => finding.confidence_pct > current.confidence_pct,
        };
        if replace {
            best = Some(finding);
        }
    }
    best
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecomposeError {
    EmptyTask,
    EmptyGoal,
    EmptyDecomposition,
    TooManySubtasks,
    OverCapacity,
    TooDeep,
    Spawn(SpawnDenial),
}

impl std::fmt::Display for DecomposeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "decomposition error: {self:?}")
    }
}

impl std::error::Error for DecomposeError {}

impl From<SpawnDenial> for DecomposeError {
    fn from(error: SpawnDenial) -> Self {
        Self::Spawn(error)
    }
}

/// Maximum affected artifacts per finding. The blackboard is bounded memory,
// not a fact store: findings point at evidence, they do not inline it.
pub const MAX_ARTIFACTS: usize = 16;

/// A structured worker finding: hypothesis plus a pointer to its evidence.
///
/// Findings are data for aggregation, never authority: posting one grants no
/// capability and changes no permission. Confidence is an integer percent so
/// every value in range is valid by construction and no float parsing can
/// smuggle NaN past validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub id: String,
    pub task_id: String,
    pub source_agent: String,
    pub hypothesis: String,
    pub evidence_ref: String,
    pub confidence_pct: u8,
    pub affected_artifacts: Vec<String>,
    pub recommended_action: String,
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        task_id: impl Into<String>,
        source_agent: impl Into<String>,
        hypothesis: impl Into<String>,
        evidence_ref: impl Into<String>,
        confidence_pct: u8,
        affected_artifacts: Vec<String>,
        recommended_action: impl Into<String>,
    ) -> Result<Self, BoardError> {
        let id = id.into();
        let task_id = task_id.into();
        let source_agent = source_agent.into();
        let hypothesis = hypothesis.into();
        let evidence_ref = evidence_ref.into();
        let recommended_action = recommended_action.into();
        if id.trim().is_empty() {
            return Err(BoardError::EmptyId);
        }
        if task_id.trim().is_empty() {
            return Err(BoardError::EmptyTask);
        }
        if source_agent.trim().is_empty() {
            return Err(BoardError::EmptySource);
        }
        if hypothesis.trim().is_empty() {
            return Err(BoardError::EmptyHypothesis);
        }
        if evidence_ref.trim().is_empty() {
            return Err(BoardError::EmptyEvidence);
        }
        if recommended_action.trim().is_empty() {
            return Err(BoardError::EmptyAction);
        }
        if confidence_pct > 100 {
            return Err(BoardError::BadConfidence);
        }
        if affected_artifacts.len() > MAX_ARTIFACTS {
            return Err(BoardError::TooManyArtifacts);
        }
        if affected_artifacts.iter().any(|item| item.trim().is_empty()) {
            return Err(BoardError::EmptyArtifact);
        }
        Ok(Self {
            id,
            task_id,
            source_agent,
            hypothesis,
            evidence_ref,
            confidence_pct,
            affected_artifacts,
            recommended_action,
        })
    }
}

/// An append-only blackboard for one task's findings.
///
/// Workers publish; nothing edits or deletes. The board is created for a
/// single task and rejects findings from any other task, so one task's
/// workers can never pollute another task's aggregation. Capacity is fixed
/// at construction to bound memory on a laptop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FindingBoard {
    task_id: String,
    capacity: usize,
    findings: Vec<Finding>,
}

impl FindingBoard {
    pub fn new(task_id: impl Into<String>, capacity: usize) -> Result<Self, BoardError> {
        let task_id = task_id.into();
        if task_id.trim().is_empty() {
            return Err(BoardError::EmptyTask);
        }
        if capacity == 0 {
            return Err(BoardError::ZeroCapacity);
        }
        Ok(Self {
            task_id,
            capacity,
            findings: Vec::new(),
        })
    }

    /// The single task this board collects for. Publishers correlate
    /// outbound events with this ID so findings can never fan out elsewhere.
    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    /// Publishes a finding and returns its 1-based sequence number.
    pub fn post(&mut self, finding: Finding) -> Result<u64, BoardError> {
        if finding.task_id != self.task_id {
            return Err(BoardError::WrongTask);
        }
        if self.findings.iter().any(|item| item.id == finding.id) {
            return Err(BoardError::DuplicateFinding);
        }
        if self.findings.len() >= self.capacity {
            return Err(BoardError::BoardFull);
        }
        self.findings.push(finding);
        Ok(self.findings.len() as u64)
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoardError {
    EmptyId,
    EmptyTask,
    EmptySource,
    EmptyHypothesis,
    EmptyEvidence,
    EmptyAction,
    EmptyArtifact,
    BadConfidence,
    TooManyArtifacts,
    ZeroCapacity,
    WrongTask,
    BoardFull,
    DuplicateFinding,
}

impl std::fmt::Display for BoardError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "finding board error: {self:?}")
    }
}

impl std::error::Error for BoardError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduler() -> AgentScheduler {
        AgentScheduler::new(AgentLimits {
            max_active: 3,
            max_depth: 1,
            max_steps: 10,
        })
    }

    #[test]
    fn prevents_recursive_agent_spawning() {
        assert_eq!(
            scheduler().admit(0, "researcher", 2, 3, 1000),
            Err(SpawnDenial::NestingLimitReached)
        );
    }

    #[test]
    fn requires_a_finite_deadline_and_budget() {
        assert_eq!(
            scheduler().admit(0, "researcher", 1, 0, 1000),
            Err(SpawnDenial::ZeroStepBudget)
        );
        assert_eq!(
            scheduler().admit(0, "researcher", 1, 3, 0),
            Err(SpawnDenial::MissingDeadline)
        );
    }

    fn finding(id: &str) -> Finding {
        Finding::new(
            id,
            "task-1",
            "researcher",
            "The config file pins the port",
            "evidence:config.toml:12",
            80,
            vec!["config.toml".into()],
            "Restart with the pinned port",
        )
        .expect("valid test finding")
    }

    fn board() -> FindingBoard {
        FindingBoard::new("task-1", 8).expect("valid test board")
    }

    #[test]
    fn board_accepts_a_valid_finding() {
        let mut board = board();
        assert_eq!(board.post(finding("f-1")), Ok(1));
        assert_eq!(board.len(), 1);
        assert_eq!(
            board.findings()[0].hypothesis,
            "The config file pins the port"
        );
    }

    #[test]
    fn board_rejects_findings_for_another_task() {
        let mut board = board();
        let outsider = Finding::new(
            "f-9",
            "task-2",
            "researcher",
            "Something elsewhere",
            "evidence:x",
            50,
            vec![],
            "Ignore it",
        )
        .expect("valid test finding");

        assert_eq!(board.post(outsider), Err(BoardError::WrongTask));
        assert_eq!(board.len(), 0);
    }

    #[test]
    fn board_rejects_posts_beyond_capacity() {
        let mut board = FindingBoard::new("task-1", 1).expect("valid test board");
        assert_eq!(board.post(finding("f-1")), Ok(1));
        assert_eq!(board.post(finding("f-2")), Err(BoardError::BoardFull));
    }

    #[test]
    fn board_rejects_duplicate_ids() {
        let mut board = board();
        assert_eq!(board.post(finding("f-1")), Ok(1));
        assert_eq!(
            board.post(finding("f-1")),
            Err(BoardError::DuplicateFinding)
        );
    }

    #[test]
    fn findings_reject_blank_fields() {
        assert_eq!(
            Finding::new("", "task-1", "r", "h", "e", 50, vec![], "a"),
            Err(BoardError::EmptyId)
        );
        assert_eq!(
            Finding::new("f", "task-1", "r", "  ", "e", 50, vec![], "a"),
            Err(BoardError::EmptyHypothesis)
        );
        assert_eq!(
            Finding::new("f", "task-1", "r", "h", "e", 50, vec!["  ".into()], "a"),
            Err(BoardError::EmptyArtifact)
        );
    }

    #[test]
    fn findings_reject_unbounded_artifact_lists() {
        let artifacts = vec!["a".to_string(); MAX_ARTIFACTS + 1];
        assert_eq!(
            Finding::new("f", "task-1", "r", "h", "e", 50, artifacts, "a"),
            Err(BoardError::TooManyArtifacts)
        );
    }

    #[test]
    fn board_rejects_zero_capacity() {
        assert_eq!(
            FindingBoard::new("task-1", 0),
            Err(BoardError::ZeroCapacity)
        );
    }

    fn worker(id: &str) -> Worker {
        let spec = scheduler()
            .admit(0, "researcher", 1, 3, 1000)
            .expect("valid test spec");
        Worker::new(id, "task-1", spec).expect("valid test worker")
    }

    #[test]
    fn worker_lifecycle_follows_created_queued_running() {
        let mut worker = worker("w-1");
        assert_eq!(worker.state(), WorkerState::Created);
        worker.enqueue().expect("enqueue");
        assert_eq!(worker.state(), WorkerState::Queued);
        worker.start(1000).expect("start");
        assert_eq!(worker.state(), WorkerState::Running);
        worker.wait().expect("wait");
        assert_eq!(worker.state(), WorkerState::Waiting);
        worker.resume().expect("resume");
        assert_eq!(worker.state(), WorkerState::Running);
    }

    #[test]
    fn worker_rejects_a_blank_id() {
        let spec = scheduler()
            .admit(0, "researcher", 1, 3, 1000)
            .expect("valid test spec");
        assert_eq!(Worker::new("  ", "task-1", spec), Err(WorkerError::EmptyId));
    }

    #[test]
    fn worker_belongs_to_its_parent_task() {
        let spec = scheduler()
            .admit(0, "researcher", 1, 3, 1000)
            .expect("valid test spec");
        assert_eq!(
            Worker::new("w-1", "  ", spec.clone()),
            Err(WorkerError::EmptyParentTask)
        );
        assert_eq!(worker("w-1").parent_task_id(), "task-1");
    }

    #[test]
    fn worker_deadlines_expire_against_caller_time() {
        let mut worker = worker("w-1");
        // Unstarted work cannot expire: no clock has started ticking.
        assert!(!worker.is_expired(9_999_999));
        worker.enqueue().expect("enqueue");
        worker.start(500).expect("start");
        assert!(!worker.is_expired(1_499));
        assert!(worker.is_expired(1_500));
    }

    #[test]
    fn worker_expiry_never_panics_on_extreme_clocks() {
        let mut worker = worker("w-1");
        worker.enqueue().expect("enqueue");
        worker.start(u64::MAX).expect("start");
        // Saturating arithmetic caps instead of panicking; with the clock
        // pinned at max, the deadline has trivially elapsed.
        assert!(worker.is_expired(u64::MAX));
    }

    #[test]
    fn worker_terminal_states_are_final() {
        let mut worker = worker("w-1");
        worker.enqueue().expect("enqueue");
        worker.start(1000).expect("start");
        worker.complete().expect("complete");
        assert_eq!(worker.state(), WorkerState::Completed);
        assert_eq!(worker.start(1000), Err(WorkerError::TerminalState));
        assert_eq!(worker.complete(), Err(WorkerError::TerminalState));
    }

    #[test]
    fn worker_timeout_and_cancel_paths_end_work() {
        let mut running = worker("w-1");
        running.enqueue().expect("enqueue");
        running.start(1000).expect("start");
        running.time_out().expect("time out");
        assert_eq!(running.state(), WorkerState::TimedOut);

        let mut queued = worker("w-2");
        queued.enqueue().expect("enqueue");
        queued.cancel().expect("cancel");
        assert_eq!(queued.state(), WorkerState::Cancelled);
    }

    #[test]
    fn worker_skips_no_steps() {
        let mut worker = worker("w-1");
        // Created cannot start without enqueueing: the scheduler must first
        // admit resource placement, otherwise queue accounting lies.
        assert_eq!(worker.start(1000), Err(WorkerError::InvalidTransition));
        assert_eq!(worker.state(), WorkerState::Created);
    }

    fn limits() -> AgentLimits {
        AgentLimits {
            max_active: 3,
            max_depth: 1,
            max_steps: 10,
        }
    }

    #[test]
    fn decomposition_splits_work_into_bounded_subtasks() {
        let subtasks = decompose(
            &limits(),
            "task-1",
            "Map the repo",
            "scout",
            2,
            3,
            1000,
            0,
            0,
        )
        .expect("valid decomposition");

        assert_eq!(subtasks.len(), 2);
        assert_eq!(subtasks[0].id, "task-1-s1");
        assert_eq!(subtasks[1].id, "task-1-s2");
        assert_eq!(subtasks[0].goal, "Map the repo");
        assert_eq!(subtasks[0].spec.depth, 1);
        assert_eq!(subtasks[0].spec.step_budget, 3);
    }

    #[test]
    fn decomposition_rejects_nonsense_counts() {
        assert_eq!(
            decompose(&limits(), "task-1", "goal", "scout", 0, 3, 1000, 0, 0),
            Err(DecomposeError::EmptyDecomposition)
        );
        assert_eq!(
            decompose(
                &limits(),
                "task-1",
                "goal",
                "scout",
                MAX_SUBTASKS + 1,
                3,
                1000,
                0,
                0
            ),
            Err(DecomposeError::TooManySubtasks)
        );
        assert_eq!(
            decompose(&limits(), "  ", "goal", "scout", 1, 3, 1000, 0, 0),
            Err(DecomposeError::EmptyTask)
        );
    }

    #[test]
    fn decomposition_respects_scheduler_capacity_and_depth() {
        assert_eq!(
            decompose(&limits(), "task-1", "goal", "scout", 1, 3, 1000, 0, 3),
            Err(DecomposeError::OverCapacity)
        );
        assert_eq!(
            decompose(&limits(), "task-1", "goal", "scout", 1, 3, 1000, 1, 0),
            Err(DecomposeError::TooDeep)
        );
        assert_eq!(
            decompose(&limits(), "task-1", "goal", "scout", 1, 0, 1000, 0, 0),
            Err(DecomposeError::Spawn(SpawnDenial::ZeroStepBudget))
        );
    }

    #[test]
    fn aggregation_prefers_the_strongest_earliest_finding() {
        let mut board = FindingBoard::new("task-1", 8).expect("valid test board");
        assert_eq!(best_finding(&board), None);
        let weak = Finding::new("f-1", "task-1", "a", "hunch", "e1", 40, vec![], "x")
            .expect("valid test finding");
        let strong = Finding::new("f-2", "task-1", "b", "proof", "e2", 90, vec![], "y")
            .expect("valid test finding");
        let tied = Finding::new("f-3", "task-1", "c", "also", "e3", 90, vec![], "z")
            .expect("valid test finding");
        board.post(weak).expect("post finding");
        board.post(strong).expect("post finding");
        board.post(tied).expect("post finding");

        assert_eq!(best_finding(&board).expect("best finding").id, "f-2");
    }

    #[test]
    fn spawn_combines_admission_with_lifecycle() {
        let scheduler = scheduler();
        let worker =
            spawn(scheduler, 0, "w-1", "task-1", "researcher", 1, 3, 1000).expect("spawn worker");

        assert_eq!(worker.id(), "w-1");
        assert_eq!(worker.state(), WorkerState::Created);
        assert_eq!(worker.spec().role, "researcher");
    }

    #[test]
    fn spawn_reports_which_layer_refused() {
        let scheduler = scheduler();
        assert_eq!(
            spawn(scheduler, 0, "  ", "task-1", "researcher", 1, 3, 1000),
            Err(SpawnWorkerError::Worker(WorkerError::EmptyId))
        );
        assert_eq!(
            spawn(scheduler, 3, "w-9", "task-1", "researcher", 1, 3, 1000),
            Err(SpawnWorkerError::Admission(SpawnDenial::ActiveLimitReached))
        );
    }

    use rocky_domain::CapabilityKind;

    fn reader() -> SpecialistRole {
        SpecialistRole::new(
            "reader",
            "Reads files and reports findings",
            vec![CapabilityKind::FilesystemRead],
            5,
        )
        .expect("valid test role")
    }

    fn editor() -> SpecialistRole {
        SpecialistRole::new(
            "editor",
            "Reads and edits files",
            vec![
                CapabilityKind::FilesystemRead,
                CapabilityKind::FilesystemWrite,
            ],
            8,
        )
        .expect("valid test role")
    }

    fn registry() -> SpecialistRegistry {
        SpecialistRegistry::new(vec![editor(), reader()]).expect("valid test registry")
    }

    #[test]
    fn selection_prefers_the_least_privileged_cover() {
        // Both cover FilesystemRead, but the reader needs no extra powers:
        // least privilege sorts first, name breaks ties deterministically.
        let registry = registry();
        let matched = registry.select_for_capability(&[CapabilityKind::FilesystemRead]);
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[0].name, "reader");
        assert_eq!(matched[1].name, "editor");
    }

    #[test]
    fn selection_returns_nothing_without_a_cover() {
        let registry = registry();
        assert!(
            registry
                .select_for_capability(&[CapabilityKind::NetworkConnect])
                .is_empty()
        );
    }

    #[test]
    fn registry_rejects_misconfiguration() {
        assert_eq!(
            SpecialistRegistry::new(Vec::new()),
            Err(RoleError::EmptyRegistry)
        );
        assert_eq!(
            SpecialistRegistry::new(vec![reader(), reader()]),
            Err(RoleError::DuplicateRole("reader".into()))
        );
        assert_eq!(
            SpecialistRole::new("  ", "desc", vec![CapabilityKind::FilesystemRead], 5),
            Err(RoleError::EmptyName)
        );
        assert_eq!(
            SpecialistRole::new("x", "desc", Vec::new(), 5),
            Err(RoleError::NoTools)
        );
        assert_eq!(
            SpecialistRole::new("x", "desc", vec![CapabilityKind::FilesystemRead], 0),
            Err(RoleError::ZeroStepBudget)
        );
    }

    #[test]
    fn spawn_specialist_wires_role_into_worker() {
        let worker = spawn_specialist(scheduler(), 0, "w-1", "task-1", &reader(), 1, 1000)
            .expect("spawn specialist");

        assert_eq!(worker.id(), "w-1");
        assert_eq!(worker.parent_task_id(), "task-1");
        assert_eq!(worker.spec().role, "reader");
        assert_eq!(worker.spec().step_budget, 5);
        assert_eq!(worker.spec().tools, vec![CapabilityKind::FilesystemRead]);
        assert_eq!(worker.state(), WorkerState::Created);
    }

    #[test]
    fn spawn_specialist_respects_scheduler_limits() {
        assert_eq!(
            spawn_specialist(scheduler(), 3, "w-9", "task-1", &reader(), 1, 1000),
            Err(SpawnWorkerError::Admission(SpawnDenial::ActiveLimitReached))
        );
    }

    #[test]
    fn worker_cancellation_is_shared_and_observable() {
        let mut worker = worker("w-1");
        let shared = worker.cancel_flag();

        assert!(!worker.is_cancelled());
        // Lifecycle cancellation trips the shared flag too, so the gate and
        // executors observe it at their next check.
        worker.cancel().expect("cancel worker");
        assert_eq!(worker.state(), WorkerState::Cancelled);
        assert!(worker.is_cancelled());
        assert!(shared.is_cancelled());
    }

    #[test]
    fn admission_refuses_spawns_under_critical_pressure() {
        assert_eq!(
            scheduler().admit_checked(ResourceMode::Critical, 0, "researcher", 1, 3, 1000),
            Err(SpawnDenial::ResourceExhausted)
        );
    }

    #[test]
    fn admission_survives_constrained_pressure_as_queued_work() {
        // Constrained pressure does not refuse the worker: it admits the
        // spec so the caller can enqueue it and let `start` wait its turn.
        // ResourceMode comes from the shared resources crate, proving the
        // scheduler reads the same pressure signal as the gate.
        let spec = scheduler()
            .admit_checked(ResourceMode::Constrained, 1, "researcher", 1, 3, 1000)
            .expect("constrained admission");
        assert_eq!(spec.role, "researcher");
    }

    #[test]
    fn worker_steps_consume_the_budget() {
        let mut worker = worker("w-1");
        assert_eq!(worker.steps_remaining(), 3);
        worker.record_step().expect("step one");
        worker.record_step().expect("step two");
        assert_eq!(worker.steps_remaining(), 1);
        assert!(!worker.is_exhausted());
        worker.record_step().expect("step three");
        assert!(worker.is_exhausted());
        assert_eq!(worker.record_step(), Err(WorkerError::BudgetExhausted));
    }
}
