//! Rocky desktop shell: Tauri adapters over the authorization boundary.
//!
//! Every command here is a thin shell: validate shape, call exactly one
//! core function (`driver`, `decisions`, store reads), and return a view.
//! No policy, permit, or approval logic lives in this crate — a compromised
//! WebView sending well-formed invokes gains nothing the core did not grant.
//!
//! Testability rule: all behavior lives in plain `do_*` functions taking
//! `&AppState`. The `#[tauri::command]` wrappers only adapt framework
//! types, because `tauri::State` cannot be constructed in unit tests.

use rocky_domain::{Capability, CapabilityKind, GoalContract, TaskState};
use rocky_ipc::{CommandPayload, EventStream, IpcCommand};
use rocky_runtime::decisions::{approve_command_decision, deny_command_decision};
use rocky_runtime::driver;
use rocky_runtime::session::TaskSession;
use rocky_storage::{ContractStore, SqliteTaskStore, TaskStore};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Read-only task projection for the frontend. The UI renders views; it
/// never sees permits, policies, or secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TaskView {
    pub id: String,
    pub goal: String,
    pub state: String,
    pub revision: u64,
}

fn view_of(task_id: &str, goal: &str, state: TaskState, revision: u64) -> TaskView {
    TaskView {
        id: task_id.into(),
        goal: goal.into(),
        state: format!("{state:?}"),
        revision,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ContractView {
    pub task_id: String,
    pub goal: String,
    pub constraints: Vec<String>,
}

/// Application state behind the commands. One store, one event stream, one
/// ID counter: everything a command needs, nothing it can abuse.
pub struct AppState {
    store: Mutex<SqliteTaskStore>,
    events: Mutex<EventStream>,
    next_id: AtomicU64,
}

impl AppState {
    pub fn open_in_memory() -> Result<Self, String> {
        Ok(Self {
            store: Mutex::new(SqliteTaskStore::open_in_memory().map_err(stringify)?),
            events: Mutex::new(EventStream::default()),
            next_id: AtomicU64::new(1),
        })
    }

    fn fresh_id(&self, prefix: &str) -> String {
        format!("{prefix}-{}", self.next_id.fetch_add(1, Ordering::SeqCst))
    }

    fn now_unix_secs() -> Result<u64, String> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(stringify)
    }
}

fn stringify(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn parse_capability_kind(kind: &str) -> Result<CapabilityKind, String> {
    match kind {
        "filesystem.read" => Ok(CapabilityKind::FilesystemRead),
        "filesystem.write" => Ok(CapabilityKind::FilesystemWrite),
        "process.execute" => Ok(CapabilityKind::ProcessExecute),
        "network.connect" => Ok(CapabilityKind::NetworkConnect),
        "browser.interact" => Ok(CapabilityKind::BrowserInteract),
        _ => Err(format!("unknown capability kind: {kind}")),
    }
}

fn lock_store(state: &AppState) -> Result<std::sync::MutexGuard<'_, SqliteTaskStore>, String> {
    state
        .store
        .lock()
        .map_err(|_| "store lock poisoned".to_string())
}

fn lock_events(state: &AppState) -> Result<std::sync::MutexGuard<'_, EventStream>, String> {
    state
        .events
        .lock()
        .map_err(|_| "event stream lock poisoned".to_string())
}

/// Submits a goal: validates the command, freezes the contract, starts the
/// session. Returns the created task view.
///
/// The explicit `&mut *store` derefs below are load-bearing: deref coercion
/// does not apply through generic `impl Trait` bounds, so clippy's
/// auto-deref suggestion does not compile here.
#[allow(clippy::explicit_auto_deref)]
pub fn do_submit_goal(
    state: &AppState,
    goal: String,
    constraints: Vec<String>,
) -> Result<TaskView, String> {
    let task_id = state.fresh_id("task");
    let command = IpcCommand::new(
        state.fresh_id("cmd"),
        task_id.clone(),
        CommandPayload::SubmitGoal { goal, constraints },
    )
    .map_err(stringify)?;
    let mut store = lock_store(state)?;
    let mut events = lock_events(state)?;
    let (session, _) =
        driver::submit_goal(&mut *store, &mut *events, &command).map_err(stringify)?;
    let record = store
        .get(session.task_id())
        .map_err(stringify)?
        .ok_or_else(|| "task vanished after submit".to_string())?;
    Ok(view_of(
        &record.id,
        &record.user_goal,
        record.state,
        record.revision,
    ))
}

/// Lists every task in ID order for the workspace view.
pub fn do_list_tasks(state: &AppState) -> Result<Vec<TaskView>, String> {
    let store = lock_store(state)?;
    let tasks = store.list_tasks().map_err(stringify)?;
    Ok(tasks
        .iter()
        .map(|task| view_of(&task.id, &task.user_goal, task.state, task.revision))
        .collect())
}

/// Queries one task. Read-only.
pub fn do_query_task(state: &AppState, task_id: String) -> Result<TaskView, String> {
    let command =
        IpcCommand::new("cmd-query", task_id, CommandPayload::QueryTask).map_err(stringify)?;
    let store = lock_store(state)?;
    let snapshot = driver::query_task(&*store, &command).map_err(stringify)?;
    Ok(view_of(
        &snapshot.task_id,
        &snapshot.goal,
        snapshot.state,
        snapshot.revision,
    ))
}

/// Cancels a task's session. Only the matching session advances.
#[allow(clippy::explicit_auto_deref)]
pub fn do_cancel_task(state: &AppState, task_id: String) -> Result<TaskView, String> {
    let command = IpcCommand::new("cmd-cancel", task_id.clone(), CommandPayload::CancelTask)
        .map_err(stringify)?;
    let mut store = lock_store(state)?;
    let mut events = lock_events(state)?;
    let mut session = TaskSession::load(&*store, &task_id).map_err(stringify)?;
    driver::cancel_task(&mut session, &mut *store, &mut *events, &command).map_err(stringify)?;
    let record = store
        .get(session.task_id())
        .map_err(stringify)?
        .ok_or_else(|| "task vanished after cancel".to_string())?;
    Ok(view_of(
        &record.id,
        &record.user_goal,
        record.state,
        record.revision,
    ))
}

/// Records a user approval for one action hash with a bounded lifetime.
/// Returns whether the grant is currently usable.
pub fn do_approve_action(
    state: &AppState,
    action_hash: String,
    capability_kind: String,
    capability_scope: String,
    expires_in_secs: u64,
) -> Result<bool, String> {
    let command = IpcCommand::new(
        "cmd-approve",
        "approval",
        CommandPayload::ApproveAction {
            action_hash: action_hash.clone(),
        },
    )
    .map_err(stringify)?;
    let kind = parse_capability_kind(&capability_kind)?;
    let capability = Capability::new(kind, capability_scope).map_err(stringify)?;
    let now = AppState::now_unix_secs()?;
    let expires_at = now
        .checked_add(expires_in_secs)
        .filter(|expiry| *expiry > now)
        .ok_or_else(|| "expiry must lie in the future".to_string())?;
    let mut store = lock_store(state)?;
    let record = approve_command_decision(&mut *store, &command, &capability, now, expires_at)
        .map_err(stringify)?;
    Ok(record.is_valid_at(now))
}

/// Denies an action, retracting any approval for its hash.
pub fn do_deny_action(state: &AppState, action_hash: String) -> Result<bool, String> {
    let command = IpcCommand::new(
        "cmd-deny",
        "approval",
        CommandPayload::DenyAction { action_hash },
    )
    .map_err(stringify)?;
    let mut store = lock_store(state)?;
    deny_command_decision(&mut *store, &command).map_err(stringify)
}

/// Reads a task's frozen contract for the inspection view.
pub fn do_inspect_contract(state: &AppState, task_id: String) -> Result<ContractView, String> {
    let store = lock_store(state)?;
    let contract: GoalContract = store
        .load_contract(&task_id)
        .map_err(stringify)?
        .ok_or_else(|| "no contract for task".to_string())?;
    Ok(ContractView {
        task_id: contract.task_id().into(),
        goal: contract.goal().into(),
        constraints: contract.constraints().to_vec(),
    })
}

#[tauri::command]
pub fn submit_goal(
    state: tauri::State<'_, AppState>,
    goal: String,
    constraints: Vec<String>,
) -> Result<TaskView, String> {
    do_submit_goal(&state, goal, constraints)
}

#[tauri::command]
pub fn list_tasks(state: tauri::State<'_, AppState>) -> Result<Vec<TaskView>, String> {
    do_list_tasks(&state)
}

#[tauri::command]
pub fn query_task(state: tauri::State<'_, AppState>, task_id: String) -> Result<TaskView, String> {
    do_query_task(&state, task_id)
}

#[tauri::command]
pub fn cancel_task(state: tauri::State<'_, AppState>, task_id: String) -> Result<TaskView, String> {
    do_cancel_task(&state, task_id)
}

#[tauri::command]
pub fn approve_action(
    state: tauri::State<'_, AppState>,
    action_hash: String,
    capability_kind: String,
    capability_scope: String,
    expires_in_secs: u64,
) -> Result<bool, String> {
    do_approve_action(
        &state,
        action_hash,
        capability_kind,
        capability_scope,
        expires_in_secs,
    )
}

#[tauri::command]
pub fn deny_action(state: tauri::State<'_, AppState>, action_hash: String) -> Result<bool, String> {
    do_deny_action(&state, action_hash)
}

#[tauri::command]
pub fn inspect_contract(
    state: tauri::State<'_, AppState>,
    task_id: String,
) -> Result<ContractView, String> {
    do_inspect_contract(&state, task_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState::open_in_memory().expect("test state")
    }

    #[test]
    fn submit_then_list_round_trips_through_commands() {
        let state = state();
        let created = do_submit_goal(&state, "Read a document".into(), vec!["read-only".into()])
            .expect("submit goal");

        assert_eq!(created.goal, "Read a document");
        let listed = do_list_tasks(&state).expect("list tasks");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], created);
    }

    #[test]
    fn query_and_cancel_flow_through_commands() {
        let state = state();
        let created = do_submit_goal(&state, "Run a tool".into(), Vec::new()).expect("submit");

        let snapshot = do_query_task(&state, created.id.clone()).expect("query task");
        assert_eq!(snapshot, created);
        let cancelled = do_cancel_task(&state, created.id).expect("cancel task");
        assert_eq!(cancelled.state, "Cancelled");
    }

    #[test]
    fn approve_then_deny_flows_through_commands() {
        let state = state();
        assert!(do_approve_action(
            &state,
            "abc123".into(),
            "filesystem.write".into(),
            "C:/workspace".into(),
            3_600,
        )
        .expect("approve action"));
        assert!(do_deny_action(&state, "abc123".into()).expect("deny action"));
        assert_eq!(
            do_approve_action(
                &state,
                "abc123".into(),
                "nope.unknown".into(),
                "C:/workspace".into(),
                3_600,
            )
            .unwrap_err(),
            "unknown capability kind: nope.unknown"
        );
    }

    #[test]
    fn submit_rejects_blank_goals_at_the_command_edge() {
        let state = state();
        assert!(do_submit_goal(&state, "  ".into(), Vec::new()).is_err());
    }

    #[test]
    fn inspect_contract_shows_the_frozen_scope() {
        let state = state();
        let created = do_submit_goal(
            &state,
            "Read a document".into(),
            vec!["read-only".into(), "no-network".into()],
        )
        .expect("submit goal");

        let contract = do_inspect_contract(&state, created.id).expect("inspect contract");
        assert_eq!(contract.goal, "Read a document");
        assert_eq!(contract.constraints, vec!["read-only", "no-network"]);
    }
}
