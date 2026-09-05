//! Rocky desktop shell crate root.
//!
//! Command handlers live in [`commands`] (a submodule, because Tauri's
//! command macro collides with `pub` items at the crate root). This root
//! only re-exports and starts the shell.

pub mod commands;

use commands::{
    approve_action, cancel_task, deny_action, inspect_contract, list_tasks, query_task,
    submit_goal, AppState,
};

/// Starts the desktop shell. State construction is the only fallible step
/// surfaced here; everything after is framework event loop.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state = AppState::open_in_memory().expect("initial application state");
    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            submit_goal,
            list_tasks,
            query_task,
            cancel_task,
            approve_action,
            deny_action,
            inspect_contract,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
