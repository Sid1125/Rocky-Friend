//! Board persistence: worker findings become task records.
//!
//! The bridge copies validated board findings into the authoritative store.
//! Already-persisted findings are skipped by ID so re-syncs are idempotent;
//! any other storage error aborts loudly instead of silently dropping data.

use rocky_agents::FindingBoard;
use rocky_storage::{FindingStore, StorageError};

/// Persists every board finding, returning the fresh IDs in board order.
/// Finding IDs are globally unique, so a re-sync skips persisted rows
/// instead of duplicating them.
pub fn persist_board(
    store: &mut impl FindingStore,
    board: &FindingBoard,
) -> Result<Vec<String>, StorageError> {
    let mut fresh = Vec::new();
    for finding in board.findings() {
        let result = store.post_finding(
            &finding.id,
            &finding.task_id,
            &finding.source_agent,
            &finding.hypothesis,
            &finding.evidence_ref,
            finding.confidence_pct,
            finding.affected_artifacts.clone(),
            &finding.recommended_action,
        );
        match result {
            Ok(record) => fresh.push(record.id),
            Err(StorageError::DuplicateFinding) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(fresh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_agents::{Finding, FindingBoard};
    use rocky_storage::{FindingStore, InMemoryTaskStore};

    fn board() -> FindingBoard {
        let mut board = FindingBoard::new("task-1", 8).expect("valid test board");
        board
            .post(
                Finding::new(
                    "f-1",
                    "task-1",
                    "scout",
                    "ports pinned",
                    "e1",
                    80,
                    vec![],
                    "x",
                )
                .expect("valid test finding"),
            )
            .expect("post finding");
        board
            .post(
                Finding::new("f-2", "task-1", "scout", "deps old", "e2", 60, vec![], "y")
                    .expect("valid test finding"),
            )
            .expect("post finding");
        board
    }

    #[test]
    fn persist_board_copies_findings_once() {
        let mut store = InMemoryTaskStore::default();
        assert_eq!(
            persist_board(&mut store, &board()).expect("persist board"),
            vec!["f-1".to_string(), "f-2".to_string()]
        );

        let listed = store.findings_for_task("task-1").expect("task query");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].hypothesis, "ports pinned");

        // Re-syncing persists nothing new instead of erroring on duplicates.
        assert!(
            persist_board(&mut store, &board())
                .expect("republish")
                .is_empty()
        );
        assert_eq!(
            store.findings_for_task("task-1").expect("task query").len(),
            2
        );
    }
}
