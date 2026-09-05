//! Append-only in-memory audit records.
//!
//! Persistence adapters may store these records, but may not rewrite their sequence.

use rocky_domain::AutonomyLevel;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub task_id: String,
    pub actor: String,
    pub action: String,
    pub autonomy_level: AutonomyLevel,
    pub outcome: AuditOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    Approved,
    ApprovalRequired,
    Queued,
    Denied,
    Cancelled,
}

#[derive(Default)]
pub struct AuditLog {
    events: Vec<AuditEvent>,
}

impl AuditLog {
    /// Appends a record and assigns its monotonic sequence number.
    pub fn append(
        &mut self,
        task_id: impl Into<String>,
        actor: impl Into<String>,
        action: impl Into<String>,
        autonomy_level: AutonomyLevel,
        outcome: AuditOutcome,
    ) -> AuditEvent {
        let event = AuditEvent {
            sequence: self.events.len() as u64 + 1,
            task_id: task_id.into(),
            actor: actor.into(),
            action: action.into(),
            autonomy_level,
            outcome,
        };
        self.events.push(event.clone());
        event
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }

    /// Lists distinct actions currently awaiting approval, oldest first.
    /// Read-only over the append-only log: surfacing for the approval UI,
    /// never a decision input.
    pub fn approval_required_actions(&self) -> Vec<String> {
        let mut actions = Vec::new();
        for event in &self.events {
            if event.outcome == AuditOutcome::ApprovalRequired && !actions.contains(&event.action) {
                actions.push(event.action.clone());
            }
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_assigns_monotonic_sequence_numbers() {
        let mut log = AuditLog::default();
        let first = log.append(
            "task-1",
            "runtime",
            "filesystem.read",
            AutonomyLevel::A0,
            AuditOutcome::Approved,
        );
        let second = log.append(
            "task-1",
            "runtime",
            "filesystem.write",
            AutonomyLevel::A2,
            AuditOutcome::Denied,
        );

        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert_eq!(log.events().len(), 2);
    }

    #[test]
    fn approval_required_actions_are_distinct_and_oldest_first() {
        let mut log = AuditLog::default();
        log.append(
            "t",
            "runtime",
            "b.write",
            AutonomyLevel::A3,
            AuditOutcome::ApprovalRequired,
        );
        log.append(
            "t",
            "runtime",
            "a.read",
            AutonomyLevel::A0,
            AuditOutcome::Approved,
        );
        log.append(
            "t",
            "runtime",
            "c.exec",
            AutonomyLevel::A3,
            AuditOutcome::ApprovalRequired,
        );
        log.append(
            "t",
            "runtime",
            "b.write",
            AutonomyLevel::A3,
            AuditOutcome::ApprovalRequired,
        );
        log.append(
            "t",
            "runtime",
            "d.exec",
            AutonomyLevel::A2,
            AuditOutcome::Denied,
        );

        assert_eq!(log.approval_required_actions(), vec!["b.write", "c.exec"]);
    }
}
