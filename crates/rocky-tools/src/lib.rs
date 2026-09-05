//! Typed tool contracts and the policy-enforced broker boundary.
//!
//! This crate validates and authorizes requests. It intentionally contains no OS executor.

use rocky_domain::{AutonomyLevel, Capability};
use rocky_policy::{Policy, PolicyDecision};
use std::collections::HashMap;
use std::fmt;

/// Metadata required before a tool can be registered with the broker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolDefinition {
    pub id: String,
    pub required_capability: Capability,
    pub autonomy_level: AutonomyLevel,
    pub timeout_ms: u64,
    pub supports_cancellation: bool,
}

impl ToolDefinition {
    /// Validates a tool contract with bounded execution semantics.
    pub fn new(
        id: impl Into<String>,
        required_capability: Capability,
        autonomy_level: AutonomyLevel,
        timeout_ms: u64,
        supports_cancellation: bool,
    ) -> Result<Self, ToolError> {
        let id = id.into();
        if id.trim().is_empty() || !id.contains('.') {
            return Err(ToolError::InvalidToolId);
        }
        if timeout_ms == 0 {
            return Err(ToolError::UnboundedTimeout);
        }
        if !supports_cancellation {
            return Err(ToolError::CancellationRequired);
        }
        Ok(Self {
            id,
            required_capability,
            autonomy_level,
            timeout_ms,
            supports_cancellation,
        })
    }
}

/// Maximum arguments per tool request. Argument vectors are attacker-shaped
/// input from model output: unbounded counts become unbounded allocations
/// and unbounded argv at the executor.
pub const MAX_TOOL_ARGS: usize = 32;

/// Maximum characters per argument. Launching a process with megabyte
/// arguments is never legitimate local-agent work.
pub const MAX_ARG_CHARS: usize = 4_096;

/// A model-proposed invocation, which has no authority on its own.
///
/// Arguments travel inside the authorized request so the permit the gate
/// issues can bind them: what the policy saw is byte-for-byte what the
/// executor must run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolRequest {
    pub tool_id: String,
    pub requested_capability: Capability,
    pub arguments: Vec<String>,
}

/// Authorizes only registered, typed tool requests.
#[derive(Default)]
pub struct ToolBroker {
    definitions: HashMap<String, ToolDefinition>,
}

impl ToolBroker {
    pub fn register(&mut self, definition: ToolDefinition) -> Result<(), ToolError> {
        if self.definitions.contains_key(&definition.id) {
            return Err(ToolError::DuplicateTool);
        }
        self.definitions.insert(definition.id.clone(), definition);
        Ok(())
    }

    /// Performs contract lookup and policy evaluation without dispatching an executor.
    pub fn authorize(
        &self,
        request: &ToolRequest,
        policy: &Policy,
    ) -> Result<PolicyDecision, ToolError> {
        let definition = self
            .definitions
            .get(&request.tool_id)
            .ok_or(ToolError::UnknownTool)?;
        if definition.required_capability.kind != request.requested_capability.kind {
            return Err(ToolError::CapabilityKindMismatch);
        }
        validate_arguments(&request.arguments)?;
        Ok(policy.evaluate(&request.requested_capability, definition.autonomy_level))
    }

    /// Looks up the registered tool's declared autonomy level.
    pub fn autonomy_level(&self, request: &ToolRequest) -> Result<AutonomyLevel, ToolError> {
        self.definitions
            .get(&request.tool_id)
            .map(|definition| definition.autonomy_level)
            .ok_or(ToolError::UnknownTool)
    }
}

/// Validates argument shape before policy evaluation. NUL bytes are rejected
/// here because `Command` would panic on them downstream; the broker is the
/// choke point that keeps hostile input from ever reaching spawning code.
fn validate_arguments(arguments: &[String]) -> Result<(), ToolError> {
    if arguments.len() > MAX_TOOL_ARGS {
        return Err(ToolError::ArgumentsTooMany);
    }
    for argument in arguments {
        if argument.contains('\0') {
            return Err(ToolError::InvalidArgument);
        }
        if argument.chars().count() > MAX_ARG_CHARS {
            return Err(ToolError::ArgumentTooLong);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolError {
    InvalidToolId,
    UnboundedTimeout,
    CancellationRequired,
    DuplicateTool,
    UnknownTool,
    CapabilityKindMismatch,
    ArgumentsTooMany,
    ArgumentTooLong,
    InvalidArgument,
}

impl fmt::Display for ToolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "tool contract error: {self:?}")
    }
}

impl std::error::Error for ToolError {}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_domain::{Capability, CapabilityKind};

    fn capability(kind: CapabilityKind, scope: &str) -> Capability {
        Capability::new(kind, scope).expect("valid test capability")
    }

    #[test]
    fn rejects_a_tool_without_a_deadline() {
        assert_eq!(
            ToolDefinition::new(
                "filesystem.read",
                capability(CapabilityKind::FilesystemRead, "C:/workspace"),
                AutonomyLevel::A0,
                0,
                true,
            ),
            Err(ToolError::UnboundedTimeout)
        );
    }

    #[test]
    fn unregistered_tools_cannot_be_authorized() {
        let broker = ToolBroker::default();
        let policy = Policy::deny_all(AutonomyLevel::A3);
        let request = ToolRequest {
            tool_id: "process.shell".into(),
            requested_capability: capability(CapabilityKind::ProcessExecute, "cmd.exe"),
            arguments: Vec::new(),
        };

        assert_eq!(
            broker.authorize(&request, &policy),
            Err(ToolError::UnknownTool)
        );
    }

    fn registered_broker() -> ToolBroker {
        let mut broker = ToolBroker::default();
        broker
            .register(
                ToolDefinition::new(
                    "process.execute",
                    capability(CapabilityKind::ProcessExecute, "cargo"),
                    AutonomyLevel::A2,
                    1_000,
                    true,
                )
                .expect("valid tool definition"),
            )
            .expect("first registration succeeds");
        broker
    }

    fn executable_request(arguments: Vec<String>) -> ToolRequest {
        ToolRequest {
            tool_id: "process.execute".into(),
            requested_capability: capability(CapabilityKind::ProcessExecute, "cargo"),
            arguments,
        }
    }

    #[test]
    fn arguments_are_bounded_before_policy_evaluation() {
        let broker = registered_broker();
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(capability(CapabilityKind::ProcessExecute, "cargo"));

        assert_eq!(
            broker.authorize(
                &executable_request(vec!["x".to_string(); MAX_TOOL_ARGS + 1]),
                &policy
            ),
            Err(ToolError::ArgumentsTooMany)
        );
        assert_eq!(
            broker.authorize(
                &executable_request(vec!["x".repeat(MAX_ARG_CHARS + 1)]),
                &policy
            ),
            Err(ToolError::ArgumentTooLong)
        );
        assert_eq!(
            broker.authorize(&executable_request(vec!["a\0b".into()]), &policy),
            Err(ToolError::InvalidArgument)
        );
        assert!(
            broker
                .authorize(&executable_request(vec!["--version".into()]), &policy)
                .is_ok()
        );
    }
}
