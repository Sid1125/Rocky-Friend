//! Deny-by-default capability and autonomy policy evaluation.

use rocky_domain::{AutonomyLevel, Capability};

/// A policy decision that a caller must enforce before any execution happens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Approved,
    RequiresApproval,
    Denied(PolicyDenial),
}

/// A machine-readable reason for denial.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDenial {
    ForbiddenAutonomyLevel,
    AutonomyLevelExceeded,
    CapabilityNotGranted,
    ScopeOutsideGrant,
    UnsafeScope,
}

/// Explicit permissions and the highest autonomy level that may be considered.
#[derive(Clone, Debug)]
pub struct Policy {
    maximum_autonomy: AutonomyLevel,
    grants: Vec<Capability>,
}

impl Policy {
    /// Starts from a deny-by-default policy with no grants.
    pub fn deny_all(maximum_autonomy: AutonomyLevel) -> Self {
        Self {
            maximum_autonomy,
            grants: Vec::new(),
        }
    }

    /// Adds one capability grant. Callers own approval and persistence of the grant.
    pub fn grant(&mut self, capability: Capability) {
        self.grants.push(capability);
    }

    /// Evaluates an operation without executing it or granting any new authority.
    pub fn evaluate(&self, requested: &Capability, level: AutonomyLevel) -> PolicyDecision {
        if level == AutonomyLevel::A4 {
            return PolicyDecision::Denied(PolicyDenial::ForbiddenAutonomyLevel);
        }
        if level > self.maximum_autonomy {
            return PolicyDecision::Denied(PolicyDenial::AutonomyLevelExceeded);
        }
        if contains_unsafe_component(&requested.scope) {
            return PolicyDecision::Denied(PolicyDenial::UnsafeScope);
        }

        let same_kind = self
            .grants
            .iter()
            .filter(|grant| grant.kind == requested.kind);
        let mut found_kind = false;
        for grant in same_kind {
            found_kind = true;
            if scope_contains(&grant.scope, &requested.scope) {
                return if level == AutonomyLevel::A3 {
                    PolicyDecision::RequiresApproval
                } else {
                    PolicyDecision::Approved
                };
            }
        }

        PolicyDecision::Denied(if found_kind {
            PolicyDenial::ScopeOutsideGrant
        } else {
            PolicyDenial::CapabilityNotGranted
        })
    }

    /// Returns the matching explicit grant. Callers must still evaluate autonomy and risk policy.
    pub fn matching_grant(&self, requested: &Capability) -> Option<Capability> {
        self.grants
            .iter()
            .find(|grant| scope_covers(grant, requested))
            .cloned()
    }
}

/// Checks that a granted capability covers a requested one: same kind and a
/// scope that is exactly the grant or a child path thereof.
pub fn scope_covers(granted: &Capability, requested: &Capability) -> bool {
    granted.kind == requested.kind && scope_contains(&granted.scope, &requested.scope)
}

/// Checks whether a requested scope is exactly a granted scope or a child path thereof.
///
/// This is a lexical pre-check only. The executor must canonicalize filesystem paths before
/// use, because symlinks and platform path rules cannot be verified in this pure policy crate.
fn scope_contains(granted: &str, requested: &str) -> bool {
    if granted == requested {
        return true;
    }
    let separator = granted.ends_with('/') || granted.ends_with('\\');
    requested.starts_with(granted)
        && (separator
            || requested
                .as_bytes()
                .get(granted.len())
                .is_some_and(|byte| *byte == b'/' || *byte == b'\\'))
}

fn contains_unsafe_component(scope: &str) -> bool {
    scope
        .split(['/', '\\'])
        .any(|component| component == "." || component == "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocky_domain::CapabilityKind;

    fn capability(kind: CapabilityKind, scope: &str) -> Capability {
        Capability::new(kind, scope).expect("valid test capability")
    }

    #[test]
    fn denies_ungranted_capabilities_by_default() {
        let policy = Policy::deny_all(AutonomyLevel::A2);
        let request = capability(CapabilityKind::FilesystemRead, "C:/workspace/readme.md");

        assert_eq!(
            policy.evaluate(&request, AutonomyLevel::A0),
            PolicyDecision::Denied(PolicyDenial::CapabilityNotGranted)
        );
    }

    #[test]
    fn denies_traversal_even_when_the_string_prefix_looks_granted() {
        let mut policy = Policy::deny_all(AutonomyLevel::A2);
        policy.grant(capability(CapabilityKind::FilesystemRead, "C:/workspace"));
        let request = capability(
            CapabilityKind::FilesystemRead,
            "C:/workspace/../secrets/token.txt",
        );

        assert_eq!(
            policy.evaluate(&request, AutonomyLevel::A0),
            PolicyDecision::Denied(PolicyDenial::UnsafeScope)
        );
    }

    #[test]
    fn does_not_treat_a_string_prefix_as_a_scope_boundary() {
        let mut policy = Policy::deny_all(AutonomyLevel::A2);
        policy.grant(capability(CapabilityKind::FilesystemRead, "C:/workspace"));
        let request = capability(CapabilityKind::FilesystemRead, "C:/workspace-evil/file.txt");

        assert_eq!(
            policy.evaluate(&request, AutonomyLevel::A0),
            PolicyDecision::Denied(PolicyDenial::ScopeOutsideGrant)
        );
    }

    #[test]
    fn consequential_work_requires_confirmation() {
        let mut policy = Policy::deny_all(AutonomyLevel::A3);
        policy.grant(capability(CapabilityKind::FilesystemWrite, "C:/workspace"));
        let request = capability(CapabilityKind::FilesystemWrite, "C:/workspace/config.toml");

        assert_eq!(
            policy.evaluate(&request, AutonomyLevel::A3),
            PolicyDecision::RequiresApproval
        );
    }
}
