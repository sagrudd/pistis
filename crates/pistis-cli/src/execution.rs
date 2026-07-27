use pistis_authentication::{ActionDescriptor, UnixTimeMillis, action_descriptor_digest};
use pistis_domain::ChallengeId;
use std::{error::Error, fmt};

/// Single-use authority returned by the durable approval verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionGrant {
    /// Exact approved action.
    pub action: ActionDescriptor,
    /// Digest of the exact signed action challenge.
    pub challenge_digest: [u8; 32],
    /// Single-use challenge identifier retained in audit evidence.
    pub challenge_id: ChallengeId,
    /// Exclusive execution expiry.
    pub expires_at: UnixTimeMillis,
}

/// Durable single-use approval-consumption boundary.
pub trait ApprovalAuthority {
    /// Atomically consumes one verified approval for the requested descriptor.
    ///
    /// Implementations must reject denial, replay, wrong installation, wrong
    /// user, wrong action, inactive device, and expired approval before
    /// returning a grant.
    ///
    /// # Errors
    ///
    /// Fails closed when no exact, current, verified approval can be consumed.
    fn consume(
        &mut self,
        descriptor_digest: [u8; 32],
        now: UnixTimeMillis,
    ) -> Result<ExecutionGrant, ExecutionError>;
}

/// Platform observation boundary used immediately before execution.
pub trait ActionInspector {
    /// Re-resolves and re-hashes every mutable part of `requested`.
    ///
    /// The returned descriptor must describe the executable, working
    /// directory, allowed environment, and resources as they exist at this
    /// instant. Failure to establish stable identity must fail closed.
    ///
    /// # Errors
    ///
    /// Fails when any required platform identity cannot be established.
    fn inspect(&mut self, requested: &ActionDescriptor)
    -> Result<ActionDescriptor, ExecutionError>;
}

/// Platform process execution boundary.
pub trait ActionExecutor {
    /// Executes an already approved and revalidated argument vector.
    ///
    /// Implementations must invoke the resolved executable directly. They must
    /// not reconstruct a shell command, repeat path lookup, add inherited
    /// environment entries, or reopen resources without identity checks.
    ///
    /// # Errors
    ///
    /// Returns a coarse execution failure without leaking command data.
    fn execute(&mut self, action: &ActionDescriptor) -> Result<(), ExecutionError>;
}

/// Coarse failure returned by the execution boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionError {
    /// No matching verified single-use approval exists.
    ApprovalRejected,
    /// The approval expired before execution.
    Expired,
    /// The executable, context, environment, or resource changed.
    Changed,
    /// The platform cannot establish the required stable identities.
    Unavailable,
    /// Direct execution failed.
    ExecutionFailed,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ApprovalRejected => "exact-action approval rejected",
            Self::Expired => "exact-action approval expired",
            Self::Changed => "approved action changed before execution",
            Self::Unavailable => "exact-action inspection unavailable",
            Self::ExecutionFailed => "approved action execution failed",
        })
    }
}

impl Error for ExecutionError {}

/// Consumes, revalidates, and directly executes one exact approved action.
///
/// Approval is consumed before platform revalidation, so a changed or failed
/// attempt cannot be replayed after an operator modifies the environment.
///
/// # Errors
///
/// Fails closed when the descriptor is invalid, approval is absent or expired,
/// any inspected binding differs, stable inspection is unavailable, or direct
/// execution fails.
pub fn execute_approved(
    requested: &ActionDescriptor,
    now: UnixTimeMillis,
    authority: &mut impl ApprovalAuthority,
    inspector: &mut impl ActionInspector,
    executor: &mut impl ActionExecutor,
) -> Result<ExecutionGrant, ExecutionError> {
    let requested_digest =
        action_descriptor_digest(requested).map_err(|_| ExecutionError::ApprovalRejected)?;
    let grant = authority.consume(requested_digest, now)?;
    if grant.expires_at <= now {
        return Err(ExecutionError::Expired);
    }
    if grant.action != *requested {
        return Err(ExecutionError::ApprovalRejected);
    }
    let observed = inspector.inspect(requested)?;
    if observed != *requested {
        return Err(ExecutionError::Changed);
    }
    executor.execute(&observed)?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pistis_authentication::{ActionEnvironment, ActionResource};

    fn action() -> ActionDescriptor {
        ActionDescriptor {
            executable_path: "/usr/bin/tool".into(),
            executable_sha256: [1; 32],
            arguments: vec!["tool".into(), "input".into()],
            working_directory: "/work".into(),
            environment: vec![ActionEnvironment {
                name: "LANG".into(),
                value: "C".into(),
            }],
            resources: Vec::<ActionResource>::new(),
        }
    }

    struct Authority {
        grant: Option<ExecutionGrant>,
        consumed: usize,
    }

    impl ApprovalAuthority for Authority {
        fn consume(
            &mut self,
            _: [u8; 32],
            _: UnixTimeMillis,
        ) -> Result<ExecutionGrant, ExecutionError> {
            self.consumed += 1;
            self.grant.take().ok_or(ExecutionError::ApprovalRejected)
        }
    }

    struct Inspector(ActionDescriptor);

    impl ActionInspector for Inspector {
        fn inspect(&mut self, _: &ActionDescriptor) -> Result<ActionDescriptor, ExecutionError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Default)]
    struct Executor(usize);

    impl ActionExecutor for Executor {
        fn execute(&mut self, _: &ActionDescriptor) -> Result<(), ExecutionError> {
            self.0 += 1;
            Ok(())
        }
    }

    fn grant(action: ActionDescriptor, expires: u64) -> ExecutionGrant {
        ExecutionGrant {
            action,
            challenge_digest: [2; 32],
            challenge_id: ChallengeId::from_bytes([3; 16]),
            expires_at: UnixTimeMillis(expires),
        }
    }

    #[test]
    fn exact_unchanged_action_executes_once() {
        let action = action();
        let mut authority = Authority {
            grant: Some(grant(action.clone(), 200)),
            consumed: 0,
        };
        let mut inspector = Inspector(action.clone());
        let mut executor = Executor::default();
        execute_approved(
            &action,
            UnixTimeMillis(100),
            &mut authority,
            &mut inspector,
            &mut executor,
        )
        .unwrap();
        assert_eq!(authority.consumed, 1);
        assert_eq!(executor.0, 1);
        assert_eq!(
            execute_approved(
                &action,
                UnixTimeMillis(101),
                &mut authority,
                &mut inspector,
                &mut executor,
            ),
            Err(ExecutionError::ApprovalRejected)
        );
        assert_eq!(executor.0, 1);
    }

    #[test]
    fn substitution_expiry_and_toctou_never_execute() {
        let requested = action();
        let mut substituted = requested.clone();
        substituted.arguments.push("--delete".into());
        let mut authority = Authority {
            grant: Some(grant(substituted, 200)),
            consumed: 0,
        };
        let mut inspector = Inspector(requested.clone());
        let mut executor = Executor::default();
        assert_eq!(
            execute_approved(
                &requested,
                UnixTimeMillis(100),
                &mut authority,
                &mut inspector,
                &mut executor,
            ),
            Err(ExecutionError::ApprovalRejected)
        );

        let mut authority = Authority {
            grant: Some(grant(requested.clone(), 100)),
            consumed: 0,
        };
        assert_eq!(
            execute_approved(
                &requested,
                UnixTimeMillis(100),
                &mut authority,
                &mut inspector,
                &mut executor,
            ),
            Err(ExecutionError::Expired)
        );

        let mut changed = requested.clone();
        changed.executable_sha256 = [9; 32];
        let mut authority = Authority {
            grant: Some(grant(requested.clone(), 200)),
            consumed: 0,
        };
        let mut inspector = Inspector(changed);
        assert_eq!(
            execute_approved(
                &requested,
                UnixTimeMillis(100),
                &mut authority,
                &mut inspector,
                &mut executor,
            ),
            Err(ExecutionError::Changed)
        );
        assert_eq!(executor.0, 0);
    }
}
