use crate::{
    AgentFailure, AgentHandler, AgentReference, AgentRequest, AgentResponse, AgentStatus,
    DispatchError, PendingChallenge,
};

/// Failure returned by the single authoritative ceremony transaction adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthoritativeError {
    /// Input, signed material, or binding verification was rejected.
    Rejected,
    /// Required durable, cryptographic, or identity authority is unavailable.
    Unavailable,
    /// The ceremony is missing, stale, replayed, or terminal.
    Conflict,
}

/// One authoritative durable ceremony and session transaction boundary.
///
/// Implementations own reference lookup, challenge signing, response
/// verification, single-use consumption, session insertion, and audit
/// insertion. `submit` must commit those mutations atomically or commit none.
/// Implementations must never maintain a second shadow ceremony state.
pub trait AuthoritativeCeremonies {
    /// Creates and durably records one signed login challenge.
    ///
    /// # Errors
    ///
    /// Fails closed when context, signing, randomness, or storage is unavailable.
    fn begin_login(&mut self) -> Result<PendingChallenge, AuthoritativeError>;

    /// Creates and durably records one signed exact-action challenge.
    ///
    /// # Errors
    ///
    /// Rejects unsafe action semantics and all login initiation failures.
    fn begin_action(
        &mut self,
        arguments: Vec<String>,
    ) -> Result<PendingChallenge, AuthoritativeError>;

    /// Returns redacted current state without response or session material.
    ///
    /// # Errors
    ///
    /// Unknown and terminally conflicting references fail closed.
    fn status(&mut self, reference: AgentReference) -> Result<AgentStatus, AuthoritativeError>;

    /// Stages, verifies, consumes, and completes through one transaction.
    ///
    /// # Errors
    ///
    /// Any malformed, unbound, inactive, replayed, or uncommitted result fails.
    fn submit(
        &mut self,
        reference: AgentReference,
        transfer: String,
    ) -> Result<AgentStatus, AuthoritativeError>;

    /// Makes a pending ceremony terminal and erases a staged response.
    ///
    /// # Errors
    ///
    /// Missing, expired, or already terminal ceremonies fail closed.
    fn cancel(&mut self, reference: AgentReference) -> Result<(), AuthoritativeError>;
}

/// Closed protocol handler backed by one authoritative ceremony adapter.
pub struct AuthoritativeHandler<A> {
    authority: A,
}

impl<A> AuthoritativeHandler<A> {
    /// Creates a handler around the sole authoritative state adapter.
    #[must_use]
    pub const fn new(authority: A) -> Self {
        Self { authority }
    }

    /// Returns the owned authority.
    pub fn into_inner(self) -> A {
        self.authority
    }
}

impl<A: AuthoritativeCeremonies> AgentHandler for AuthoritativeHandler<A> {
    fn handle(&mut self, request: AgentRequest) -> Result<AgentResponse, DispatchError> {
        let result = match request {
            AgentRequest::BeginLogin => self.authority.begin_login().map(AgentResponse::Pending),
            AgentRequest::BeginAction { arguments } => self
                .authority
                .begin_action(arguments)
                .map(AgentResponse::Pending),
            AgentRequest::Status { reference } => {
                self.authority.status(reference).map(AgentResponse::Status)
            }
            AgentRequest::Submit {
                reference,
                transfer,
            } => self
                .authority
                .submit(reference, transfer)
                .map(AgentResponse::Status),
            AgentRequest::Cancel { reference } => self
                .authority
                .cancel(reference)
                .map(|()| AgentResponse::Acknowledged),
        };
        Ok(result.unwrap_or_else(|error| AgentResponse::Failure(map_failure(error))))
    }
}

const fn map_failure(error: AuthoritativeError) -> AgentFailure {
    match error {
        AuthoritativeError::Rejected => AgentFailure::Rejected,
        AuthoritativeError::Unavailable => AgentFailure::Unavailable,
        AuthoritativeError::Conflict => AgentFailure::Conflict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Authority {
        submissions: usize,
        cancellations: usize,
    }

    impl AuthoritativeCeremonies for Authority {
        fn begin_login(&mut self) -> Result<PendingChallenge, AuthoritativeError> {
            Err(AuthoritativeError::Unavailable)
        }

        fn begin_action(&mut self, _: Vec<String>) -> Result<PendingChallenge, AuthoritativeError> {
            Err(AuthoritativeError::Rejected)
        }

        fn status(&mut self, _: AgentReference) -> Result<AgentStatus, AuthoritativeError> {
            Ok(AgentStatus::Pending)
        }

        fn submit(
            &mut self,
            _: AgentReference,
            _: String,
        ) -> Result<AgentStatus, AuthoritativeError> {
            self.submissions += 1;
            Ok(AgentStatus::Completed)
        }

        fn cancel(&mut self, _: AgentReference) -> Result<(), AuthoritativeError> {
            self.cancellations += 1;
            Ok(())
        }
    }

    #[test]
    fn every_request_routes_once_and_failures_remain_closed() {
        let reference = AgentReference::from_bytes([4; 32]);
        let mut handler = AuthoritativeHandler::new(Authority {
            submissions: 0,
            cancellations: 0,
        });
        assert_eq!(
            handler.handle(AgentRequest::BeginLogin).unwrap(),
            AgentResponse::Failure(AgentFailure::Unavailable)
        );
        assert_eq!(
            handler
                .handle(AgentRequest::BeginAction {
                    arguments: vec!["tool".into()],
                })
                .unwrap(),
            AgentResponse::Failure(AgentFailure::Rejected)
        );
        assert_eq!(
            handler.handle(AgentRequest::Status { reference }).unwrap(),
            AgentResponse::Status(AgentStatus::Pending)
        );
        assert_eq!(
            handler
                .handle(AgentRequest::Submit {
                    reference,
                    transfer: "PISTIS1:response".into(),
                })
                .unwrap(),
            AgentResponse::Status(AgentStatus::Completed)
        );
        assert_eq!(
            handler.handle(AgentRequest::Cancel { reference }).unwrap(),
            AgentResponse::Acknowledged
        );
        let authority = handler.into_inner();
        assert_eq!(authority.submissions, 1);
        assert_eq!(authority.cancellations, 1);
    }
}
