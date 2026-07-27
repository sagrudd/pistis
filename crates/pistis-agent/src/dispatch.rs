use crate::{
    AgentRequest, AgentResponse, ProtocolError, SocketFrameError, decode_request, encode_response,
    read_frame, write_frame,
};
use std::{error::Error, fmt, os::unix::net::UnixStream};

/// Platform peer-credential authorisation boundary.
pub trait PeerAuthorizer {
    /// Verifies that the connected peer is permitted to use this agent.
    ///
    /// This check runs before any request bytes are read or decoded.
    ///
    /// # Errors
    ///
    /// Fails closed when credentials cannot be read or do not match policy.
    fn authorize(&self, stream: &UnixStream) -> Result<(), DispatchError>;
}

/// Semantic local-agent request handler.
pub trait AgentHandler {
    /// Handles one already authorised, closed request.
    ///
    /// # Errors
    ///
    /// Returns a coarse internal failure without returning secret material.
    fn handle(&mut self, request: AgentRequest) -> Result<AgentResponse, DispatchError>;
}

/// Authorises, decodes, handles, and replies to one socket request.
///
/// The connection is intentionally single-request. This bounds parser state
/// and requires peer authorisation for every operation.
///
/// # Errors
///
/// Fails on peer rejection, frame/schema errors, handler failure, or reply I/O.
pub fn dispatch_one(
    mut stream: UnixStream,
    authorizer: &impl PeerAuthorizer,
    handler: &mut impl AgentHandler,
) -> Result<(), DispatchError> {
    authorizer.authorize(&stream)?;
    let request = decode_request(&read_frame(&mut stream)?)?;
    let response = handler.handle(request)?;
    write_frame(&mut stream, &encode_response(&response)?)?;
    Ok(())
}

/// Coarse daemon dispatch failure.
#[derive(Debug)]
pub enum DispatchError {
    /// Peer credentials are unavailable or unauthorized.
    Unauthorized,
    /// Canonical framing or semantic protocol failed.
    Protocol,
    /// Authoritative handler is unavailable.
    Unavailable,
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unauthorized => "local agent peer unauthorized",
            Self::Protocol => "local agent protocol rejected",
            Self::Unavailable => "local agent handler unavailable",
        })
    }
}

impl Error for DispatchError {}

impl From<SocketFrameError> for DispatchError {
    fn from(_: SocketFrameError) -> Self {
        Self::Protocol
    }
}

impl From<ProtocolError> for DispatchError {
    fn from(_: ProtocolError) -> Self {
        Self::Protocol
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentStatus, decode_response, encode_request};
    use std::{
        io::Read as _,
        sync::atomic::{AtomicUsize, Ordering},
    };

    struct Authorizer(bool);

    impl PeerAuthorizer for Authorizer {
        fn authorize(&self, _: &UnixStream) -> Result<(), DispatchError> {
            if self.0 {
                Ok(())
            } else {
                Err(DispatchError::Unauthorized)
            }
        }
    }

    struct Handler<'a>(&'a AtomicUsize);

    impl AgentHandler for Handler<'_> {
        fn handle(&mut self, request: AgentRequest) -> Result<AgentResponse, DispatchError> {
            assert_eq!(request, AgentRequest::BeginLogin);
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(AgentResponse::Status(AgentStatus::Pending))
        }
    }

    #[test]
    fn authorized_closed_request_gets_one_closed_response() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let request = encode_request(&AgentRequest::BeginLogin).unwrap();
        write_frame(&mut client, &request).unwrap();
        let calls = AtomicUsize::new(0);
        dispatch_one(server, &Authorizer(true), &mut Handler(&calls)).unwrap();
        let response = read_frame(&mut client).unwrap();
        assert_eq!(
            decode_response(&response),
            Ok(AgentResponse::Status(AgentStatus::Pending))
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rejected_peer_is_not_read_or_dispatched() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let calls = AtomicUsize::new(0);
        assert!(matches!(
            dispatch_one(server, &Authorizer(false), &mut Handler(&calls)),
            Err(DispatchError::Unauthorized)
        ));
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    }
}
